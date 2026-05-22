import EndpointSecurityExtension
import Darwin
import Foundation

let runtimeSnapshotMaxAgeSeconds: TimeInterval = 120

enum StatusToolMode {
    case live
    case fixture(EndpointSecurityFixtureScenario)
    case observeAuthOpen(durationSeconds: TimeInterval)
}

enum StatusToolInvocationError: Error, LocalizedError {
    case missingMode
    case unsupportedMode(String)
    case missingFixtureScenario
    case invalidObserveDuration(String)
    case missingAgentToken(String)

    var errorDescription: String? {
        switch self {
        case .missingMode:
            return "missing endpoint-security status-tool mode (use `live`, `fixture <scenario>`, or `observe-auth-open [seconds]`)"
        case .unsupportedMode(let mode):
            return "unsupported endpoint-security status-tool mode: \(mode)"
        case .missingFixtureScenario:
            return "missing endpoint-security fixture scenario"
        case .invalidObserveDuration(let value):
            return "invalid observe-auth-open duration: \(value)"
        case .missingAgentToken(let path):
            return "missing agent bearer token; set CLAWDSTRIKE_AGENT_TOKEN or create \(path)"
        }
    }
}

func resolveMode(arguments: ArraySlice<String>) throws -> StatusToolMode {
    guard let mode = arguments.first else {
        throw StatusToolInvocationError.missingMode
    }
    switch mode {
    case "live":
        return .live
    case "fixture":
        guard let scenarioArgument = arguments.dropFirst().first else {
            throw StatusToolInvocationError.missingFixtureScenario
        }
        return .fixture(try EndpointSecurityFixtureScenario.resolve(commandLineArgument: scenarioArgument))
    case "observe-auth-open":
        let durationArgument = arguments.dropFirst().first
            ?? environmentValue("CLAWDSTRIKE_ENDPOINT_SECURITY_OBSERVE_SECONDS")
            ?? "30"
        guard let duration = TimeInterval(durationArgument), duration > 0 else {
            throw StatusToolInvocationError.invalidObserveDuration(durationArgument)
        }
        return .observeAuthOpen(durationSeconds: duration)
    default:
        throw StatusToolInvocationError.unsupportedMode(mode)
    }
}

func environmentValue(_ key: String) -> String? {
    let value = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines)
    return value?.isEmpty == false ? value : nil
}

func endpointSecurityRuntimeSnapshotURL() -> URL? {
    guard let path = environmentValue("CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH") else {
        return nil
    }
    return URL(fileURLWithPath: path)
}

func runtimeSnapshotIsFresh(_ url: URL, now: Date = Date()) throws -> Bool {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard let modifiedAt = attributes[.modificationDate] as? Date else {
        return false
    }
    let age = now.timeIntervalSince(modifiedAt)
    return age >= 0 && age <= runtimeSnapshotMaxAgeSeconds
}

func loadRuntimeSnapshot() throws -> EndpointSecurityStatusReport? {
    guard let url = endpointSecurityRuntimeSnapshotURL(),
          FileManager.default.fileExists(atPath: url.path)
    else {
        return nil
    }
    guard try runtimeSnapshotIsFresh(url) else {
        return nil
    }
    let data = try Data(contentsOf: url)
    return try JSONDecoder().decode(EndpointSecurityStatusReport.self, from: data)
}

func writeRuntimeSnapshot(_ report: EndpointSecurityStatusReport) throws {
    guard let url = endpointSecurityRuntimeSnapshotURL() else {
        return
    }
    try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(report)
    try data.write(to: url, options: [.atomic])
}

func readAgentToken() throws -> String {
    if let token = environmentValue("CLAWDSTRIKE_AGENT_TOKEN") {
        return token
    }
    let tokenPaths = ClawdStrikeAgentConfigPaths.agentTokenCandidates(
        explicitPath: environmentValue("CLAWDSTRIKE_AGENT_TOKEN_FILE")
    )
    for tokenPath in tokenPaths where FileManager.default.fileExists(atPath: tokenPath) {
        let token = try String(contentsOfFile: tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            throw StatusToolInvocationError.missingAgentToken(tokenPath)
        }
        return token
    }
    throw StatusToolInvocationError.missingAgentToken(tokenPaths.joined(separator: " or "))
}

func observeAuthOpen(durationSeconds: TimeInterval) throws -> EndpointSecurityStatusReport {
    let monitor = EndpointSecurityMonitor()
    let publisher = try EndpointSecurityAgentEventPublisher(
        agentURL: environmentValue("CLAWDSTRIKE_ENDPOINT_SECURITY_AGENT_URL")
            ?? environmentValue("CLAWDSTRIKE_AGENT_URL")
            ?? "http://127.0.0.1:9878",
        bearerToken: try readAgentToken(),
        transport: URLSessionEndpointSecurityAgentEventTransport()
    )
    let runtime = EndpointSecurityAuthOpenRuntime(
        monitor: monitor,
        publisher: publisher,
        adapter: EndpointSecurityAuthOpenMessageAdapter(
            hostId: environmentValue("CLAWDSTRIKE_ENDPOINT_ID") ?? ProcessInfo.processInfo.hostName,
            userId: environmentValue("CLAWDSTRIKE_USER_ID"),
            sessionId: environmentValue("CLAWDSTRIKE_SESSION_ID")
        ),
        publishErrorHandler: { error in
            FileHandle.standardError.write(Data("EndpointSecurity runtime warning: \(error.localizedDescription)\n".utf8))
        }
    )

    try runtime.start()
    try writeRuntimeSnapshot(monitor.snapshot())
    RunLoop.current.run(until: Date().addingTimeInterval(durationSeconds))
    try runtime.stop()
    let report = monitor.snapshot()
    try writeRuntimeSnapshot(report)
    return report
}

do {
    let mode = try resolveMode(arguments: CommandLine.arguments.dropFirst())
    let report: EndpointSecurityStatusReport
    switch mode {
    case .live:
        report = try loadRuntimeSnapshot() ?? EndpointSecurityMonitor.liveReport()
    case .fixture(let scenario):
        report = EndpointSecurityMonitor.fixtureScenario(scenario)
    case .observeAuthOpen(let durationSeconds):
        report = try observeAuthOpen(durationSeconds: durationSeconds)
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]

    let data = try encoder.encode(report)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(64)
}
