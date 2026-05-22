import ClawdStrikeNetworkExtension
import Darwin
import Foundation

enum StatusToolMode {
    case live
    case fixture(NetworkExtensionFixtureScenario)
    case requestReload(policySnapshotPath: String, generation: UInt64)
}

enum StatusToolInvocationError: Error, LocalizedError {
    case missingMode
    case unsupportedMode(String)
    case missingFixtureScenario
    case missingPolicySnapshotPath
    case invalidGeneration(String)

    var errorDescription: String? {
        switch self {
        case .missingMode:
            return "missing network-extension status-tool mode (use `live`, `fixture <scenario>`, or `request-reload <policy-snapshot-path> [generation]`)"
        case .unsupportedMode(let mode):
            return "unsupported network-extension status-tool mode: \(mode)"
        case .missingFixtureScenario:
            return "missing network-extension fixture scenario"
        case .missingPolicySnapshotPath:
            return "missing network-extension policy snapshot path"
        case .invalidGeneration(let value):
            return "invalid network-extension reload generation: \(value)"
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
        return .fixture(try NetworkExtensionFixtureScenario.resolve(argument: scenarioArgument))
    case "request-reload":
        let rest = arguments.dropFirst()
        guard let policySnapshotPath = rest.first else {
            throw StatusToolInvocationError.missingPolicySnapshotPath
        }
        let generation: UInt64
        if let generationArgument = rest.dropFirst().first {
            guard let parsed = UInt64(generationArgument) else {
                throw StatusToolInvocationError.invalidGeneration(generationArgument)
            }
            generation = parsed
        } else {
            generation = UInt64(Date().timeIntervalSince1970 * 1000)
        }
        return .requestReload(
            policySnapshotPath: policySnapshotPath,
            generation: generation
        )
    default:
        throw StatusToolInvocationError.unsupportedMode(mode)
    }
}

do {
    let mode = try resolveMode(arguments: CommandLine.arguments.dropFirst())
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]

    let data: Data
    switch mode {
    case .live:
        data = try encoder.encode(NetworkExtensionStatusTool.liveSnapshot())
    case .fixture(let scenario):
        data = try encoder.encode(NetworkExtensionStatusTool.fixtureSnapshot(scenario))
    case .requestReload(let policySnapshotPath, let generation):
        let store = NetworkExtensionFilterManagerVendorConfigurationStore()
        let result = try NetworkExtensionProviderReloadRequester.requestReload(
            policySnapshotPath: policySnapshotPath,
            generation: generation,
            requestID: "network-extension-reload-\(UUID().uuidString)",
            store: store
        )
        data = try encoder.encode(result)
    }

    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(64)
}
