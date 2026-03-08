import EndpointSecurityExtension
import Darwin
import Foundation

enum StatusToolMode {
    case live
    case fixture(EndpointSecurityFixtureScenario)
}

enum StatusToolInvocationError: Error, LocalizedError {
    case missingMode
    case unsupportedMode(String)
    case missingFixtureScenario

    var errorDescription: String? {
        switch self {
        case .missingMode:
            return "missing endpoint-security status-tool mode (use `live` or `fixture <scenario>`)"
        case .unsupportedMode(let mode):
            return "unsupported endpoint-security status-tool mode: \(mode)"
        case .missingFixtureScenario:
            return "missing endpoint-security fixture scenario"
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
    default:
        throw StatusToolInvocationError.unsupportedMode(mode)
    }
}

do {
    let mode = try resolveMode(arguments: CommandLine.arguments.dropFirst())
    let report: EndpointSecurityStatusReport
    switch mode {
    case .live:
        report = EndpointSecurityMonitor.liveReport()
    case .fixture(let scenario):
        report = EndpointSecurityMonitor.fixtureScenario(scenario)
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
