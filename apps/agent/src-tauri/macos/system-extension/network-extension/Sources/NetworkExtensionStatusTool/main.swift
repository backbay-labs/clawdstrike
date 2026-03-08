import ClawdStrikeNetworkExtension
import Darwin
import Foundation

enum StatusToolMode {
    case live
    case fixture(NetworkExtensionFixtureScenario)
}

enum StatusToolInvocationError: Error, LocalizedError {
    case missingMode
    case unsupportedMode(String)
    case missingFixtureScenario

    var errorDescription: String? {
        switch self {
        case .missingMode:
            return "missing network-extension status-tool mode (use `live` or `fixture <scenario>`)"
        case .unsupportedMode(let mode):
            return "unsupported network-extension status-tool mode: \(mode)"
        case .missingFixtureScenario:
            return "missing network-extension fixture scenario"
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
    default:
        throw StatusToolInvocationError.unsupportedMode(mode)
    }
}

do {
    let mode = try resolveMode(arguments: CommandLine.arguments.dropFirst())
    let snapshot: NetworkExtensionProviderSnapshot
    switch mode {
    case .live:
        snapshot = NetworkExtensionStatusTool.liveSnapshot()
    case .fixture(let scenario):
        snapshot = NetworkExtensionStatusTool.fixtureSnapshot(scenario)
    }

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]

    let data = try encoder.encode(snapshot)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(64)
}
