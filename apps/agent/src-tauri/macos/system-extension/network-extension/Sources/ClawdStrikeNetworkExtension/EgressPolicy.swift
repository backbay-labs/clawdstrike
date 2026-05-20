import Foundation

public struct NetworkExtensionFlowTarget: Equatable, Sendable {
    public var host: String
    public var port: Int

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    public var normalizedTarget: String {
        let normalizedHost = host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        return "\(normalizedHost):\(port)"
    }
}

public struct NetworkExtensionEgressRestriction: Codable, Equatable, Sendable {
    public var restrictionID: String
    public var actionID: String
    public var executionID: String
    public var target: String
    public var active: Bool
    public var expiresAt: Date

    public init(
        restrictionID: String,
        actionID: String,
        executionID: String,
        target: String,
        active: Bool = true,
        expiresAt: Date
    ) {
        self.restrictionID = restrictionID
        self.actionID = actionID
        self.executionID = executionID
        self.target = target
        self.active = active
        self.expiresAt = expiresAt
    }

    public func blocks(_ flow: NetworkExtensionFlowTarget, now: Date) -> Bool {
        active && expiresAt > now && normalizedTarget(target) == flow.normalizedTarget
    }

    enum CodingKeys: String, CodingKey {
        case restrictionID = "restrictionId"
        case actionID = "actionId"
        case executionID = "executionId"
        case target
        case active
        case expiresAt
    }
}

public enum NetworkExtensionFlowDecision: Equatable, Sendable {
    case allow
    case block(NetworkExtensionEgressRestriction)
}

public struct NetworkExtensionEgressPolicy: Equatable, Sendable {
    public var generatedAt: Date?
    public var restrictions: [NetworkExtensionEgressRestriction]

    public init(generatedAt: Date? = nil, restrictions: [NetworkExtensionEgressRestriction]) {
        self.generatedAt = generatedAt
        self.restrictions = restrictions
    }

    public var enforcementReady: Bool {
        restrictions.contains { $0.active }
    }

    public func decision(for target: NetworkExtensionFlowTarget, now: Date) -> NetworkExtensionFlowDecision {
        if let restriction = restrictions.first(where: { $0.blocks(target, now: now) }) {
            return .block(restriction)
        }
        return .allow
    }

    public static func loadSnapshot(from url: URL) throws -> NetworkExtensionEgressPolicy {
        try decodeSnapshot(data: Data(contentsOf: url))
    }

    public static func decodeSnapshot(data: Data) throws -> NetworkExtensionEgressPolicy {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            if let date = iso8601Formatter.date(from: value)
                ?? fractionalISO8601Formatter.date(from: value) {
                return date
            }
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid ISO-8601 timestamp"
            )
        }
        return try decoder.decode(NetworkExtensionEgressPolicySnapshot.self, from: data).policy
    }
}

public struct NetworkExtensionEgressPolicyReloader: Sendable {
    public let snapshotURL: URL
    public private(set) var policy: NetworkExtensionEgressPolicy?
    private var lastSnapshotData: Data?

    public init(snapshotURL: URL) {
        self.snapshotURL = snapshotURL
        self.policy = nil
        self.lastSnapshotData = nil
    }

    public mutating func reloadIfChanged() throws -> Bool {
        let data = try Data(contentsOf: snapshotURL)
        guard data != lastSnapshotData else {
            return false
        }
        policy = try NetworkExtensionEgressPolicy.decodeSnapshot(data: data)
        lastSnapshotData = data
        return true
    }
}

private struct NetworkExtensionEgressPolicySnapshot: Decodable {
    var generatedAt: Date?
    var restrictions: [NetworkExtensionEgressRestriction]

    var policy: NetworkExtensionEgressPolicy {
        NetworkExtensionEgressPolicy(generatedAt: generatedAt, restrictions: restrictions)
    }
}

private func normalizedTarget(_ target: String) -> String {
    let parts = target.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2 else {
        return target
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }
    let host = parts[0]
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        .lowercased()
    let port = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
    return "\(host):\(port)"
}

private let iso8601Formatter: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter
}()

private let fractionalISO8601Formatter: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter
}()
