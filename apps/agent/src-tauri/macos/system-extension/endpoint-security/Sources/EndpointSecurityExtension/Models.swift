import Foundation

public enum SystemExtensionInstallState: String, Codable, Equatable {
    case unknown
    case notInstalled = "not_installed"
    case installed
}

public enum SystemExtensionApproval: String, Codable, Equatable {
    case unknown
    case approved
    case approvalBlocked = "approval_blocked"
}

public enum ProviderApprovalStatus: String, Codable, Equatable {
    case notRequired = "not_required"
    case approved
    case blocked
    case missing
    case unknown
}

public enum ProviderAvailability: String, Codable, Equatable {
    case unavailable
    case inactive
    case active
    case degraded
}

public struct HostProviderStatus: Codable, Equatable {
    public var runtime: HostProviderRuntimeState

    public init(runtime: HostProviderRuntimeState) {
        self.runtime = runtime
    }
}

public enum HostProviderRuntimeState: Equatable {
    case unknown
    case inactive
    case active
    case degraded(reason: String)
}

extension HostProviderRuntimeState: Codable {
    enum CodingKeys: String, CodingKey {
        case state
        case reason
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let state = try container.decode(String.self, forKey: .state)
        switch state {
        case "unknown":
            self = .unknown
        case "inactive":
            self = .inactive
        case "active":
            self = .active
        case "degraded":
            self = .degraded(reason: try container.decode(String.self, forKey: .reason))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .state,
                in: container,
                debugDescription: "unsupported provider runtime state: \(state)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unknown:
            try container.encode("unknown", forKey: .state)
        case .inactive:
            try container.encode("inactive", forKey: .state)
        case .active:
            try container.encode("active", forKey: .state)
        case .degraded(let reason):
            try container.encode("degraded", forKey: .state)
            try container.encode(reason, forKey: .reason)
        }
    }
}

public struct HostEndpointSecurityStatusPatch: Codable, Equatable {
    public var installState: SystemExtensionInstallState
    public var approval: SystemExtensionApproval
    public var endpointSecurity: HostProviderStatus

    public init(
        installState: SystemExtensionInstallState,
        approval: SystemExtensionApproval,
        endpointSecurity: HostProviderStatus
    ) {
        self.installState = installState
        self.approval = approval
        self.endpointSecurity = endpointSecurity
    }

    enum CodingKeys: String, CodingKey {
        case installState = "install_state"
        case approval
        case endpointSecurity = "endpoint_security"
    }
}

public struct AttestationProviderState: Codable, Equatable {
    public var provider: String
    public var installed: Bool
    public var approvalStatus: ProviderApprovalStatus
    public var active: Bool
    public var healthy: Bool
    public var availability: ProviderAvailability
    public var degradedReasons: [String]
    public var lastHealthyTimestamp: String?

    public init(
        provider: String,
        installed: Bool,
        approvalStatus: ProviderApprovalStatus,
        active: Bool,
        healthy: Bool,
        availability: ProviderAvailability,
        degradedReasons: [String],
        lastHealthyTimestamp: String?
    ) {
        self.provider = provider
        self.installed = installed
        self.approvalStatus = approvalStatus
        self.active = active
        self.healthy = healthy
        self.availability = availability
        self.degradedReasons = degradedReasons
        self.lastHealthyTimestamp = lastHealthyTimestamp
    }

    enum CodingKeys: String, CodingKey {
        case provider
        case installed
        case approvalStatus = "approval_status"
        case active
        case healthy
        case availability
        case degradedReasons = "degraded_reasons"
        case lastHealthyTimestamp = "last_healthy_timestamp"
    }
}

public struct EndpointSecurityCounters: Codable, Equatable {
    public var authOpenAllowCount: UInt64
    public var authOpenDenyCount: UInt64
    public var notifyOpenCount: UInt64
    public var deadlineMissCount: UInt64
    public var droppedEventCount: UInt64

    public init(
        authOpenAllowCount: UInt64 = 0,
        authOpenDenyCount: UInt64 = 0,
        notifyOpenCount: UInt64 = 0,
        deadlineMissCount: UInt64 = 0,
        droppedEventCount: UInt64 = 0
    ) {
        self.authOpenAllowCount = authOpenAllowCount
        self.authOpenDenyCount = authOpenDenyCount
        self.notifyOpenCount = notifyOpenCount
        self.deadlineMissCount = deadlineMissCount
        self.droppedEventCount = droppedEventCount
    }

    enum CodingKeys: String, CodingKey {
        case authOpenAllowCount = "auth_open_allow_count"
        case authOpenDenyCount = "auth_open_deny_count"
        case notifyOpenCount = "notify_open_count"
        case deadlineMissCount = "deadline_miss_count"
        case droppedEventCount = "dropped_event_count"
    }
}

public struct EvidenceArtifact: Codable, Equatable {
    public var kind: String
    public var path: String
    public var detail: String

    public init(kind: String, path: String, detail: String) {
        self.kind = kind
        self.path = path
        self.detail = detail
    }
}

public struct EndpointSecurityStatusReport: Codable, Equatable {
    public var contract: String
    public var authorizationModel: String
    public var fdInjectionEquivalent: Bool
    public var failOpenPossible: Bool
    public var hostStatus: HostEndpointSecurityStatusPatch
    public var providerState: AttestationProviderState
    public var counters: EndpointSecurityCounters
    public var degradedReasons: [String]
    public var evidencePaths: [EvidenceArtifact]

    public init(
        contract: String,
        authorizationModel: String,
        fdInjectionEquivalent: Bool,
        failOpenPossible: Bool,
        hostStatus: HostEndpointSecurityStatusPatch,
        providerState: AttestationProviderState,
        counters: EndpointSecurityCounters,
        degradedReasons: [String],
        evidencePaths: [EvidenceArtifact]
    ) {
        self.contract = contract
        self.authorizationModel = authorizationModel
        self.fdInjectionEquivalent = fdInjectionEquivalent
        self.failOpenPossible = failOpenPossible
        self.hostStatus = hostStatus
        self.providerState = providerState
        self.counters = counters
        self.degradedReasons = degradedReasons
        self.evidencePaths = evidencePaths
    }

    enum CodingKeys: String, CodingKey {
        case contract
        case authorizationModel = "authorization_model"
        case fdInjectionEquivalent = "fd_injection_equivalent"
        case failOpenPossible = "fail_open_possible"
        case hostStatus = "host_status"
        case providerState = "provider_state"
        case counters
        case degradedReasons = "degraded_reasons"
        case evidencePaths = "evidence_paths"
    }
}

public enum AuthorizationDecision: String, Codable, Equatable {
    case allow
    case deny
}

public struct AuthorizationEvent: Codable, Equatable {
    public var eventType: String
    public var path: String
    public var decision: AuthorizationDecision
    public var latencyMs: UInt64
    public var deadlineMs: UInt64
    public var notifyObserved: Bool
    public var observedAt: Date?

    public init(
        eventType: String = "auth_open",
        path: String,
        decision: AuthorizationDecision,
        latencyMs: UInt64,
        deadlineMs: UInt64,
        notifyObserved: Bool,
        observedAt: Date? = nil
    ) {
        self.eventType = eventType
        self.path = path
        self.decision = decision
        self.latencyMs = latencyMs
        self.deadlineMs = deadlineMs
        self.notifyObserved = notifyObserved
        self.observedAt = observedAt
    }

    public var exceededDeadline: Bool {
        latencyMs > deadlineMs
    }

    enum CodingKeys: String, CodingKey {
        case eventType = "event_type"
        case path
        case decision
        case latencyMs = "latency_ms"
        case deadlineMs = "deadline_ms"
        case notifyObserved = "notify_observed"
    }
}

public enum EndpointSecurityFixtureScenario: String {
    case healthyAllow = "healthy-allow"
    case denyDecision = "deny-decision"
    case deadlineMiss = "deadline-miss"
    case droppedEvents = "dropped-events"
    case missingFullDiskAccess = "missing-full-disk-access"
    case inactiveProvider = "inactive-provider"
    case approvalBlocked = "approval-blocked"

    public static func resolve(commandLineArgument argument: String?) throws -> Self {
        guard let argument else {
            throw StatusToolScenarioError.missingScenario
        }
        guard let scenario = Self(rawValue: argument) else {
            throw StatusToolScenarioError.unsupportedScenario(argument)
        }
        return scenario
    }
}

public enum StatusToolScenarioError: Error, Equatable, LocalizedError {
    case missingScenario
    case unsupportedScenario(String)

    public var errorDescription: String? {
        switch self {
        case .missingScenario:
            return "missing endpoint-security fixture scenario"
        case .unsupportedScenario(let value):
            return "unsupported endpoint-security scenario: \(value)"
        }
    }
}

public enum ClawdStrikeAgentConfigPaths {
    public static func configDirectory(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        #if os(macOS)
        return homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("clawdstrike", isDirectory: true)
        #else
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("clawdstrike", isDirectory: true)
        #endif
    }

    public static func legacyDotConfigDirectory(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("clawdstrike", isDirectory: true)
    }

    public static func agentTokenCandidates(
        explicitPath: String? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String] {
        if let explicitPath, !explicitPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return [explicitPath]
        }
        let primary = configDirectory(homeDirectory: homeDirectory)
            .appendingPathComponent("agent-local-token")
            .path
        let legacy = legacyDotConfigDirectory(homeDirectory: homeDirectory)
            .appendingPathComponent("agent-local-token")
            .path
        return primary == legacy ? [primary] : [primary, legacy]
    }
}
