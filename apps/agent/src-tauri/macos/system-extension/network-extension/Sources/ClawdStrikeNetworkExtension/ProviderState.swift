import Foundation

public enum SystemExtensionInstallState: String, Codable, Equatable, Sendable {
    case unknown
    case notInstalled = "not_installed"
    case installed
}

public enum SystemExtensionApproval: String, Codable, Equatable, Sendable {
    case unknown
    case approved
    case approvalBlocked = "approval_blocked"
}

public enum ProviderRuntimeState: Codable, Equatable, Sendable {
    case unknown
    case inactive
    case active
    case degraded(reason: String)

    private enum CodingKeys: String, CodingKey {
        case state
        case reason
    }

    private enum StateValue: String, Codable {
        case unknown
        case inactive
        case active
        case degraded
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(StateValue.self, forKey: .state) {
        case .unknown:
            self = .unknown
        case .inactive:
            self = .inactive
        case .active:
            self = .active
        case .degraded:
            self = .degraded(reason: try container.decode(String.self, forKey: .reason))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unknown:
            try container.encode(StateValue.unknown, forKey: .state)
        case .inactive:
            try container.encode(StateValue.inactive, forKey: .state)
        case .active:
            try container.encode(StateValue.active, forKey: .state)
        case .degraded(let reason):
            try container.encode(StateValue.degraded, forKey: .state)
            try container.encode(reason, forKey: .reason)
        }
    }
}

public struct HostProviderStatus: Codable, Equatable, Sendable {
    public var runtime: ProviderRuntimeState

    public init(runtime: ProviderRuntimeState) {
        self.runtime = runtime
    }
}

public enum ProviderApprovalStatus: String, Codable, Equatable, Sendable {
    case notRequired = "not_required"
    case approved
    case blocked
    case missing
    case unknown
}

public enum ProviderAvailability: String, Codable, Equatable, Sendable {
    case unavailable
    case inactive
    case active
    case degraded
}

public struct AttestationProviderState: Codable, Equatable, Sendable {
    public var provider: String
    public var installed: Bool
    public var approvalStatus: ProviderApprovalStatus
    public var active: Bool
    public var healthy: Bool
    public var availability: ProviderAvailability
    public var degradedReasons: [String]
    public var lastHealthyTimestamp: String?

    public init(
        provider: String = "network_extension",
        installed: Bool,
        approvalStatus: ProviderApprovalStatus,
        active: Bool,
        healthy: Bool,
        availability: ProviderAvailability,
        degradedReasons: [String] = [],
        lastHealthyTimestamp: String? = nil
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

public enum NetworkExtensionProviderKind: String, Codable, Equatable, Sendable {
    case contentFilter = "content_filter"
    case transparentProxy = "transparent_proxy"
}

public enum MediationBackendHint: String, Codable, Equatable, Sendable {
    case legacyProxyOnlyRuntime = "legacy_proxy_only_runtime"
}

public struct NetworkExtensionCounters: Codable, Equatable, Sendable {
    public var flowsObserved: UInt64
    public var flowsBlocked: UInt64
    public var remediationRequests: UInt64
    public var droppedVerdicts: UInt64

    public init(
        flowsObserved: UInt64 = 0,
        flowsBlocked: UInt64 = 0,
        remediationRequests: UInt64 = 0,
        droppedVerdicts: UInt64 = 0
    ) {
        self.flowsObserved = flowsObserved
        self.flowsBlocked = flowsBlocked
        self.remediationRequests = remediationRequests
        self.droppedVerdicts = droppedVerdicts
    }

    enum CodingKeys: String, CodingKey {
        case flowsObserved = "flows_observed"
        case flowsBlocked = "flows_blocked"
        case remediationRequests = "remediation_requests"
        case droppedVerdicts = "dropped_verdicts"
    }
}

public struct ProviderSelectionEvidence: Codable, Equatable, Sendable {
    public var requestedProvider: NetworkExtensionProviderKind
    public var effectiveProvider: NetworkExtensionProviderKind
    public var backendHint: MediationBackendHint?
    public var exceptionRequired: Bool

    public init(
        requestedProvider: NetworkExtensionProviderKind,
        effectiveProvider: NetworkExtensionProviderKind,
        backendHint: MediationBackendHint?,
        exceptionRequired: Bool
    ) {
        self.requestedProvider = requestedProvider
        self.effectiveProvider = effectiveProvider
        self.backendHint = backendHint
        self.exceptionRequired = exceptionRequired
    }

    enum CodingKeys: String, CodingKey {
        case requestedProvider = "requested_provider"
        case effectiveProvider = "effective_provider"
        case backendHint = "backend_hint"
        case exceptionRequired = "exception_required"
    }
}

public struct NetworkExtensionProviderSnapshot: Codable, Equatable, Sendable {
    public var installState: SystemExtensionInstallState
    public var approval: SystemExtensionApproval
    public var providerKind: NetworkExtensionProviderKind
    public var backendHint: MediationBackendHint?
    public var policySynced: Bool
    public var hostStatus: HostProviderStatus
    public var attestationState: AttestationProviderState
    public var counters: NetworkExtensionCounters
    public var selectionEvidence: ProviderSelectionEvidence

    public init(
        installState: SystemExtensionInstallState,
        approval: SystemExtensionApproval,
        providerKind: NetworkExtensionProviderKind,
        backendHint: MediationBackendHint?,
        policySynced: Bool,
        hostStatus: HostProviderStatus,
        attestationState: AttestationProviderState,
        counters: NetworkExtensionCounters,
        selectionEvidence: ProviderSelectionEvidence
    ) {
        self.installState = installState
        self.approval = approval
        self.providerKind = providerKind
        self.backendHint = backendHint
        self.policySynced = policySynced
        self.hostStatus = hostStatus
        self.attestationState = attestationState
        self.counters = counters
        self.selectionEvidence = selectionEvidence
    }

    enum CodingKeys: String, CodingKey {
        case installState = "install_state"
        case approval
        case providerKind = "provider_kind"
        case backendHint = "backend_hint"
        case policySynced = "policy_synced"
        case hostStatus = "host_status"
        case attestationState = "attestation_state"
        case counters
        case selectionEvidence = "selection_evidence"
    }
}

public struct NetworkExtensionProviderInputs: Equatable, Sendable {
    public var installState: SystemExtensionInstallState
    public var approval: SystemExtensionApproval
    public var providerKind: NetworkExtensionProviderKind
    public var backendHint: MediationBackendHint?
    public var filterRunning: Bool
    public var policySynced: Bool
    public var degradedReasons: [String]
    public var lastHealthyAt: Date?
    public var counters: NetworkExtensionCounters

    public init(
        installState: SystemExtensionInstallState = .unknown,
        approval: SystemExtensionApproval = .unknown,
        providerKind: NetworkExtensionProviderKind = .contentFilter,
        backendHint: MediationBackendHint? = nil,
        filterRunning: Bool = false,
        policySynced: Bool = false,
        degradedReasons: [String] = [],
        lastHealthyAt: Date? = nil,
        counters: NetworkExtensionCounters = .init()
    ) {
        self.installState = installState
        self.approval = approval
        self.providerKind = providerKind
        self.backendHint = backendHint
        self.filterRunning = filterRunning
        self.policySynced = policySynced
        self.degradedReasons = degradedReasons
        self.lastHealthyAt = lastHealthyAt
        self.counters = counters
    }
}

public enum ProviderSelectionError: Error, Equatable, Sendable {
    case transparentProxyExceptionRequired
}

public enum NetworkExtensionFixtureScenario: String {
    case selection
    case inactive
    case unavailable
    case approvalBlocked = "approval-blocked"

    public static func resolve(argument: String?) throws -> Self {
        guard let argument else {
            throw NetworkExtensionStatusToolError.missingScenario
        }
        guard let scenario = Self(rawValue: argument) else {
            throw NetworkExtensionStatusToolError.unsupportedScenario(argument)
        }
        return scenario
    }
}

public enum NetworkExtensionStatusToolError: Error, Equatable, LocalizedError {
    case missingScenario
    case unsupportedScenario(String)

    public var errorDescription: String? {
        switch self {
        case .missingScenario:
            return "missing network-extension fixture scenario"
        case .unsupportedScenario(let value):
            return "unsupported network-extension scenario: \(value)"
        }
    }
}

public enum NetworkExtensionStatusTool {
    public static func liveSnapshot() -> NetworkExtensionProviderSnapshot {
        NetworkExtensionStateProjector.snapshot(from: NetworkExtensionProviderInputs())
    }

    public static func fixtureSnapshot(_ scenario: NetworkExtensionFixtureScenario) -> NetworkExtensionProviderSnapshot {
        switch scenario {
        case .selection:
            return NetworkExtensionStateProjector.snapshot(
                from: NetworkExtensionProviderInputs(
                    installState: .installed,
                    approval: .approved,
                    providerKind: .contentFilter,
                    backendHint: .legacyProxyOnlyRuntime,
                    filterRunning: true,
                    policySynced: true,
                    degradedReasons: [],
                    lastHealthyAt: nil,
                    counters: NetworkExtensionCounters(
                        flowsObserved: 42,
                        flowsBlocked: 0,
                        remediationRequests: 0,
                        droppedVerdicts: 0
                    )
                )
            )
        case .inactive:
            return NetworkExtensionStateProjector.snapshot(
                from: NetworkExtensionProviderInputs(
                    installState: .installed,
                    approval: .approved,
                    providerKind: .contentFilter,
                    backendHint: .legacyProxyOnlyRuntime,
                    filterRunning: false,
                    policySynced: false,
                    degradedReasons: ["provider_failed"],
                    lastHealthyAt: nil
                )
            )
        case .unavailable:
            return NetworkExtensionStateProjector.snapshot(
                from: NetworkExtensionProviderInputs(
                    installState: .notInstalled,
                    approval: .unknown,
                    providerKind: .contentFilter,
                    backendHint: .legacyProxyOnlyRuntime,
                    filterRunning: false,
                    policySynced: false
                )
            )
        case .approvalBlocked:
            return NetworkExtensionStateProjector.snapshot(
                from: NetworkExtensionProviderInputs(
                    installState: .installed,
                    approval: .approvalBlocked,
                    providerKind: .contentFilter,
                    backendHint: .legacyProxyOnlyRuntime,
                    filterRunning: false,
                    policySynced: false
                )
            )
        }
    }
}

public enum NetworkExtensionStateProjector {
    public static func snapshot(from inputs: NetworkExtensionProviderInputs) -> NetworkExtensionProviderSnapshot {
        let health = deriveHealth(inputs)
        return NetworkExtensionProviderSnapshot(
            installState: inputs.installState,
            approval: inputs.approval,
            providerKind: inputs.providerKind,
            backendHint: inputs.backendHint,
            policySynced: inputs.policySynced,
            hostStatus: HostProviderStatus(runtime: health.hostRuntime),
            attestationState: AttestationProviderState(
                installed: health.installed,
                approvalStatus: health.approvalStatus,
                active: health.active,
                healthy: health.healthy,
                availability: health.availability,
                degradedReasons: health.degradedReasons,
                lastHealthyTimestamp: health.lastHealthyTimestamp
            ),
            counters: inputs.counters,
            selectionEvidence: ProviderSelectionEvidence(
                requestedProvider: inputs.providerKind,
                effectiveProvider: .contentFilter,
                backendHint: inputs.backendHint,
                exceptionRequired: inputs.providerKind != .contentFilter
            )
        )
    }

    public static func requireContentFilterBaseline(
        requestedProvider: NetworkExtensionProviderKind,
        backendHint: MediationBackendHint?
    ) throws -> ProviderSelectionEvidence {
        let evidence = ProviderSelectionEvidence(
            requestedProvider: requestedProvider,
            effectiveProvider: .contentFilter,
            backendHint: backendHint,
            exceptionRequired: requestedProvider != .contentFilter
        )
        guard requestedProvider == .contentFilter else {
            throw ProviderSelectionError.transparentProxyExceptionRequired
        }
        return evidence
    }

    private static func deriveHealth(_ inputs: NetworkExtensionProviderInputs) -> DerivedHealth {
        let installed = inputs.installState == .installed
        let approvalStatus = approvalStatus(for: inputs.approval)
        let droppedVerdictsReason = inputs.counters.droppedVerdicts > 0 ? "dropped_verdicts" : nil

        let degradedReasons = uniqueReasons([inputs.degradedReasons, droppedVerdictsReason.map { [$0] } ?? []]
            .flatMap { $0 })

        if inputs.installState == .unknown && inputs.approval == .unknown {
            return DerivedHealth(
                installed: false,
                approvalStatus: .unknown,
                active: false,
                healthy: false,
                availability: .unavailable,
                degradedReasons: ["provider_state_unknown"],
                hostRuntime: .unknown,
                lastHealthyTimestamp: nil
            )
        }

        if !installed {
            return DerivedHealth(
                installed: false,
                approvalStatus: approvalStatus,
                active: false,
                healthy: false,
                availability: .unavailable,
                degradedReasons: ["system_extension_not_installed"],
                hostRuntime: .degraded(reason: "system_extension_not_installed"),
                lastHealthyTimestamp: nil
            )
        }

        if inputs.approval == .approvalBlocked {
            return DerivedHealth(
                installed: true,
                approvalStatus: approvalStatus,
                active: false,
                healthy: false,
                availability: .unavailable,
                degradedReasons: ["approval_blocked"],
                hostRuntime: .degraded(reason: "approval_blocked"),
                lastHealthyTimestamp: nil
            )
        }

        if !inputs.filterRunning {
            let reasons = degradedReasons.isEmpty ? ["provider_inactive"] : degradedReasons
            return DerivedHealth(
                installed: true,
                approvalStatus: approvalStatus,
                active: false,
                healthy: false,
                availability: .inactive,
                degradedReasons: reasons,
                hostRuntime: .inactive,
                lastHealthyTimestamp: lastHealthyTimestamp(from: inputs.lastHealthyAt)
            )
        }

        if !inputs.policySynced {
            let reasons = uniqueReasons(degradedReasons + ["policy_not_synced"])
            return DerivedHealth(
                installed: true,
                approvalStatus: approvalStatus,
                active: true,
                healthy: false,
                availability: .degraded,
                degradedReasons: reasons,
                hostRuntime: .degraded(reason: "policy_not_synced"),
                lastHealthyTimestamp: lastHealthyTimestamp(from: inputs.lastHealthyAt)
            )
        }

        if let firstReason = degradedReasons.first {
            return DerivedHealth(
                installed: true,
                approvalStatus: approvalStatus,
                active: true,
                healthy: false,
                availability: .degraded,
                degradedReasons: degradedReasons,
                hostRuntime: .degraded(reason: firstReason),
                lastHealthyTimestamp: lastHealthyTimestamp(from: inputs.lastHealthyAt)
            )
        }

        let reasons = uniqueReasons(degradedReasons + ["non_enforcing_provider"])
        return DerivedHealth(
            installed: true,
            approvalStatus: approvalStatus,
            active: true,
            healthy: false,
            availability: .degraded,
            degradedReasons: reasons,
            hostRuntime: .degraded(reason: reasons[0]),
            lastHealthyTimestamp: lastHealthyTimestamp(from: inputs.lastHealthyAt)
        )
    }

    private static func approvalStatus(for approval: SystemExtensionApproval) -> ProviderApprovalStatus {
        switch approval {
        case .unknown:
            return .unknown
        case .approved:
            return .approved
        case .approvalBlocked:
            return .blocked
        }
    }

    private static func lastHealthyTimestamp(from date: Date?) -> String? {
        guard let date else {
            return nil
        }
        return ISO8601DateFormatter().string(from: date)
    }

    private static func uniqueReasons(_ reasons: [String]) -> [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for reason in reasons where seen.insert(reason).inserted {
            ordered.append(reason)
        }
        return ordered
    }
}

private struct DerivedHealth {
    var installed: Bool
    var approvalStatus: ProviderApprovalStatus
    var active: Bool
    var healthy: Bool
    var availability: ProviderAvailability
    var degradedReasons: [String]
    var hostRuntime: ProviderRuntimeState
    var lastHealthyTimestamp: String?
}
