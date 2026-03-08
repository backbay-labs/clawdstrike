import Foundation

#if canImport(EndpointSecurity)
import EndpointSecurity
#endif

public final class EndpointSecurityMonitor {
    public static let endpointSecurityProvider = "endpoint_security"
    public static let authorizationContract = "macos_endpoint_security_auth_contract"
    public static let authorizationModel = "auth_open_point_in_time"

    private var installState: SystemExtensionInstallState
    private var approval: SystemExtensionApproval
    private var providerActive: Bool
    private var fullDiskAccessGranted: Bool
    private var counters: EndpointSecurityCounters
    private var evidencePaths: [EvidenceArtifact]
    private var lastHealthyTimestamp: String?
    private var healthyObservationSeen: Bool

    public init(
        installState: SystemExtensionInstallState = .unknown,
        approval: SystemExtensionApproval = .unknown,
        providerActive: Bool = false,
        fullDiskAccessGranted: Bool = true
    ) {
        self.installState = installState
        self.approval = approval
        self.providerActive = providerActive
        self.fullDiskAccessGranted = fullDiskAccessGranted
        self.counters = EndpointSecurityCounters()
        self.evidencePaths = []
        self.lastHealthyTimestamp = nil
        self.healthyObservationSeen = false
    }

    public func recordAuthorization(_ event: AuthorizationEvent) {
        switch event.decision {
        case .allow:
            counters.authOpenAllowCount += 1
        case .deny:
            counters.authOpenDenyCount += 1
        }

        if event.notifyObserved {
            counters.notifyOpenCount += 1
        }

        if event.exceededDeadline {
            counters.deadlineMissCount += 1
        } else {
            healthyObservationSeen = true
            recordHealthyObservation(at: event.observedAt ?? Date())
        }
    }

    public func recordDroppedEvents(
        count: UInt64,
        evidencePath: String,
        detail: String = "EndpointSecurity reported dropped enforcement events."
    ) {
        counters.droppedEventCount += count
        addEvidence(kind: "dropped_events", path: evidencePath, detail: detail)
    }

    public func setFullDiskAccessGranted(
        _ granted: Bool,
        evidencePath: String? = nil,
        detail: String = "Full Disk Access is missing for the EndpointSecurity host."
    ) {
        fullDiskAccessGranted = granted
        if !granted {
            if let evidencePath {
                addEvidence(kind: "missing_full_disk_access", path: evidencePath, detail: detail)
            }
        }
    }

    public func setProviderActive(
        _ active: Bool,
        evidencePath: String? = nil,
        detail: String = "EndpointSecurity provider is installed but inactive."
    ) {
        providerActive = active
        if !active {
            if let evidencePath {
                addEvidence(kind: "inactive_provider", path: evidencePath, detail: detail)
            }
        }
    }

    public func setInstallState(_ state: SystemExtensionInstallState) {
        installState = state
    }

    public func setApproval(
        _ value: SystemExtensionApproval,
        evidencePath: String? = nil,
        detail: String = "System extension approval is blocked or missing."
    ) {
        approval = value
        if value == .approvalBlocked {
            if let evidencePath {
                addEvidence(kind: "approval_blocked", path: evidencePath, detail: detail)
            }
        }
    }

    public func snapshot() -> EndpointSecurityStatusReport {
        let degradedReasons = currentDegradedReasons()
        let providerState = currentProviderState()
        let hostStatus = HostEndpointSecurityStatusPatch(
            installState: installState,
            approval: approval,
            endpointSecurity: HostProviderStatus(runtime: currentHostRuntimeState())
        )

        return EndpointSecurityStatusReport(
            contract: Self.authorizationContract,
            authorizationModel: Self.authorizationModel,
            fdInjectionEquivalent: false,
            failOpenPossible: true,
            hostStatus: hostStatus,
            providerState: providerState,
            counters: counters,
            degradedReasons: degradedReasons,
            evidencePaths: evidencePaths
        )
    }

    public static func liveReport() -> EndpointSecurityStatusReport {
        EndpointSecurityMonitor().snapshot()
    }

    public static func fixtureScenario(_ scenario: EndpointSecurityFixtureScenario) -> EndpointSecurityStatusReport {
        let monitor = EndpointSecurityMonitor(
            installState: .installed,
            approval: .approved,
            providerActive: true,
            fullDiskAccessGranted: true
        )
        switch scenario {
        case .healthyAllow:
            monitor.recordAuthorization(
                AuthorizationEvent(
                    path: "/Applications/Notes.app/Contents/MacOS/Notes",
                    decision: .allow,
                    latencyMs: 12,
                    deadlineMs: 200,
                    notifyObserved: true,
                    observedAt: Date(timeIntervalSince1970: 1_778_824_800)
                )
            )
        case .denyDecision:
            monitor.recordAuthorization(
                AuthorizationEvent(
                    path: "/private/tmp/blocked.txt",
                    decision: .deny,
                    latencyMs: 18,
                    deadlineMs: 200,
                    notifyObserved: false,
                    observedAt: Date(timeIntervalSince1970: 1_778_824_860)
                )
            )
        case .deadlineMiss:
            monitor.recordAuthorization(
                AuthorizationEvent(
                    path: "/private/tmp/slow.txt",
                    decision: .deny,
                    latencyMs: 275,
                    deadlineMs: 200,
                    notifyObserved: false,
                    observedAt: Date(timeIntervalSince1970: 1_778_824_920)
                )
            )
            monitor.addEvidence(
                kind: "deadline_miss",
                path: "fixtures/macos/endpoint-security/evidence/deadline-miss.json",
                detail: "Synthetic over-deadline AUTH_OPEN path proving fail-open risk."
            )
        case .droppedEvents:
            monitor.recordAuthorization(
                AuthorizationEvent(
                    path: "/private/tmp/allow.txt",
                    decision: .allow,
                    latencyMs: 16,
                    deadlineMs: 200,
                    notifyObserved: true,
                    observedAt: Date(timeIntervalSince1970: 1_778_824_980)
                )
            )
            monitor.recordDroppedEvents(
                count: 3,
                evidencePath: "fixtures/macos/endpoint-security/evidence/dropped-events.json"
            )
        case .missingFullDiskAccess:
            monitor.setFullDiskAccessGranted(
                false,
                evidencePath: "fixtures/macos/endpoint-security/evidence/missing-full-disk-access.json"
            )
        case .inactiveProvider:
            monitor.setProviderActive(
                false,
                evidencePath: "fixtures/macos/endpoint-security/evidence/inactive-provider.json"
            )
        case .approvalBlocked:
            monitor.setApproval(
                .approvalBlocked,
                evidencePath: "fixtures/macos/endpoint-security/evidence/approval-blocked.json"
            )
        }
        return monitor.snapshot()
    }

    private func currentProviderState() -> AttestationProviderState {
        let hostRuntime = currentHostRuntimeState()
        let degradedReasons = currentDegradedReasons()
        let installed = installState == .installed
        let approvalStatus: ProviderApprovalStatus = {
            switch approval {
            case .unknown:
                return .unknown
            case .approved:
                return .approved
            case .approvalBlocked:
                return .blocked
            }
        }()
        let active = installState == .installed && approval == .approved && providerActive

        let availability: ProviderAvailability = {
            switch hostRuntime {
            case .active:
                return .active
            case .inactive:
                return .inactive
            case .unknown:
                return installed ? .inactive : .unavailable
            case .degraded:
                if !installed || approval == .approvalBlocked {
                    return .unavailable
                }
                if !providerActive {
                    return .inactive
                }
                return .degraded
            }
        }()

        let healthy = {
            if case .active = hostRuntime {
                return true
            }
            return false
        }()

        return AttestationProviderState(
            provider: Self.endpointSecurityProvider,
            installed: installed,
            approvalStatus: approvalStatus,
            active: active,
            healthy: healthy,
            availability: availability,
            degradedReasons: degradedReasons,
            lastHealthyTimestamp: lastHealthyTimestamp
        )
    }

    private func currentHostRuntimeState() -> HostProviderRuntimeState {
        if installState == .unknown {
            return .unknown
        }
        if installState == .notInstalled {
            return .degraded(reason: "system_extension_not_installed")
        }
        if approval == .unknown {
            return .unknown
        }
        if approval == .approvalBlocked {
            return .degraded(reason: "system_extension_approval_blocked")
        }
        if !providerActive {
            return .inactive
        }
        if !fullDiskAccessGranted {
            return .degraded(reason: "missing_full_disk_access")
        }
        if counters.deadlineMissCount > 0 {
            return .degraded(reason: "authorization_deadline_missed")
        }
        if counters.droppedEventCount > 0 {
            return .degraded(reason: "dropped_enforcement_events")
        }
        if !healthyObservationSeen {
            return .degraded(reason: "live_authorization_signal_missing")
        }
        return .active
    }

    private func currentDegradedReasons() -> [String] {
        var reasons: [String] = []
        if installState == .unknown || (installState == .installed && approval == .unknown) {
            reasons.append("provider_state_unknown")
        }
        if installState == .notInstalled {
            reasons.append("system_extension_not_installed")
        }
        if approval == .approvalBlocked {
            reasons.append("system_extension_approval_blocked")
        }
        if installState == .installed && approval == .approved && !providerActive {
            reasons.append("provider_inactive")
        }
        if installState == .installed && approval == .approved && !fullDiskAccessGranted {
            reasons.append("missing_full_disk_access")
        }
        if counters.deadlineMissCount > 0 {
            reasons.append("authorization_deadline_missed")
        }
        if counters.droppedEventCount > 0 {
            reasons.append("dropped_enforcement_events")
        }
        if installState == .installed && approval == .approved && providerActive && fullDiskAccessGranted && !healthyObservationSeen {
            reasons.append("live_authorization_signal_missing")
        }
        return reasons
    }

    private func recordHealthyObservation(at date: Date) {
        lastHealthyTimestamp = ISO8601DateFormatter().string(from: date)
    }

    private func addEvidence(kind: String, path: String, detail: String) {
        let artifact = EvidenceArtifact(kind: kind, path: path, detail: detail)
        if !evidencePaths.contains(artifact) {
            evidencePaths.append(artifact)
        }
    }
}
