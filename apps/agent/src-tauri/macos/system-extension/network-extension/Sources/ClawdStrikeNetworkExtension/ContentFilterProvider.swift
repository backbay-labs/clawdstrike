import Foundation

#if canImport(NetworkExtension)
import NetworkExtension

public final class ClawdStrikeContentFilterDataProvider: NEFilterDataProvider {
    private let lock = NSLock()
    private var installed: SystemExtensionInstallState
    private var approval: SystemExtensionApproval
    private var backendHint: MediationBackendHint?
    private var policySynced: Bool
    private var counters: NetworkExtensionCounters
    private var degradedReasons: [String]
    private var running: Bool
    private var lastHealthyAt: Date?

    public init(
        installState: SystemExtensionInstallState = .installed,
        approval: SystemExtensionApproval = .approved,
        backendHint: MediationBackendHint? = nil,
        policySynced: Bool = false
    ) {
        self.installed = installState
        self.approval = approval
        self.backendHint = backendHint
        self.policySynced = policySynced
        self.counters = NetworkExtensionCounters()
        self.degradedReasons = []
        self.running = false
        self.lastHealthyAt = nil
        super.init()
    }

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        lock.lock()
        running = true
        lock.unlock()
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        running = false
        degradedReasons = [stopReasonString(reason)]
        lock.unlock()
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        lock.lock()
        counters.flowsObserved += 1
        lock.unlock()

        // Baseline content-filter implementation: stay truthful about backend mediation
        // by carrying the backend hint in state, but do not pivot the provider away
        // from content filter here.
        return .allow()
    }

    public func markPolicySynced(_ synced: Bool) {
        lock.lock()
        policySynced = synced
        lock.unlock()
    }

    public func markDegraded(reason: String) {
        lock.lock()
        degradedReasons = [reason]
        lock.unlock()
    }

    public func recordDroppedVerdict() {
        lock.lock()
        counters.droppedVerdicts += 1
        lock.unlock()
    }

    public func snapshot() -> NetworkExtensionProviderSnapshot {
        lock.lock()
        let inputs = NetworkExtensionProviderInputs(
            installState: installed,
            approval: approval,
            providerKind: .contentFilter,
            backendHint: backendHint,
            filterRunning: running,
            policySynced: policySynced,
            degradedReasons: degradedReasons,
            lastHealthyAt: lastHealthyAt,
            counters: counters
        )
        lock.unlock()
        return NetworkExtensionStateProjector.snapshot(from: inputs)
    }

    private func stopReasonString(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none:
            return "none"
        case .authenticationCanceled:
            return "authentication_canceled"
        case .configurationDisabled:
            return "configuration_disabled"
        case .configurationFailed:
            return "configuration_failed"
        case .configurationRemoved:
            return "configuration_removed"
        case .connectionFailed:
            return "connection_failed"
        case .idleTimeout:
            return "idle_timeout"
        case .noNetworkAvailable:
            return "no_network_available"
        case .providerDisabled:
            return "provider_disabled"
        case .providerFailed:
            return "provider_failed"
        case .sleep:
            return "sleep"
        case .superceded:
            return "superceded"
        case .unrecoverableNetworkChange:
            return "unrecoverable_network_change"
        case .appUpdate:
            return "app_update"
        case .userInitiated:
            return "user_initiated"
        case .userLogout:
            return "user_logout"
        case .userSwitch:
            return "user_switch"
        case .internalError:
            return "internal_error"
        @unknown default:
            return "provider_stopped_unknown_reason"
        }
    }
}
#else
public final class ClawdStrikeContentFilterDataProvider {
    public init() {}
}
#endif
