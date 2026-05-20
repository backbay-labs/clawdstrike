import Foundation

#if canImport(NetworkExtension)
import Dispatch
import NetworkExtension
#endif

public struct NetworkExtensionProviderCommandContext: Equatable, Sendable {
    public var installState: SystemExtensionInstallState
    public var approval: SystemExtensionApproval
    public var backendHint: MediationBackendHint?
    public var filterRunning: Bool

    public init(
        installState: SystemExtensionInstallState,
        approval: SystemExtensionApproval,
        backendHint: MediationBackendHint?,
        filterRunning: Bool
    ) {
        self.installState = installState
        self.approval = approval
        self.backendHint = backendHint
        self.filterRunning = filterRunning
    }
}

public struct NetworkExtensionProviderCommandResponse: Codable, Equatable, Sendable {
    public var requestID: String?
    public var command: String
    public var accepted: Bool
    public var reloaded: Bool
    public var snapshot: NetworkExtensionProviderSnapshot?
    public var error: String?

    public init(
        requestID: String?,
        command: String,
        accepted: Bool,
        reloaded: Bool,
        snapshot: NetworkExtensionProviderSnapshot?,
        error: String?
    ) {
        self.requestID = requestID
        self.command = command
        self.accepted = accepted
        self.reloaded = reloaded
        self.snapshot = snapshot
        self.error = error
    }

    enum CodingKeys: String, CodingKey {
        case requestID = "requestId"
        case command
        case accepted
        case reloaded
        case snapshot
        case error
    }
}

private struct NetworkExtensionProviderCommandRequest: Decodable {
    var requestID: String?
    var command: String
    var policySnapshotPath: String?
    var generation: UInt64?

    enum CodingKeys: String, CodingKey {
        case requestID = "requestId"
        case command
        case policySnapshotPath
        case generation
    }
}

public enum NetworkExtensionProviderCommand {
    public static let reloadPolicyCommand = "reload_policy"

    public static func handle(
        _ requestData: Data,
        runtime: NetworkExtensionContentFilterRuntime,
        context: NetworkExtensionProviderCommandContext
    ) throws -> Data {
        let decoder = JSONDecoder()
        let request = try decoder.decode(NetworkExtensionProviderCommandRequest.self, from: requestData)
        let response: NetworkExtensionProviderCommandResponse

        switch request.command {
        case reloadPolicyCommand:
            if let policySnapshotPath = request.policySnapshotPath,
               !policySnapshotPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                runtime.setPolicySnapshotSource(at: URL(fileURLWithPath: policySnapshotPath))
            }
            let reloaded = runtime.requestPolicyReloadFromHostApp(
                requestID: request.requestID,
                command: request.command,
                policySnapshotPath: request.policySnapshotPath,
                generation: request.generation
            )
            let snapshot = runtime.snapshot(
                installState: context.installState,
                approval: context.approval,
                backendHint: context.backendHint,
                filterRunning: context.filterRunning
            )
            runtime.persistSnapshot(
                installState: context.installState,
                approval: context.approval,
                backendHint: context.backendHint,
                filterRunning: context.filterRunning
            )
            response = NetworkExtensionProviderCommandResponse(
                requestID: request.requestID,
                command: request.command,
                accepted: true,
                reloaded: reloaded,
                snapshot: snapshot,
                error: reloaded ? nil : snapshot.lastError
            )
        default:
            response = NetworkExtensionProviderCommandResponse(
                requestID: request.requestID,
                command: request.command,
                accepted: false,
                reloaded: false,
                snapshot: nil,
                error: "unsupported_provider_command"
            )
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(response)
    }
}

public enum NetworkExtensionProviderVendorConfiguration {
    public static let commandKey = "clawdstrike.command"
    public static let requestIDKey = "clawdstrike.request_id"
    public static let policySnapshotPathKey = "clawdstrike.policy_snapshot_path"
    public static let generationKey = "clawdstrike.generation"

    public static func reloadPolicy(
        requestID: String,
        policySnapshotPath: String,
        generation: UInt64
    ) -> [String: Any] {
        [
            commandKey: NetworkExtensionProviderCommand.reloadPolicyCommand,
            requestIDKey: requestID,
            policySnapshotPathKey: policySnapshotPath,
            generationKey: generation,
        ]
    }

    public static func commandData(from vendorConfiguration: [String: Any]) throws -> Data {
        let command = vendorConfiguration[commandKey] as? String
        let requestID = vendorConfiguration[requestIDKey] as? String
        let policySnapshotPath = vendorConfiguration[policySnapshotPathKey] as? String
        let generation = vendorConfiguration[generationKey]

        var payload: [String: Any] = [
            "command": command ?? "",
        ]
        if let requestID {
            payload["requestId"] = requestID
        }
        if let policySnapshotPath {
            payload["policySnapshotPath"] = policySnapshotPath
        }
        if let generation = generation as? UInt64 {
            payload["generation"] = generation
        } else if let generation = generation as? Int {
            payload["generation"] = generation
        }
        return try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }
}

public struct NetworkExtensionProviderVendorConfigurationHandler {
    private var lastCommandData: Data?

    public init() {
        self.lastCommandData = nil
    }

    public mutating func handleIfChanged(
        _ vendorConfiguration: [String: Any],
        runtime: NetworkExtensionContentFilterRuntime,
        context: NetworkExtensionProviderCommandContext
    ) throws -> NetworkExtensionProviderCommandResponse? {
        guard vendorConfiguration[NetworkExtensionProviderVendorConfiguration.commandKey] != nil else {
            return nil
        }
        let commandData = try NetworkExtensionProviderVendorConfiguration.commandData(
            from: vendorConfiguration
        )
        guard commandData != lastCommandData else {
            return nil
        }

        let responseData = try NetworkExtensionProviderCommand.handle(
            commandData,
            runtime: runtime,
            context: context
        )
        let response = try JSONDecoder().decode(
            NetworkExtensionProviderCommandResponse.self,
            from: responseData
        )
        lastCommandData = commandData
        return response
    }
}

public protocol NetworkExtensionProviderVendorConfigurationStore: AnyObject {
    func loadVendorConfiguration() throws -> [String: Any]
    func saveVendorConfiguration(_ vendorConfiguration: [String: Any]) throws
}

public struct NetworkExtensionProviderReloadRequestResult: Codable, Equatable, Sendable {
    public var requestID: String
    public var command: String
    public var policySnapshotPath: String
    public var generation: UInt64
    public var saved: Bool

    public init(
        requestID: String,
        command: String,
        policySnapshotPath: String,
        generation: UInt64,
        saved: Bool
    ) {
        self.requestID = requestID
        self.command = command
        self.policySnapshotPath = policySnapshotPath
        self.generation = generation
        self.saved = saved
    }

    enum CodingKeys: String, CodingKey {
        case requestID = "requestId"
        case command
        case policySnapshotPath
        case generation
        case saved
    }
}

public enum NetworkExtensionProviderReloadRequester {
    @discardableResult
    public static func requestReload(
        policySnapshotPath: String,
        generation: UInt64,
        requestID: String,
        store: NetworkExtensionProviderVendorConfigurationStore
    ) throws -> NetworkExtensionProviderReloadRequestResult {
        let reloadConfiguration = NetworkExtensionProviderVendorConfiguration.reloadPolicy(
            requestID: requestID,
            policySnapshotPath: policySnapshotPath,
            generation: generation
        )
        var vendorConfiguration = try store.loadVendorConfiguration()
        for (key, value) in reloadConfiguration {
            vendorConfiguration[key] = value
        }
        try store.saveVendorConfiguration(vendorConfiguration)
        return NetworkExtensionProviderReloadRequestResult(
            requestID: requestID,
            command: NetworkExtensionProviderCommand.reloadPolicyCommand,
            policySnapshotPath: policySnapshotPath,
            generation: generation,
            saved: true
        )
    }
}

public enum NetworkExtensionProviderReloadStoreError: Error, LocalizedError, Equatable {
    case missingProviderConfiguration
    case preferenceOperationTimedOut(String)

    public var errorDescription: String? {
        switch self {
        case .missingProviderConfiguration:
            return "network-extension provider configuration is missing"
        case .preferenceOperationTimedOut(let operation):
            return "network-extension preference operation timed out: \(operation)"
        }
    }
}

#if canImport(NetworkExtension)
public final class NetworkExtensionFilterManagerVendorConfigurationStore:
    NetworkExtensionProviderVendorConfigurationStore {
    private let manager: NEFilterManager
    private let timeoutSeconds: Double

    public init(
        manager: NEFilterManager = .shared(),
        timeoutSeconds: Double = 10
    ) {
        self.manager = manager
        self.timeoutSeconds = timeoutSeconds
    }

    public func loadVendorConfiguration() throws -> [String: Any] {
        try waitForPreferenceOperation("load") { completion in
            manager.loadFromPreferences(completionHandler: completion)
        }
        return manager.providerConfiguration?.vendorConfiguration ?? [:]
    }

    public func saveVendorConfiguration(_ vendorConfiguration: [String: Any]) throws {
        guard let providerConfiguration = manager.providerConfiguration else {
            throw NetworkExtensionProviderReloadStoreError.missingProviderConfiguration
        }
        providerConfiguration.vendorConfiguration = vendorConfiguration
        try waitForPreferenceOperation("save") { completion in
            manager.saveToPreferences(completionHandler: completion)
        }
    }

    private func waitForPreferenceOperation(
        _ operationName: String,
        _ operation: (@escaping (Error?) -> Void) -> Void
    ) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var operationError: Error?
        operation { error in
            operationError = error
            semaphore.signal()
        }
        let timeout = DispatchTime.now() + timeoutSeconds
        guard semaphore.wait(timeout: timeout) == .success else {
            throw NetworkExtensionProviderReloadStoreError.preferenceOperationTimedOut(operationName)
        }
        if let operationError {
            throw operationError
        }
    }
}
#endif

public final class NetworkExtensionContentFilterRuntime {
    private let lock = NSLock()
    private var runtimeSnapshotStore: NetworkExtensionProviderRuntimeSnapshotStore?
    private var policySynced: Bool
    private var policy: NetworkExtensionEgressPolicy?
    private var policyReloader: NetworkExtensionEgressPolicyReloader?
    private var counters: NetworkExtensionCounters
    private var degradedReasons: [String]
    private var lastHealthyAt: Date?
    private var lastReloadObservation: NetworkExtensionProviderReloadObservation?
    private var lastError: String?

    public init(
        policySynced: Bool = false,
        policySnapshotURL: URL? = nil,
        runtimeSnapshotStore: NetworkExtensionProviderRuntimeSnapshotStore? = nil
    ) {
        self.runtimeSnapshotStore = runtimeSnapshotStore
        self.policySynced = policySynced
        self.policy = nil
        self.policyReloader = policySnapshotURL.map(NetworkExtensionEgressPolicyReloader.init(snapshotURL:))
        self.counters = NetworkExtensionCounters()
        self.degradedReasons = []
        self.lastHealthyAt = nil
        self.lastReloadObservation = nil
        self.lastError = nil
    }

    public func updatePolicy(_ nextPolicy: NetworkExtensionEgressPolicy) {
        lock.lock()
        policy = nextPolicy
        policySynced = true
        degradedReasons = []
        lastError = nil
        lock.unlock()
    }

    public func reloadPolicy(from url: URL) throws {
        updatePolicy(try NetworkExtensionEgressPolicy.loadSnapshot(from: url))
    }

    public func watchPolicySnapshot(at url: URL) {
        setPolicySnapshotSource(at: url)
        reloadWatchedPolicy()
    }

    public func setPolicySnapshotSource(at url: URL) {
        lock.lock()
        policyReloader = NetworkExtensionEgressPolicyReloader(snapshotURL: url)
        if runtimeSnapshotStore == nil {
            runtimeSnapshotStore = FileNetworkExtensionProviderRuntimeSnapshotStore(
                snapshotURL: NetworkExtensionStatusTool.runtimeSnapshotURL(for: url)
            )
        }
        lock.unlock()
    }

    @discardableResult
    public func reloadWatchedPolicy() -> Bool {
        lock.lock()
        guard var reloader = policyReloader else {
            lock.unlock()
            return false
        }
        lock.unlock()

        do {
            let didReload = try reloader.reloadIfChanged()
            lock.lock()
            policyReloader = reloader
            if didReload {
                policy = reloader.policy
                policySynced = true
                degradedReasons.removeAll()
                lastError = nil
            }
            lock.unlock()
            return didReload
        } catch {
            lock.lock()
            policyReloader = reloader
            policySynced = false
            degradedReasons = ["policy_reload_failed"]
            lastError = "policy_reload_failed"
            lock.unlock()
            return false
        }
    }

    @discardableResult
    public func requestPolicyReloadFromHostApp(
        requestID: String? = nil,
        command: String = NetworkExtensionProviderCommand.reloadPolicyCommand,
        policySnapshotPath: String? = nil,
        generation: UInt64? = nil
    ) -> Bool {
        lock.lock()
        counters.remediationRequests += 1
        lock.unlock()
        let reloaded = reloadWatchedPolicy()
        lock.lock()
        let reloadError = reloaded ? nil : lastError
        lastReloadObservation = NetworkExtensionProviderReloadObservation(
            requestID: requestID,
            command: command,
            policySnapshotPath: policySnapshotPath,
            generation: generation,
            accepted: true,
            reloaded: reloaded,
            error: reloadError
        )
        lock.unlock()
        return reloaded
    }

    public func clearPolicy() {
        lock.lock()
        policy = nil
        policySynced = false
        lastError = nil
        lock.unlock()
    }

    public func evaluate(target: NetworkExtensionFlowTarget, now: Date = Date()) -> NetworkExtensionFlowDecision {
        lock.lock()
        let decision: NetworkExtensionFlowDecision
        if let policy, policySynced, policy.enforcementReady {
            decision = policy.decision(for: target, now: now)
        } else {
            decision = failClosedDecision(target: target, now: now, reason: "policy_not_enforcing")
        }
        lock.unlock()
        return decision
    }

    public func markPolicySynced(_ synced: Bool) {
        lock.lock()
        policySynced = synced
        lock.unlock()
    }

    public func markDegraded(reason: String) {
        lock.lock()
        degradedReasons = [reason]
        lastError = reason
        lock.unlock()
    }

    public func recordDroppedVerdict() {
        lock.lock()
        counters.droppedVerdicts += 1
        lock.unlock()
    }

    public func recordFlow(
        target: NetworkExtensionFlowTarget?,
        now: Date = Date()
    ) -> NetworkExtensionFlowDecision {
        reloadWatchedPolicy()

        lock.lock()
        counters.flowsObserved += 1
        let decision: NetworkExtensionFlowDecision
        if let target, let policy, policySynced, policy.enforcementReady {
            decision = policy.decision(for: target, now: now)
            lastHealthyAt = now
        } else {
            let reason = target == nil ? "flow_target_unresolved" : "policy_not_enforcing"
            decision = failClosedDecision(target: target, now: now, reason: reason)
        }
        if case .block = decision {
            counters.flowsBlocked += 1
        }
        lock.unlock()

        return decision
    }

    private func failClosedDecision(
        target: NetworkExtensionFlowTarget?,
        now: Date,
        reason: String
    ) -> NetworkExtensionFlowDecision {
        counters.droppedVerdicts += 1
        degradedReasons = [reason]
        lastError = reason
        return .block(NetworkExtensionEgressRestriction(
            restrictionID: "clawdstrike_fail_closed",
            actionID: "clawdstrike_fail_closed",
            executionID: "clawdstrike_fail_closed",
            target: target.map { "\($0.host):\($0.port)" } ?? "unresolved-flow-target",
            expiresAt: now.addingTimeInterval(60)
        ))
    }

    public func snapshot(
        installState: SystemExtensionInstallState,
        approval: SystemExtensionApproval,
        providerKind: NetworkExtensionProviderKind = .contentFilter,
        backendHint: MediationBackendHint?,
        filterRunning: Bool
    ) -> NetworkExtensionProviderSnapshot {
        lock.lock()
        let inputs = NetworkExtensionProviderInputs(
            installState: installState,
            approval: approval,
            providerKind: providerKind,
            backendHint: backendHint,
            filterRunning: filterRunning,
            policySynced: policySynced,
            enforcementReady: policy?.enforcementReady ?? false,
            degradedReasons: degradedReasons,
            lastHealthyAt: lastHealthyAt,
            counters: counters,
            lastReloadObservation: lastReloadObservation,
            lastError: lastError
        )
        lock.unlock()

        return NetworkExtensionStateProjector.snapshot(from: inputs)
    }

    @discardableResult
    public func persistSnapshot(
        installState: SystemExtensionInstallState,
        approval: SystemExtensionApproval,
        providerKind: NetworkExtensionProviderKind = .contentFilter,
        backendHint: MediationBackendHint?,
        filterRunning: Bool
    ) -> Bool {
        guard let runtimeSnapshotStore else {
            return false
        }
        let currentSnapshot = snapshot(
            installState: installState,
            approval: approval,
            providerKind: providerKind,
            backendHint: backendHint,
            filterRunning: filterRunning
        )
        do {
            try runtimeSnapshotStore.saveSnapshot(currentSnapshot)
            return true
        } catch {
            return false
        }
    }
}

#if canImport(NetworkExtension)
import Network
import NetworkExtension

public final class ClawdStrikeContentFilterDataProvider: NEFilterDataProvider {
    private var installed: SystemExtensionInstallState
    private var approval: SystemExtensionApproval
    private var backendHint: MediationBackendHint?
    private let runtime: NetworkExtensionContentFilterRuntime
    private var running: Bool
    private let vendorConfigurationLock: NSLock
    private var vendorConfigurationHandler: NetworkExtensionProviderVendorConfigurationHandler
    private var filterConfigurationObservation: NSKeyValueObservation?

    public init(
        installState: SystemExtensionInstallState = .installed,
        approval: SystemExtensionApproval = .approved,
        backendHint: MediationBackendHint? = nil,
        policySynced: Bool = false,
        policySnapshotURL: URL? = nil
    ) {
        self.installed = installState
        self.approval = approval
        self.backendHint = backendHint
        let resolvedPolicySnapshotURL = policySnapshotURL
            ?? ClawdStrikeContentFilterDataProvider.defaultPolicySnapshotURL()
        let runtimeSnapshotStore = ClawdStrikeContentFilterDataProvider
            .defaultRuntimeSnapshotStore(policySnapshotURL: resolvedPolicySnapshotURL)
        self.runtime = NetworkExtensionContentFilterRuntime(
            policySynced: policySynced,
            policySnapshotURL: resolvedPolicySnapshotURL,
            runtimeSnapshotStore: runtimeSnapshotStore
        )
        self.running = false
        self.vendorConfigurationLock = NSLock()
        self.vendorConfigurationHandler = NetworkExtensionProviderVendorConfigurationHandler()
        self.filterConfigurationObservation = nil
        super.init()
    }

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        running = true
        installFilterConfigurationObserver()
        applyCurrentVendorConfiguration()
        runtime.reloadWatchedPolicy()
        persistRuntimeSnapshot()
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        filterConfigurationObservation?.invalidate()
        filterConfigurationObservation = nil
        running = false
        runtime.markDegraded(reason: stopReasonString(reason))
        persistRuntimeSnapshot()
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        applyCurrentVendorConfiguration()
        let decision = runtime.recordFlow(target: Self.target(from: flow))
        persistRuntimeSnapshot()
        switch decision {
        case .allow:
            return .allow()
        case .block:
            return .drop()
        }
    }

    public func updatePolicy(_ nextPolicy: NetworkExtensionEgressPolicy) {
        runtime.updatePolicy(nextPolicy)
        persistRuntimeSnapshot()
    }

    public func reloadPolicy(from url: URL) throws {
        try runtime.reloadPolicy(from: url)
        persistRuntimeSnapshot()
    }

    public func watchPolicySnapshot(at url: URL) {
        runtime.watchPolicySnapshot(at: url)
        persistRuntimeSnapshot()
    }

    @discardableResult
    public func requestPolicyReloadFromHostApp() -> Bool {
        let reloaded = runtime.requestPolicyReloadFromHostApp()
        persistRuntimeSnapshot()
        return reloaded
    }

    public func clearPolicy() {
        runtime.clearPolicy()
        persistRuntimeSnapshot()
    }

    public func evaluate(target: NetworkExtensionFlowTarget, now: Date = Date()) -> NetworkExtensionFlowDecision {
        runtime.evaluate(target: target, now: now)
    }

    public func markPolicySynced(_ synced: Bool) {
        runtime.markPolicySynced(synced)
        persistRuntimeSnapshot()
    }

    public func markDegraded(reason: String) {
        runtime.markDegraded(reason: reason)
        persistRuntimeSnapshot()
    }

    public func recordDroppedVerdict() {
        runtime.recordDroppedVerdict()
        persistRuntimeSnapshot()
    }

    public func snapshot() -> NetworkExtensionProviderSnapshot {
        runtime.snapshot(
            installState: installed,
            approval: approval,
            providerKind: .contentFilter,
            backendHint: backendHint,
            filterRunning: running
        )
    }

    private func installFilterConfigurationObserver() {
        guard filterConfigurationObservation == nil else {
            return
        }
        filterConfigurationObservation = observe(
            \.filterConfiguration.vendorConfiguration,
            options: [.new]
        ) { provider, _ in
            provider.applyCurrentVendorConfiguration()
        }
    }

    private func applyCurrentVendorConfiguration() {
        vendorConfigurationLock.lock()
        defer {
            vendorConfigurationLock.unlock()
        }
        do {
            _ = try vendorConfigurationHandler.handleIfChanged(
                filterConfiguration.vendorConfiguration ?? [:],
                runtime: runtime,
                context: providerCommandContext()
            )
            persistRuntimeSnapshot()
        } catch {
            runtime.markDegraded(reason: "vendor_configuration_command_failed")
            persistRuntimeSnapshot()
        }
    }

    private func providerCommandContext() -> NetworkExtensionProviderCommandContext {
        NetworkExtensionProviderCommandContext(
            installState: installed,
            approval: approval,
            backendHint: backendHint,
            filterRunning: running
        )
    }

    private static func defaultPolicySnapshotURL() -> URL? {
        guard let policyPath = ProcessInfo.processInfo
            .environment[NetworkExtensionStatusTool.egressPolicyPathEnvironment],
            !policyPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return nil
        }
        return URL(fileURLWithPath: policyPath)
    }

    private static func defaultRuntimeSnapshotStore(
        policySnapshotURL: URL?
    ) -> NetworkExtensionProviderRuntimeSnapshotStore? {
        if let snapshotPath = ProcessInfo.processInfo
            .environment[NetworkExtensionStatusTool.runtimeSnapshotPathEnvironment],
           !snapshotPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return FileNetworkExtensionProviderRuntimeSnapshotStore(
                snapshotURL: URL(fileURLWithPath: snapshotPath)
            )
        }
        guard let policySnapshotURL else {
            return nil
        }
        return FileNetworkExtensionProviderRuntimeSnapshotStore(
            snapshotURL: NetworkExtensionStatusTool.runtimeSnapshotURL(for: policySnapshotURL)
        )
    }

    private func persistRuntimeSnapshot() {
        runtime.persistSnapshot(
            installState: installed,
            approval: approval,
            providerKind: .contentFilter,
            backendHint: backendHint,
            filterRunning: running
        )
    }

    private static func target(from flow: NEFilterFlow) -> NetworkExtensionFlowTarget? {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return nil
        }

        if #available(macOS 15.0, *),
           let remoteFlowEndpoint = socketFlow.remoteFlowEndpoint {
            return target(from: remoteFlowEndpoint)
        }

        guard let hostEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return nil
        }
        guard let port = Int(hostEndpoint.port) else {
            return nil
        }
        return NetworkExtensionFlowTarget(host: hostEndpoint.hostname, port: port)
    }

    private static func target(from endpoint: Network.NWEndpoint) -> NetworkExtensionFlowTarget? {
        switch endpoint {
        case Network.NWEndpoint.hostPort(let host, let port):
            return NetworkExtensionFlowTarget(host: "\(host)", port: Int(port.rawValue))
        default:
            return nil
        }
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
