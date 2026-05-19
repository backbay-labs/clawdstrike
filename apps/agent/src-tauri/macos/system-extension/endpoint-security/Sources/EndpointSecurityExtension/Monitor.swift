import Foundation
import Darwin
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(EndpointSecurity)
import EndpointSecurity
#endif

public final class EndpointSecurityMonitor {
    public static let endpointSecurityProvider = "endpoint_security"
    public static let authorizationContract = "macos_endpoint_security_auth_contract"
    public static let authorizationModel = "auth_open_point_in_time"

    private let stateLock = NSLock()
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
        withLockedState {
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
                recordHealthyObservationLocked(at: event.observedAt ?? Date())
            }
        }
    }

    public func recordDroppedEvents(
        count: UInt64,
        evidencePath: String,
        detail: String = "EndpointSecurity reported dropped enforcement events."
    ) {
        withLockedState {
            counters.droppedEventCount += count
            addEvidenceLocked(kind: "dropped_events", path: evidencePath, detail: detail)
        }
    }

    public func setFullDiskAccessGranted(
        _ granted: Bool,
        evidencePath: String? = nil,
        detail: String = "Full Disk Access is missing for the EndpointSecurity host."
    ) {
        withLockedState {
            fullDiskAccessGranted = granted
            if !granted {
                if let evidencePath {
                    addEvidenceLocked(kind: "missing_full_disk_access", path: evidencePath, detail: detail)
                }
            }
        }
    }

    public func setProviderActive(
        _ active: Bool,
        evidencePath: String? = nil,
        detail: String = "EndpointSecurity provider is installed but inactive."
    ) {
        withLockedState {
            providerActive = active
            if !active {
                if let evidencePath {
                    addEvidenceLocked(kind: "inactive_provider", path: evidencePath, detail: detail)
                }
            }
        }
    }

    public func setInstallState(_ state: SystemExtensionInstallState) {
        withLockedState {
            installState = state
        }
    }

    public func setApproval(
        _ value: SystemExtensionApproval,
        evidencePath: String? = nil,
        detail: String = "System extension approval is blocked or missing."
    ) {
        withLockedState {
            approval = value
            if value == .approvalBlocked {
                if let evidencePath {
                    addEvidenceLocked(kind: "approval_blocked", path: evidencePath, detail: detail)
                }
            }
        }
    }

    public func snapshot() -> EndpointSecurityStatusReport {
        withLockedState {
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

    private func withLockedState<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }

    private func recordHealthyObservationLocked(at date: Date) {
        lastHealthyTimestamp = ISO8601DateFormatter().string(from: date)
    }

    private func addEvidence(kind: String, path: String, detail: String) {
        withLockedState {
            addEvidenceLocked(kind: kind, path: path, detail: detail)
        }
    }

    private func addEvidenceLocked(kind: String, path: String, detail: String) {
        let artifact = EvidenceArtifact(kind: kind, path: path, detail: detail)
        if !evidencePaths.contains(artifact) {
            evidencePaths.append(artifact)
        }
    }
}

public enum EndpointSecurityAgentEventPublisherError: Error, LocalizedError, Equatable {
    case emptyAgentURL
    case invalidAgentURL(String)
    case missingBearerToken
    case missingAuthorizationPath
    case missingProcessIdentity
    case nonHTTPResponse
    case rejected(statusCode: Int, body: String)

    public var errorDescription: String? {
        switch self {
        case .emptyAgentURL:
            return "agent URL is empty"
        case .invalidAgentURL(let url):
            return "invalid agent URL: \(url)"
        case .missingBearerToken:
            return "missing agent bearer token"
        case .missingAuthorizationPath:
            return "EndpointSecurity authorization event path is empty"
        case .missingProcessIdentity:
            return "EndpointSecurity event must include a process image or command line"
        case .nonHTTPResponse:
            return "agent response was not HTTP"
        case .rejected(let statusCode, let body):
            return "agent rejected EndpointSecurity event delivery with HTTP \(statusCode): \(body)"
        }
    }
}

public struct EndpointSecurityAgentProcess: Codable, Equatable {
    public var pid: UInt32?
    public var ppid: UInt32?
    public var processGuid: String?
    public var parentProcessGuid: String?
    public var image: String?
    public var commandLine: String?
    public var cwd: String?

    public init(
        pid: UInt32? = nil,
        ppid: UInt32? = nil,
        processGuid: String? = nil,
        parentProcessGuid: String? = nil,
        image: String? = nil,
        commandLine: String? = nil,
        cwd: String? = nil
    ) {
        self.pid = pid
        self.ppid = ppid
        self.processGuid = processGuid
        self.parentProcessGuid = parentProcessGuid
        self.image = image
        self.commandLine = commandLine
        self.cwd = cwd
    }

    var hasIdentity: Bool {
        !(image?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            || !(commandLine?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
    }
}

public struct EndpointSecurityAgentEventContext: Equatable {
    public var eventId: String?
    public var hostId: String?
    public var userId: String?
    public var sessionId: String?
    public var process: EndpointSecurityAgentProcess
    public var metadata: [String: String]

    public init(
        eventId: String? = nil,
        hostId: String? = nil,
        userId: String? = nil,
        sessionId: String? = nil,
        process: EndpointSecurityAgentProcess,
        metadata: [String: String] = [:]
    ) {
        self.eventId = eventId
        self.hostId = hostId
        self.userId = userId
        self.sessionId = sessionId
        self.process = process
        self.metadata = metadata
    }
}

public struct EndpointSecurityAgentEventsRequest: Codable, Equatable {
    public var events: [EndpointSecurityAgentEvent]

    public init(events: [EndpointSecurityAgentEvent]) {
        self.events = events
    }
}

public struct EndpointSecurityAgentEvent: Codable, Equatable {
    public var eventId: String?
    public var kind: String
    public var observedAt: String?
    public var hostId: String?
    public var userId: String?
    public var sessionId: String?
    public var process: EndpointSecurityAgentProcess?
    public var path: String?
    public var operation: String?
    public var decision: String?
    public var reason: String?
    public var deadlineMissed: Bool?
    public var deadlineMs: UInt64?
    public var droppedEventCount: UInt64?
    public var deadlineMissCount: UInt64?
    public var metadata: [String: String]

    public init(
        eventId: String? = nil,
        kind: String,
        observedAt: String? = nil,
        hostId: String? = nil,
        userId: String? = nil,
        sessionId: String? = nil,
        process: EndpointSecurityAgentProcess? = nil,
        path: String? = nil,
        operation: String? = nil,
        decision: String? = nil,
        reason: String? = nil,
        deadlineMissed: Bool? = nil,
        deadlineMs: UInt64? = nil,
        droppedEventCount: UInt64? = nil,
        deadlineMissCount: UInt64? = nil,
        metadata: [String: String] = [:]
    ) {
        self.eventId = eventId
        self.kind = kind
        self.observedAt = observedAt
        self.hostId = hostId
        self.userId = userId
        self.sessionId = sessionId
        self.process = process
        self.path = path
        self.operation = operation
        self.decision = decision
        self.reason = reason
        self.deadlineMissed = deadlineMissed
        self.deadlineMs = deadlineMs
        self.droppedEventCount = droppedEventCount
        self.deadlineMissCount = deadlineMissCount
        self.metadata = metadata
    }
}

public struct EndpointSecurityAgentPublishResponse: Equatable {
    public var statusCode: Int
    public var body: Data

    public init(statusCode: Int, body: Data = Data()) {
        self.statusCode = statusCode
        self.body = body
    }
}

public protocol EndpointSecurityAgentEventTransport {
    func postEndpointSecurityEvents(
        _ body: Data,
        to url: URL,
        bearerToken: String
    ) async throws -> EndpointSecurityAgentPublishResponse
}

public struct URLSessionEndpointSecurityAgentEventTransport: EndpointSecurityAgentEventTransport {
    public init() {}

    public func postEndpointSecurityEvents(
        _ body: Data,
        to url: URL,
        bearerToken: String
    ) async throws -> EndpointSecurityAgentPublishResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw EndpointSecurityAgentEventPublisherError.nonHTTPResponse
        }
        return EndpointSecurityAgentPublishResponse(statusCode: http.statusCode, body: data)
    }
}

public struct EndpointSecurityAgentEventEncoder {
    public init() {}

    private static func iso8601String(from date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    public func authorizationOpenRequest(
        event: AuthorizationEvent,
        context: EndpointSecurityAgentEventContext
    ) throws -> EndpointSecurityAgentEventsRequest {
        let path = event.path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else {
            throw EndpointSecurityAgentEventPublisherError.missingAuthorizationPath
        }
        guard context.process.hasIdentity else {
            throw EndpointSecurityAgentEventPublisherError.missingProcessIdentity
        }

        var metadata = context.metadata
        metadata["collectorKind"] = "endpoint_security"
        metadata["providerId"] = "macos.endpoint_security"
        metadata["deliveryPath"] = "endpoint_security_agent_publisher"

        let delivered = EndpointSecurityAgentEvent(
            eventId: context.eventId,
            kind: event.eventType,
            observedAt: event.observedAt.map(Self.iso8601String),
            hostId: context.hostId,
            userId: context.userId,
            sessionId: context.sessionId,
            process: context.process,
            path: path,
            operation: "open",
            decision: event.decision.rawValue,
            reason: nil,
            deadlineMissed: event.exceededDeadline,
            deadlineMs: event.deadlineMs,
            metadata: metadata
        )
        return EndpointSecurityAgentEventsRequest(events: [delivered])
    }

    public func eventLossRequest(
        reason: String,
        droppedEventCount: UInt64,
        deadlineMissCount: UInt64 = 0,
        observedAt: Date = Date()
    ) -> EndpointSecurityAgentEventsRequest {
        let metadata = [
            "collectorKind": "endpoint_security",
            "providerId": "macos.endpoint_security",
            "deliveryPath": "endpoint_security_agent_publisher",
            "endpointSecurityEventType": "EVENT_LOSS"
        ]
        let delivered = EndpointSecurityAgentEvent(
            kind: "event_loss",
            observedAt: Self.iso8601String(from: observedAt),
            process: EndpointSecurityAgentProcess(
                image: "macos.endpoint_security",
                commandLine: "endpoint_security event_loss"
            ),
            reason: reason,
            deadlineMissed: deadlineMissCount > 0,
            droppedEventCount: droppedEventCount,
            deadlineMissCount: deadlineMissCount,
            metadata: metadata
        )
        return EndpointSecurityAgentEventsRequest(events: [delivered])
    }

    public func encode(_ request: EndpointSecurityAgentEventsRequest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(request)
    }
}

public struct EndpointSecurityAgentEventPublisher<Transport: EndpointSecurityAgentEventTransport> {
    private let agentURL: URL
    private let bearerToken: String
    private let transport: Transport
    private let encoder: EndpointSecurityAgentEventEncoder

    public init(
        agentURL: String,
        bearerToken: String,
        transport: Transport,
        encoder: EndpointSecurityAgentEventEncoder = EndpointSecurityAgentEventEncoder()
    ) throws {
        let trimmedURL = agentURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedURL.isEmpty else {
            throw EndpointSecurityAgentEventPublisherError.emptyAgentURL
        }
        guard let parsedURL = URL(string: trimmedURL) else {
            throw EndpointSecurityAgentEventPublisherError.invalidAgentURL(agentURL)
        }
        guard let scheme = parsedURL.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              parsedURL.host != nil
        else {
            throw EndpointSecurityAgentEventPublisherError.invalidAgentURL(agentURL)
        }
        let trimmedToken = bearerToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedToken.isEmpty else {
            throw EndpointSecurityAgentEventPublisherError.missingBearerToken
        }

        self.agentURL = parsedURL
        self.bearerToken = trimmedToken
        self.transport = transport
        self.encoder = encoder
    }

    public func publishAuthorizationOpen(
        event: AuthorizationEvent,
        context: EndpointSecurityAgentEventContext
    ) async throws -> EndpointSecurityAgentPublishResponse {
        let request = try encoder.authorizationOpenRequest(event: event, context: context)
        let body = try encoder.encode(request)
        let response = try await transport.postEndpointSecurityEvents(
            body,
            to: endpointSecurityEventsURL(),
            bearerToken: bearerToken
        )
        guard (200 ..< 300).contains(response.statusCode) else {
            let bodyText = String(data: response.body, encoding: .utf8) ?? ""
            throw EndpointSecurityAgentEventPublisherError.rejected(
                statusCode: response.statusCode,
                body: bodyText
            )
        }
        return response
    }

    public func publishEventLoss(
        reason: String,
        droppedEventCount: UInt64,
        deadlineMissCount: UInt64 = 0
    ) async throws -> EndpointSecurityAgentPublishResponse {
        let request = encoder.eventLossRequest(
            reason: reason,
            droppedEventCount: droppedEventCount,
            deadlineMissCount: deadlineMissCount
        )
        let body = try encoder.encode(request)
        let response = try await transport.postEndpointSecurityEvents(
            body,
            to: endpointSecurityEventsURL(),
            bearerToken: bearerToken
        )
        guard (200 ..< 300).contains(response.statusCode) else {
            let bodyText = String(data: response.body, encoding: .utf8) ?? ""
            throw EndpointSecurityAgentEventPublisherError.rejected(
                statusCode: response.statusCode,
                body: bodyText
            )
        }
        return response
    }

    public func endpointSecurityEventsURL() -> URL {
        var base = agentURL.absoluteString
        while base.hasSuffix("/") {
            base.removeLast()
        }
        return URL(string: "\(base)/api/v1/agent/edr/endpoint-security/events")!
    }
}

public enum EndpointSecurityAuthorizationDecision: Equatable {
    case allow
    case deny

    public var eventDecision: AuthorizationDecision {
        switch self {
        case .allow:
            return .allow
        case .deny:
            return .deny
        }
    }

    public var authorizedFlags: UInt32 {
        switch self {
        case .allow:
            return UInt32.max
        case .deny:
            return 0
        }
    }
}

public struct EndpointSecurityAuthorizationRequest: Equatable {
    public var path: String
    public var fflag: Int32
    public var latencyMs: UInt64
    public var deadlineMs: UInt64
    public var observedAt: Date?
    public var context: EndpointSecurityAgentEventContext

    public init(
        path: String,
        fflag: Int32,
        latencyMs: UInt64,
        deadlineMs: UInt64,
        observedAt: Date? = nil,
        context: EndpointSecurityAgentEventContext
    ) {
        self.path = path
        self.fflag = fflag
        self.latencyMs = latencyMs
        self.deadlineMs = deadlineMs
        self.observedAt = observedAt
        self.context = context
    }

    public func authorizationEvent(decision: EndpointSecurityAuthorizationDecision) -> AuthorizationEvent {
        AuthorizationEvent(
            path: path,
            decision: decision.eventDecision,
            latencyMs: latencyMs,
            deadlineMs: deadlineMs,
            notifyObserved: false,
            observedAt: observedAt
        )
    }
}

public enum EndpointSecurityRuntimeClientError: Error, LocalizedError, Equatable {
    case endpointSecurityUnavailable
    case clientCreationFailed(String)
    case clientMissingAfterCreation
    case subscriptionFailed(String)
    case deletionFailed(String)
    case unsupportedEventType(String)
    case missingOpenPath
    case missingProcessExecutable
    case responseFailed(String)

    public var errorDescription: String? {
        switch self {
        case .endpointSecurityUnavailable:
            return "EndpointSecurity framework is unavailable"
        case .clientCreationFailed(let result):
            return "EndpointSecurity client creation failed: \(result)"
        case .clientMissingAfterCreation:
            return "EndpointSecurity did not return a client after successful creation"
        case .subscriptionFailed(let result):
            return "EndpointSecurity AUTH_OPEN subscription failed: \(result)"
        case .deletionFailed(let result):
            return "EndpointSecurity client deletion failed: \(result)"
        case .unsupportedEventType(let eventType):
            return "unsupported EndpointSecurity event type: \(eventType)"
        case .missingOpenPath:
            return "EndpointSecurity AUTH_OPEN message did not include a file path"
        case .missingProcessExecutable:
            return "EndpointSecurity AUTH_OPEN message did not include a process executable path"
        case .responseFailed(let result):
            return "EndpointSecurity AUTH_OPEN response failed: \(result)"
        }
    }
}

#if canImport(EndpointSecurity)
public struct EndpointSecurityAuthOpenMessageAdapter {
    private let hostId: String?
    private let userId: String?
    private let sessionId: String?

    public init(hostId: String? = nil, userId: String? = nil, sessionId: String? = nil) {
        self.hostId = hostId
        self.userId = userId
        self.sessionId = sessionId
    }

    public func authorizationRequest(
        from message: UnsafePointer<es_message_t>
    ) throws -> EndpointSecurityAuthorizationRequest {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN else {
            throw EndpointSecurityRuntimeClientError.unsupportedEventType(
                endpointSecurityEventTypeName(message.pointee.event_type)
            )
        }

        let open = message.pointee.event.open
        guard let path = endpointSecurityString(open.file.pointee.path) else {
            throw EndpointSecurityRuntimeClientError.missingOpenPath
        }

        let process = message.pointee.process.pointee
        guard let image = endpointSecurityString(process.executable.pointee.path) else {
            throw EndpointSecurityRuntimeClientError.missingProcessExecutable
        }

        let pid = audit_token_to_pid(process.audit_token)
        let pidVersion = audit_token_to_pidversion(process.audit_token)
        let processGuid = pid > 0 && pidVersion >= 0 ? "macos:\(pid):\(pidVersion)" : nil
        let parentGuid = parentProcessGuid(for: process, messageVersion: message.pointee.version)
        let latencyMs = Self.machDeltaMilliseconds(from: message.pointee.mach_time, to: mach_absolute_time())
        let deadlineMs = Self.machDeltaMilliseconds(from: message.pointee.mach_time, to: message.pointee.deadline)
        let observedAt = Date(
            timeIntervalSince1970: TimeInterval(message.pointee.time.tv_sec)
                + TimeInterval(message.pointee.time.tv_nsec) / 1_000_000_000
        )

        var metadata: [String: String] = [
            "endpointSecurityEventType": "AUTH_OPEN",
            "endpointSecurityFflag": String(open.fflag),
            "endpointSecurityMessageVersion": String(message.pointee.version),
            "endpointSecurityRespondApi": "es_respond_flags_result",
            "authorizationBoundary": "point_in_time_snapshot"
        ]
        if message.pointee.version >= 2 {
            metadata["endpointSecuritySeqNum"] = String(message.pointee.seq_num)
        }
        if message.pointee.version >= 4 {
            metadata["endpointSecurityGlobalSeqNum"] = String(message.pointee.global_seq_num)
        }

        let context = EndpointSecurityAgentEventContext(
            eventId: endpointSecurityEventId(for: message.pointee),
            hostId: hostId,
            userId: userId,
            sessionId: sessionId,
            process: EndpointSecurityAgentProcess(
                pid: positiveUInt32(pid),
                ppid: positiveUInt32(process.ppid),
                processGuid: processGuid,
                parentProcessGuid: parentGuid,
                image: image,
                commandLine: image
            ),
            metadata: metadata
        )

        return EndpointSecurityAuthorizationRequest(
            path: path,
            fflag: open.fflag,
            latencyMs: latencyMs,
            deadlineMs: deadlineMs,
            observedAt: observedAt,
            context: context
        )
    }

    public func respondAuthorizationOpen(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        decision: EndpointSecurityAuthorizationDecision
    ) throws {
        let result = es_respond_flags_result(client, message, decision.authorizedFlags, false)
        guard result == ES_RESPOND_RESULT_SUCCESS else {
            throw EndpointSecurityRuntimeClientError.responseFailed(endpointSecurityRespondResultName(result))
        }
    }

    private static func machDeltaMilliseconds(from start: UInt64, to end: UInt64) -> UInt64 {
        guard end > start else {
            return 0
        }
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        let nanos = Double(end - start) * Double(info.numer) / Double(info.denom)
        return UInt64(nanos / 1_000_000)
    }
}

@available(macOS 10.15, *)
public final class EndpointSecurityAuthOpenRuntime<Transport: EndpointSecurityAgentEventTransport> {
    public typealias DecisionHandler = (EndpointSecurityAuthorizationRequest) -> EndpointSecurityAuthorizationDecision
    public typealias PublishErrorHandler = (Error) -> Void

    private let monitor: EndpointSecurityMonitor
    private let publisher: EndpointSecurityAgentEventPublisher<Transport>
    private let adapter: EndpointSecurityAuthOpenMessageAdapter
    private let decisionHandler: DecisionHandler
    private let publishErrorHandler: PublishErrorHandler?
    private var client: OpaquePointer?

    public init(
        monitor: EndpointSecurityMonitor,
        publisher: EndpointSecurityAgentEventPublisher<Transport>,
        adapter: EndpointSecurityAuthOpenMessageAdapter = EndpointSecurityAuthOpenMessageAdapter(),
        decisionHandler: @escaping DecisionHandler = { _ in .allow },
        publishErrorHandler: PublishErrorHandler? = nil
    ) {
        self.monitor = monitor
        self.publisher = publisher
        self.adapter = adapter
        self.decisionHandler = decisionHandler
        self.publishErrorHandler = publishErrorHandler
    }

    public func start() throws {
        guard client == nil else {
            return
        }

        var createdClient: OpaquePointer?
        let monitor = monitor
        let createResult = es_new_client(&createdClient) { [weak self, monitor] client, message in
            guard let self else {
                _ = Self.issueFailOpenAuthOpenResponse(
                    client: client,
                    message: message,
                    monitor: monitor,
                    detail: "EndpointSecurity runtime was deallocated before AUTH_OPEN handling; fail-open response issued to meet the kernel deadline."
                )
                return
            }
            self.handleAuthorizationMessage(client: client, message: message)
        }
        guard createResult == ES_NEW_CLIENT_RESULT_SUCCESS else {
            recordClientCreationFailure(createResult)
            throw EndpointSecurityRuntimeClientError.clientCreationFailed(
                endpointSecurityNewClientResultName(createResult)
            )
        }
        guard let createdClient else {
            throw EndpointSecurityRuntimeClientError.clientMissingAfterCreation
        }

        let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_OPEN]
        let subscribeResult = events.withUnsafeBufferPointer { buffer in
            es_subscribe(createdClient, buffer.baseAddress!, UInt32(buffer.count))
        }
        guard subscribeResult == ES_RETURN_SUCCESS else {
            _ = es_delete_client(createdClient)
            monitor.setProviderActive(
                false,
                evidencePath: "endpoint-security-runtime",
                detail: "EndpointSecurity AUTH_OPEN subscription failed: \(endpointSecurityReturnName(subscribeResult))"
            )
            throw EndpointSecurityRuntimeClientError.subscriptionFailed(
                endpointSecurityReturnName(subscribeResult)
            )
        }

        client = createdClient
        monitor.setInstallState(.installed)
        monitor.setApproval(.approved)
        monitor.setProviderActive(true)
    }

    deinit {
        if let activeClient = client {
            _ = es_delete_client(activeClient)
        }
        client = nil
    }

    public func stop() throws {
        guard let activeClient = client else {
            return
        }
        let result = es_delete_client(activeClient)
        guard result == ES_RETURN_SUCCESS else {
            throw EndpointSecurityRuntimeClientError.deletionFailed(endpointSecurityReturnName(result))
        }
        client = nil
    }

    private func handleAuthorizationMessage(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>
    ) {
        var responseAttempted = false
        do {
            let request = try adapter.authorizationRequest(from: message)
            let decision = decisionHandler(request)
            try adapter.respondAuthorizationOpen(client: client, message: message, decision: decision)
            responseAttempted = true
            let event = request.authorizationEvent(decision: decision)
            monitor.recordAuthorization(event)

            Task {
                do {
                    _ = try await publisher.publishAuthorizationOpen(event: event, context: request.context)
                } catch {
                    publishErrorHandler?(error)
                }
            }
        } catch {
            if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN && !responseAttempted {
                if let responseDetail = Self.issueFailOpenAuthOpenResponse(
                    client: client,
                    message: message,
                    monitor: monitor,
                    detail: "EndpointSecurity AUTH_OPEN message could not be mapped or answered; fail-open response issued to meet the kernel deadline."
                ) {
                    Task {
                        do {
                            _ = try await publisher.publishEventLoss(
                                reason: "\(error.localizedDescription) \(responseDetail)",
                                droppedEventCount: 1
                            )
                        } catch {
                            publishErrorHandler?(error)
                        }
                    }
                }
            }
            publishErrorHandler?(error)
        }
    }

    private static func issueFailOpenAuthOpenResponse(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        monitor: EndpointSecurityMonitor,
        detail: String
    ) -> String? {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN else {
            return nil
        }

        let result = es_respond_flags_result(client, message, UInt32.max, false)
        let responseDetail: String
        if result == ES_RESPOND_RESULT_SUCCESS {
            responseDetail = detail
        } else {
            responseDetail = "\(detail) Fail-open response result: \(endpointSecurityRespondResultName(result))."
        }
        monitor.recordDroppedEvents(
            count: 1,
            evidencePath: "endpoint-security-runtime",
            detail: responseDetail
        )
        return responseDetail
    }

    private func recordClientCreationFailure(_ result: es_new_client_result_t) {
        monitor.setProviderActive(
            false,
            evidencePath: "endpoint-security-runtime",
            detail: "EndpointSecurity client creation failed: \(endpointSecurityNewClientResultName(result))"
        )
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            monitor.setInstallState(.installed)
            monitor.setApproval(.approved)
            monitor.setFullDiskAccessGranted(
                false,
                evidencePath: "endpoint-security-runtime",
                detail: "EndpointSecurity client creation failed because Full Disk Access is missing."
            )
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED, ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            monitor.setInstallState(.installed)
            monitor.setApproval(
                .approvalBlocked,
                evidencePath: "endpoint-security-runtime",
                detail: "EndpointSecurity client creation failed before authorization could start: \(endpointSecurityNewClientResultName(result))"
            )
        default:
            break
        }
    }
}

private func endpointSecurityString(_ token: es_string_token_t) -> String? {
    guard token.length > 0, let data = token.data else {
        return nil
    }
    let bytes = UnsafeBufferPointer(start: data, count: token.length).map { UInt8(bitPattern: $0) }
    return String(bytes: bytes, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .nilIfEmpty
}

private func endpointSecurityEventId(for message: es_message_t) -> String? {
    if message.version >= 4 {
        return "es-auth-open:\(message.global_seq_num)"
    }
    if message.version >= 2 {
        return "es-auth-open:\(message.seq_num)"
    }
    return nil
}

private func parentProcessGuid(for process: es_process_t, messageVersion: UInt32) -> String? {
    guard messageVersion >= 4 else {
        return nil
    }
    let parentPid = audit_token_to_pid(process.parent_audit_token)
    let parentPidVersion = audit_token_to_pidversion(process.parent_audit_token)
    guard parentPid > 0, parentPidVersion >= 0 else {
        return nil
    }
    return "macos:\(parentPid):\(parentPidVersion)"
}

private func positiveUInt32(_ value: pid_t) -> UInt32? {
    guard value > 0 else {
        return nil
    }
    return UInt32(value)
}

private func endpointSecurityEventTypeName(_ eventType: es_event_type_t) -> String {
    switch eventType {
    case ES_EVENT_TYPE_AUTH_OPEN:
        return "ES_EVENT_TYPE_AUTH_OPEN"
    default:
        return "es_event_type_t(\(eventType.rawValue))"
    }
}

private func endpointSecurityNewClientResultName(_ result: es_new_client_result_t) -> String {
    switch result {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        return "ES_NEW_CLIENT_RESULT_SUCCESS"
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
        return "ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT"
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
        return "ES_NEW_CLIENT_RESULT_ERR_INTERNAL"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        return "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        return "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        return "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        return "ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS"
    default:
        return "es_new_client_result_t(\(result.rawValue))"
    }
}

private func endpointSecurityReturnName(_ result: es_return_t) -> String {
    switch result {
    case ES_RETURN_SUCCESS:
        return "ES_RETURN_SUCCESS"
    case ES_RETURN_ERROR:
        return "ES_RETURN_ERROR"
    default:
        return "es_return_t(\(result.rawValue))"
    }
}

private func endpointSecurityRespondResultName(_ result: es_respond_result_t) -> String {
    switch result {
    case ES_RESPOND_RESULT_SUCCESS:
        return "ES_RESPOND_RESULT_SUCCESS"
    case ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT:
        return "ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT"
    case ES_RESPOND_RESULT_ERR_INTERNAL:
        return "ES_RESPOND_RESULT_ERR_INTERNAL"
    case ES_RESPOND_RESULT_NOT_FOUND:
        return "ES_RESPOND_RESULT_NOT_FOUND"
    case ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE:
        return "ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE"
    case ES_RESPOND_RESULT_ERR_EVENT_TYPE:
        return "ES_RESPOND_RESULT_ERR_EVENT_TYPE"
    default:
        return "es_respond_result_t(\(result.rawValue))"
    }
}
#endif

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
