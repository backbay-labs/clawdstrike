import EndpointSecurityExtension
import Foundation
import XCTest

final class EndpointSecurityExtensionTests: XCTestCase {
    func testHealthyAllowFixtureMatchesContract() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.healthyAllow)

        XCTAssertEqual(report.fdInjectionEquivalent, false)
        XCTAssertEqual(report.failOpenPossible, true)
        XCTAssertEqual(report.contract, "macos_endpoint_security_auth_contract")
        XCTAssertEqual(report.authorizationModel, "auth_open_point_in_time")
        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .active)
        XCTAssertEqual(report.providerState.availability, .active)
        XCTAssertEqual(report.counters.authOpenAllowCount, 1)
        XCTAssertEqual(report.counters.notifyOpenCount, 1)
        XCTAssertEqual(report.counters.deadlineMissCount, 0)
        XCTAssertTrue(report.evidencePaths.isEmpty)
        try assertFixture(report, named: "healthy-allow")
    }

    func testDenyDecisionFixturePreservesNonFdInjectionSemantics() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.denyDecision)

        XCTAssertEqual(report.fdInjectionEquivalent, false)
        XCTAssertEqual(report.counters.authOpenDenyCount, 1)
        XCTAssertEqual(report.counters.notifyOpenCount, 0)
        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .active)
        try assertFixture(report, named: "deny-decision")
    }

    func testDeadlineMissDegradesHostAndAttestationState() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.deadlineMiss)

        XCTAssertEqual(report.counters.deadlineMissCount, 1)
        XCTAssertTrue(report.degradedReasons.contains("authorization_deadline_missed"))
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertEqual(report.providerState.availability, .degraded)
        XCTAssertTrue(report.evidencePaths.contains(where: { $0.kind == "deadline_miss" }))
        XCTAssertEqual(
            report.hostStatus.endpointSecurity.runtime,
            .degraded(reason: "authorization_deadline_missed")
        )
        try assertFixture(report, named: "deadline-miss")
    }

    func testDroppedEventsCarryEvidencePathAndDegradeProvider() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.droppedEvents)

        XCTAssertEqual(report.counters.droppedEventCount, 3)
        XCTAssertTrue(report.degradedReasons.contains("dropped_enforcement_events"))
        XCTAssertTrue(report.evidencePaths.contains(where: { $0.path.hasSuffix("dropped-events.json") }))
        XCTAssertEqual(report.providerState.availability, .degraded)
        try assertFixture(report, named: "dropped-events")
    }

    func testMissingFullDiskAccessSurfacesDegradedEvidence() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.missingFullDiskAccess)

        XCTAssertTrue(report.degradedReasons.contains("missing_full_disk_access"))
        XCTAssertEqual(report.providerState.availability, .degraded)
        XCTAssertTrue(report.evidencePaths.contains(where: { $0.kind == "missing_full_disk_access" }))
        XCTAssertEqual(
            report.hostStatus.endpointSecurity.runtime,
            .degraded(reason: "missing_full_disk_access")
        )
        try assertFixture(report, named: "missing-full-disk-access")
    }

    func testInactiveProviderStaysInactiveInsteadOfClaimingHealthyEnforcement() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.inactiveProvider)

        XCTAssertEqual(report.providerState.active, false)
        XCTAssertEqual(report.providerState.availability, .inactive)
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertTrue(report.evidencePaths.contains(where: { $0.kind == "inactive_provider" }))
        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .inactive)
        try assertFixture(report, named: "inactive-provider")
    }

    func testApprovalBlockedProviderDoesNotClaimActiveEnforcement() throws {
        let report = EndpointSecurityMonitor.fixtureScenario(.approvalBlocked)

        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .degraded(reason: "system_extension_approval_blocked"))
        XCTAssertEqual(report.providerState.active, false)
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertEqual(report.providerState.availability, .unavailable)
        XCTAssertEqual(report.providerState.approvalStatus, .blocked)
        XCTAssertTrue(report.degradedReasons.contains("system_extension_approval_blocked"))
        XCTAssertTrue(report.evidencePaths.contains(where: { $0.kind == "approval_blocked" }))
        try assertFixture(report, named: "approval-blocked")
    }

    func testProviderIsNotMarkedActiveWhenExtensionIsNotInstalled() {
        let monitor = EndpointSecurityMonitor()
        monitor.setInstallState(.notInstalled)

        let report = monitor.snapshot()

        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .degraded(reason: "system_extension_not_installed"))
        XCTAssertEqual(report.providerState.active, false)
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertEqual(report.providerState.availability, .unavailable)
        XCTAssertTrue(report.degradedReasons.contains("system_extension_not_installed"))
    }

    func testProviderIsNotMarkedActiveWhenStateIsUnknown() {
        let monitor = EndpointSecurityMonitor()

        let report = monitor.snapshot()

        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .unknown)
        XCTAssertEqual(report.providerState.active, false)
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertEqual(report.providerState.availability, .unavailable)
        XCTAssertTrue(report.degradedReasons.contains("provider_state_unknown"))
    }

    func testLiveReportStartsUnknownUntilAHealthyObservationIsRecorded() {
        let report = EndpointSecurityMonitor.liveReport()

        XCTAssertEqual(report.hostStatus.endpointSecurity.runtime, .unknown)
        XCTAssertEqual(report.providerState.active, false)
        XCTAssertEqual(report.providerState.healthy, false)
        XCTAssertEqual(report.providerState.availability, .unavailable)
        XCTAssertTrue(report.degradedReasons.contains("provider_state_unknown"))
    }

    func testAuthorizationPublisherRequestMatchesAgentEndpointContract() throws {
        let event = AuthorizationEvent(
            path: "/tmp/clawdstrike-es-dogfood-test.txt",
            decision: .deny,
            latencyMs: 275,
            deadlineMs: 200,
            notifyObserved: false,
            observedAt: Date(timeIntervalSince1970: 1_778_824_800)
        )
        let context = EndpointSecurityAgentEventContext(
            eventId: "es-auth-open-1",
            hostId: "host-1",
            userId: "user-1",
            sessionId: "session-1",
            process: EndpointSecurityAgentProcess(
                pid: 42,
                ppid: 7,
                processGuid: "proc-1",
                parentProcessGuid: "proc-parent-1",
                image: "/bin/cat",
                commandLine: "cat /tmp/clawdstrike-es-dogfood-test.txt",
                cwd: "/tmp"
            ),
            metadata: ["dogfoodMarker": "clawdstrike-es-dogfood-test"]
        )

        let request = try EndpointSecurityAgentEventEncoder().authorizationOpenRequest(
            event: event,
            context: context
        )
        let encoded = try EndpointSecurityAgentEventEncoder().encode(request)
        let payload = try jsonObject(encoded)
        let events = try XCTUnwrap(payload["events"] as? [[String: Any]])
        let delivered = try XCTUnwrap(events.first)
        let process = try XCTUnwrap(delivered["process"] as? [String: Any])
        let metadata = try XCTUnwrap(delivered["metadata"] as? [String: Any])

        XCTAssertEqual(delivered["eventId"] as? String, "es-auth-open-1")
        XCTAssertEqual(delivered["kind"] as? String, "auth_open")
        XCTAssertEqual(delivered["hostId"] as? String, "host-1")
        XCTAssertEqual(delivered["userId"] as? String, "user-1")
        XCTAssertEqual(delivered["sessionId"] as? String, "session-1")
        XCTAssertEqual(delivered["path"] as? String, "/tmp/clawdstrike-es-dogfood-test.txt")
        XCTAssertEqual(delivered["operation"] as? String, "open")
        XCTAssertEqual(delivered["decision"] as? String, "deny")
        XCTAssertEqual(delivered["deadlineMissed"] as? Bool, true)
        XCTAssertEqual(delivered["deadlineMs"] as? Int, 200)
        XCTAssertTrue((delivered["observedAt"] as? String)?.hasSuffix("Z") == true)
        XCTAssertEqual(process["pid"] as? Int, 42)
        XCTAssertEqual(process["ppid"] as? Int, 7)
        XCTAssertEqual(process["processGuid"] as? String, "proc-1")
        XCTAssertEqual(process["parentProcessGuid"] as? String, "proc-parent-1")
        XCTAssertEqual(process["image"] as? String, "/bin/cat")
        XCTAssertEqual(process["commandLine"] as? String, "cat /tmp/clawdstrike-es-dogfood-test.txt")
        XCTAssertEqual(metadata["collectorKind"] as? String, "endpoint_security")
        XCTAssertEqual(metadata["providerId"] as? String, "macos.endpoint_security")
        XCTAssertEqual(metadata["deliveryPath"] as? String, "endpoint_security_agent_publisher")
        XCTAssertEqual(metadata["dogfoodMarker"] as? String, "clawdstrike-es-dogfood-test")
    }

    func testAuthorizationPublisherRejectsEventsThatCannotReachAgentContract() throws {
        let event = AuthorizationEvent(
            path: "   ",
            decision: .allow,
            latencyMs: 1,
            deadlineMs: 200,
            notifyObserved: true
        )
        let context = EndpointSecurityAgentEventContext(
            process: EndpointSecurityAgentProcess(image: "/bin/cat")
        )

        XCTAssertThrowsError(
            try EndpointSecurityAgentEventEncoder().authorizationOpenRequest(
                event: event,
                context: context
            )
        ) { error in
            XCTAssertEqual(
                error as? EndpointSecurityAgentEventPublisherError,
                .missingAuthorizationPath
            )
        }
    }

    func testPublisherPostsEndpointSecurityEventsWithBearerToken() async throws {
        let transport = CapturingEndpointSecurityTransport()
        let publisher = try EndpointSecurityAgentEventPublisher(
            agentURL: "http://127.0.0.1:9878/",
            bearerToken: "test-token",
            transport: transport
        )
        let event = AuthorizationEvent(
            path: "/tmp/clawdstrike-es-dogfood-test.txt",
            decision: .allow,
            latencyMs: 10,
            deadlineMs: 200,
            notifyObserved: true
        )
        let context = EndpointSecurityAgentEventContext(
            eventId: "es-auth-open-2",
            process: EndpointSecurityAgentProcess(image: "/bin/cat")
        )

        let response = try await publisher.publishAuthorizationOpen(event: event, context: context)

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(
            transport.url?.absoluteString,
            "http://127.0.0.1:9878/api/v1/agent/edr/endpoint-security/events"
        )
        XCTAssertEqual(transport.bearerToken, "test-token")
        let body = try XCTUnwrap(transport.body)
        let payload = try jsonObject(body)
        let events = try XCTUnwrap(payload["events"] as? [[String: Any]])
        XCTAssertEqual(events.first?["eventId"] as? String, "es-auth-open-2")
    }

    func testPublisherPostsEndpointSecurityEventLossForFailOpenRecovery() async throws {
        let transport = CapturingEndpointSecurityTransport()
        let publisher = try EndpointSecurityAgentEventPublisher(
            agentURL: "http://127.0.0.1:9878/",
            bearerToken: "test-token",
            transport: transport
        )

        let response = try await publisher.publishEventLoss(
            reason: "AUTH_OPEN response failed; fail-open recovery issued.",
            droppedEventCount: 1
        )

        XCTAssertEqual(response.statusCode, 200)
        let body = try XCTUnwrap(transport.body)
        let payload = try jsonObject(body)
        let events = try XCTUnwrap(payload["events"] as? [[String: Any]])
        let delivered = try XCTUnwrap(events.first)
        XCTAssertEqual(delivered["kind"] as? String, "event_loss")
        XCTAssertEqual(delivered["reason"] as? String, "AUTH_OPEN response failed; fail-open recovery issued.")
        XCTAssertEqual(delivered["droppedEventCount"] as? Int, 1)
        XCTAssertEqual(delivered["deadlineMissCount"] as? Int, 0)
        XCTAssertEqual(delivered["deadlineMissed"] as? Bool, false)
        let process = try XCTUnwrap(delivered["process"] as? [String: Any])
        XCTAssertEqual(process["image"] as? String, "macos.endpoint_security")
        let metadata = try XCTUnwrap(delivered["metadata"] as? [String: Any])
        XCTAssertEqual(metadata["endpointSecurityEventType"] as? String, "EVENT_LOSS")
    }

    func testPublisherRejectsRelativeAgentURL() {
        XCTAssertThrowsError(
            try EndpointSecurityAgentEventPublisher(
                agentURL: "agent.sock",
                bearerToken: "test-token",
                transport: CapturingEndpointSecurityTransport()
            )
        ) { error in
            XCTAssertEqual(
                error as? EndpointSecurityAgentEventPublisherError,
                .invalidAgentURL("agent.sock")
            )
        }
    }

    func testAuthorizationDecisionUsesEndpointSecurityAuthOpenFlags() {
        XCTAssertEqual(EndpointSecurityAuthorizationDecision.allow.authorizedFlags, UInt32.max)
        XCTAssertEqual(EndpointSecurityAuthorizationDecision.deny.authorizedFlags, 0)
        XCTAssertEqual(EndpointSecurityAuthorizationDecision.allow.eventDecision, .allow)
        XCTAssertEqual(EndpointSecurityAuthorizationDecision.deny.eventDecision, .deny)
    }

    func testAuthorizationRequestProducesDeadlineAwareObservationEvent() throws {
        let observedAt = Date(timeIntervalSince1970: 1_778_824_800)
        let context = EndpointSecurityAgentEventContext(
            eventId: "es-auth-open:101",
            process: EndpointSecurityAgentProcess(
                pid: 501,
                ppid: 1,
                processGuid: "macos:501:9",
                image: "/bin/cat",
                commandLine: "/bin/cat"
            ),
            metadata: [
                "endpointSecurityEventType": "AUTH_OPEN",
                "endpointSecurityRespondApi": "es_respond_flags_result"
            ]
        )
        let request = EndpointSecurityAuthorizationRequest(
            path: "/tmp/clawdstrike-es-auth-open.txt",
            fflag: 1,
            latencyMs: 51,
            deadlineMs: 50,
            observedAt: observedAt,
            context: context
        )

        let event = request.authorizationEvent(decision: .deny)

        XCTAssertEqual(event.eventType, "auth_open")
        XCTAssertEqual(event.path, "/tmp/clawdstrike-es-auth-open.txt")
        XCTAssertEqual(event.decision, .deny)
        XCTAssertEqual(event.latencyMs, 51)
        XCTAssertEqual(event.deadlineMs, 50)
        XCTAssertEqual(event.observedAt, observedAt)
        XCTAssertEqual(event.notifyObserved, false)
        XCTAssertTrue(event.exceededDeadline)
        XCTAssertEqual(request.context.eventId, "es-auth-open:101")
        XCTAssertEqual(request.context.metadata["endpointSecurityRespondApi"], "es_respond_flags_result")
    }

    func testStatusToolRejectsUnsupportedScenarioInsteadOfFallingBackToHealthy() {
        XCTAssertThrowsError(
            try EndpointSecurityFixtureScenario.resolve(commandLineArgument: "definitely-not-real")
        ) { error in
            XCTAssertEqual(
                error as? StatusToolScenarioError,
                .unsupportedScenario("definitely-not-real")
            )
        }
    }

    func testStatusToolRejectsMissingFixtureScenario() {
        XCTAssertThrowsError(
            try EndpointSecurityFixtureScenario.resolve(commandLineArgument: nil)
        ) { error in
            XCTAssertEqual(error as? StatusToolScenarioError, .missingScenario)
        }
    }

    func testAgentTokenCandidatesPreferPlatformConfigPathWithLegacyFallback() {
        let homeDirectory = URL(fileURLWithPath: "/Users/tester", isDirectory: true)

        let candidates = ClawdStrikeAgentConfigPaths.agentTokenCandidates(
            homeDirectory: homeDirectory
        )

        XCTAssertEqual(
            candidates,
            [
                "/Users/tester/Library/Application Support/clawdstrike/agent-local-token",
                "/Users/tester/.config/clawdstrike/agent-local-token",
            ]
        )
    }

    func testAgentTokenCandidatesUseExplicitPathOnly() {
        let candidates = ClawdStrikeAgentConfigPaths.agentTokenCandidates(
            explicitPath: "/tmp/clawdstrike-token",
            homeDirectory: URL(fileURLWithPath: "/Users/tester", isDirectory: true)
        )

        XCTAssertEqual(candidates, ["/tmp/clawdstrike-token"])
    }

    private func assertFixture(_ report: EndpointSecurityStatusReport, named name: String) throws {
        let fixtureURL = fixturesRoot().appendingPathComponent("status/\(name).json")
        let expected = try Data(contentsOf: fixtureURL)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let actual = try encoder.encode(report)
        let expectedObject = try JSONSerialization.jsonObject(with: expected)
        let actualObject = try JSONSerialization.jsonObject(with: actual)
        XCTAssertEqual(
            expectedObject as? NSDictionary,
            actualObject as? NSDictionary
        )
    }

    private func fixturesRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/macos/endpoint-security", isDirectory: true)
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}

private final class CapturingEndpointSecurityTransport: EndpointSecurityAgentEventTransport {
    var body: Data?
    var url: URL?
    var bearerToken: String?
    var response = EndpointSecurityAgentPublishResponse(statusCode: 200, body: Data("{}".utf8))

    func postEndpointSecurityEvents(
        _ body: Data,
        to url: URL,
        bearerToken: String
    ) async throws -> EndpointSecurityAgentPublishResponse {
        self.body = body
        self.url = url
        self.bearerToken = bearerToken
        return response
    }
}
