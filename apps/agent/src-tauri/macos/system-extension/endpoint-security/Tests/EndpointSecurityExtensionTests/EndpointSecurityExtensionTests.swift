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
}
