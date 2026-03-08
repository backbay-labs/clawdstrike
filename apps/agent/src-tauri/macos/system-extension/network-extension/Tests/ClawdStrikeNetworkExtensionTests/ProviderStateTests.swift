import Foundation
import XCTest

@testable import ClawdStrikeNetworkExtension

final class ProviderStateTests: XCTestCase {
    func testProviderSelectionStaysOnContentFilterBaselineAndKeepsLegacyBackendHint() throws {
        let evidence = try NetworkExtensionStateProjector.requireContentFilterBaseline(
            requestedProvider: .contentFilter,
            backendHint: .legacyProxyOnlyRuntime
        )

        XCTAssertEqual(evidence.requestedProvider, .contentFilter)
        XCTAssertEqual(evidence.effectiveProvider, .contentFilter)
        XCTAssertEqual(evidence.backendHint, .legacyProxyOnlyRuntime)
        XCTAssertFalse(evidence.exceptionRequired)
    }

    func testTransparentProxySelectionRequiresExplicitException() {
        XCTAssertThrowsError(
            try NetworkExtensionStateProjector.requireContentFilterBaseline(
                requestedProvider: .transparentProxy,
                backendHint: .legacyProxyOnlyRuntime
            )
        ) { error in
            XCTAssertEqual(
                error as? ProviderSelectionError,
                .transparentProxyExceptionRequired
            )
        }
    }

    func testUnavailableProviderProducesHostAndAttestationEvidence() {
        let snapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: false,
                policySynced: false
            )
        )

        XCTAssertEqual(snapshot.providerKind, .contentFilter)
        XCTAssertEqual(snapshot.backendHint, .legacyProxyOnlyRuntime)
        XCTAssertEqual(snapshot.selectionEvidence.effectiveProvider, .contentFilter)
        XCTAssertEqual(snapshot.hostStatus.runtime, .inactive)
        XCTAssertEqual(snapshot.attestationState.availability, .inactive)
        XCTAssertEqual(snapshot.attestationState.degradedReasons, ["provider_inactive"])
    }

    func testApprovalBlockedProviderReportsUnavailableWithoutClaimingActiveEnforcement() {
        let snapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approvalBlocked,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: false,
                policySynced: false
            )
        )

        XCTAssertEqual(snapshot.hostStatus.runtime, .degraded(reason: "approval_blocked"))
        XCTAssertEqual(snapshot.attestationState.active, false)
        XCTAssertEqual(snapshot.attestationState.healthy, false)
        XCTAssertEqual(snapshot.attestationState.availability, .unavailable)
        XCTAssertEqual(snapshot.attestationState.degradedReasons, ["approval_blocked"])
        XCTAssertEqual(snapshot.attestationState.approvalStatus, .blocked)
    }

    func testPolicySyncGapIsReportedAsDegradedWithoutRenamingBackendHint() {
        let snapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: true,
                policySynced: false,
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

        XCTAssertEqual(snapshot.hostStatus.runtime, .degraded(reason: "policy_not_synced"))
        XCTAssertEqual(snapshot.attestationState.availability, .degraded)
        XCTAssertEqual(snapshot.attestationState.degradedReasons, ["policy_not_synced"])
        XCTAssertEqual(snapshot.backendHint, .legacyProxyOnlyRuntime)
    }

    func testRunningSyncedAllowAllProviderStaysDegradedUntilItCanActuallyEnforce() {
        let snapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: true,
                policySynced: true
            )
        )

        XCTAssertEqual(snapshot.hostStatus.runtime, .degraded(reason: "non_enforcing_provider"))
        XCTAssertEqual(snapshot.attestationState.active, true)
        XCTAssertEqual(snapshot.attestationState.healthy, false)
        XCTAssertEqual(snapshot.attestationState.availability, .degraded)
        XCTAssertEqual(snapshot.attestationState.degradedReasons, ["non_enforcing_provider"])
    }

    func testFixtureEvidenceDecodesForSelectionInactiveUnavailableAndApprovalBlockedPaths() throws {
        let selectionFixture = try loadFixture(named: "content-filter-provider-selection.json")
        let inactiveFixture = try loadFixture(named: "content-filter-provider-inactive.json")
        let unavailableFixture = try loadFixture(named: "content-filter-provider-unavailable.json")
        let approvalBlockedFixture = try loadFixture(named: "content-filter-provider-approval-blocked.json")

        XCTAssertEqual(selectionFixture.providerKind, .contentFilter)
        XCTAssertEqual(selectionFixture.selectionEvidence.effectiveProvider, .contentFilter)
        XCTAssertEqual(selectionFixture.backendHint, .legacyProxyOnlyRuntime)
        XCTAssertEqual(selectionFixture.hostStatus.runtime, .degraded(reason: "non_enforcing_provider"))
        XCTAssertEqual(selectionFixture.attestationState.availability, .degraded)
        XCTAssertEqual(inactiveFixture.hostStatus.runtime, .inactive)
        XCTAssertEqual(inactiveFixture.attestationState.availability, .inactive)
        XCTAssertEqual(inactiveFixture.attestationState.degradedReasons, ["provider_failed"])
        XCTAssertEqual(unavailableFixture.hostStatus.runtime, .degraded(reason: "system_extension_not_installed"))
        XCTAssertEqual(unavailableFixture.attestationState.availability, .unavailable)
        XCTAssertEqual(approvalBlockedFixture.hostStatus.runtime, .degraded(reason: "approval_blocked"))
        XCTAssertEqual(approvalBlockedFixture.attestationState.availability, .unavailable)
        XCTAssertEqual(approvalBlockedFixture.attestationState.approvalStatus, .blocked)
    }

    func testRecoveredInputsStayDegradedUntilProviderCanActuallyEnforce() {
        let degraded = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: false,
                policySynced: true,
                degradedReasons: ["provider_failed"],
                lastHealthyAt: nil
            )
        )

        XCTAssertEqual(degraded.hostStatus.runtime, .inactive)
        XCTAssertEqual(degraded.attestationState.degradedReasons, ["provider_failed"])

        let recovered = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: true,
                policySynced: true,
                degradedReasons: [],
                lastHealthyAt: nil
            )
        )

        XCTAssertEqual(recovered.hostStatus.runtime, .degraded(reason: "non_enforcing_provider"))
        XCTAssertEqual(recovered.attestationState.degradedReasons, ["non_enforcing_provider"])
        XCTAssertEqual(recovered.attestationState.availability, .degraded)
    }

    private func loadFixture(named name: String) throws -> NetworkExtensionProviderSnapshot {
        let fixturesURL = try findFixturesDirectory(startingAt: URL(fileURLWithPath: #filePath))
        let data = try Data(contentsOf: fixturesURL.appendingPathComponent(name))
        return try JSONDecoder().decode(NetworkExtensionProviderSnapshot.self, from: data)
    }

    private func findFixturesDirectory(startingAt start: URL) throws -> URL {
        var current = start.deletingLastPathComponent()
        for _ in 0..<16 {
            let candidate = current
                .appendingPathComponent("fixtures")
                .appendingPathComponent("macos")
                .appendingPathComponent("network-extension")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
            current.deleteLastPathComponent()
        }
        throw FixtureLookupError.notFound
    }

    private enum FixtureLookupError: Error {
        case notFound
    }
}
