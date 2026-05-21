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

    func testRunningSyncedEnforcementReadyProviderReportsActiveHealth() {
        let snapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: .legacyProxyOnlyRuntime,
                filterRunning: true,
                policySynced: true,
                enforcementReady: true
            )
        )

        XCTAssertEqual(snapshot.hostStatus.runtime, .active)
        XCTAssertEqual(snapshot.attestationState.active, true)
        XCTAssertEqual(snapshot.attestationState.healthy, true)
        XCTAssertEqual(snapshot.attestationState.availability, .active)
        XCTAssertEqual(snapshot.attestationState.degradedReasons, [])
        XCTAssertTrue(snapshot.enforcementReady)
    }

    func testEgressPolicyBlocksExactActiveHostPortAndIgnoresExpiredRestrictions() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let policy = NetworkExtensionEgressPolicy(
            restrictions: [
                NetworkExtensionEgressRestriction(
                    restrictionID: "restriction-expired",
                    actionID: "action-expired",
                    executionID: "execution-expired",
                    target: "egress.example.invalid:443",
                    expiresAt: now.addingTimeInterval(-1)
                ),
                NetworkExtensionEgressRestriction(
                    restrictionID: "restriction-active",
                    actionID: "action-active",
                    executionID: "execution-active",
                    target: "egress.example.invalid:443",
                    expiresAt: now.addingTimeInterval(60)
                ),
            ]
        )

        let blocked = policy.decision(
            for: NetworkExtensionFlowTarget(host: "Egress.Example.Invalid.", port: 443),
            now: now
        )
        XCTAssertEqual(
            blocked,
            .block(policy.restrictions[1])
        )
        XCTAssertEqual(
            policy.decision(
                for: NetworkExtensionFlowTarget(host: "egress.example.invalid", port: 8443),
                now: now
            ),
            .allow
        )
    }

    func testEgressPolicyLoadsAgentGeneratedSnapshot() throws {
        let data = Data(
            """
            {
              "schemaVersion": 1,
              "generatedAt": "2026-05-15T15:00:00Z",
              "restrictions": [
                {
                  "restrictionId": "egress_restriction_test",
                  "executionId": "execution_test",
                  "actionId": "action_test",
                  "graphSliceId": "graph_slice_test",
                  "rollbackRef": "rollback_test",
                  "target": "egress.example.invalid:443",
                  "targetHash": "sha256:test",
                  "active": true,
                  "createdAt": "2026-05-15T15:00:00Z",
                  "expiresAt": "2026-05-15T15:10:00Z",
                  "updatedAt": "2026-05-15T15:00:00Z"
                }
              ]
            }
            """.utf8
        )
        let policy = try NetworkExtensionEgressPolicy.decodeSnapshot(data: data)
        let decision = policy.decision(
            for: NetworkExtensionFlowTarget(host: "egress.example.invalid", port: 443),
            now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        )

        XCTAssertEqual(decision, .block(policy.restrictions[0]))
    }

    func testLiveSnapshotReportsLoadedPolicyWithoutClaimingProviderActive() throws {
        let data = Data(
            """
            {
              "schemaVersion": 1,
              "generatedAt": "2026-05-15T15:00:00Z",
              "restrictions": [
                {
                  "restrictionId": "egress_restriction_test",
                  "executionId": "execution_test",
                  "actionId": "action_test",
                  "target": "egress.example.invalid:443",
                  "active": true,
                  "expiresAt": "2099-05-15T15:10:00Z"
                }
              ]
            }
            """.utf8
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-policy-\(UUID().uuidString).json")
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let snapshot = NetworkExtensionStatusTool.liveSnapshot(policySnapshotURL: url)

        XCTAssertTrue(snapshot.policySynced)
        XCTAssertTrue(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.remediationRequests, 1)
        XCTAssertEqual(snapshot.hostStatus.runtime, .unknown)
        XCTAssertEqual(snapshot.attestationState.active, false)
        XCTAssertEqual(snapshot.attestationState.healthy, false)
        XCTAssertEqual(snapshot.attestationState.availability, .unavailable)
        XCTAssertEqual(
            snapshot.attestationState.degradedReasons,
            ["policy_snapshot_loaded_provider_runtime_unknown"]
        )
    }

    func testLiveSnapshotReportsUnreadablePolicyWithoutClaimingProviderActive() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-invalid-policy-\(UUID().uuidString).json")
        try Data("{ not valid json".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let snapshot = NetworkExtensionStatusTool.liveSnapshot(policySnapshotURL: url)

        XCTAssertFalse(snapshot.policySynced)
        XCTAssertFalse(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.lastError, "policy_snapshot_unreadable")
        XCTAssertEqual(snapshot.hostStatus.runtime, .unknown)
        XCTAssertEqual(snapshot.attestationState.active, false)
        XCTAssertEqual(snapshot.attestationState.healthy, false)
        XCTAssertEqual(snapshot.attestationState.availability, .unavailable)
        XCTAssertEqual(
            snapshot.attestationState.degradedReasons,
            ["policy_snapshot_unreadable_provider_runtime_unknown"]
        )
    }

    func testLiveSnapshotPrefersProviderAuthoredRuntimeSnapshot() throws {
        let policyURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-policy-fallback-\(UUID().uuidString).json")
        let runtimeURL = NetworkExtensionStatusTool.runtimeSnapshotURL(for: policyURL)
        defer {
            try? FileManager.default.removeItem(at: policyURL)
            try? FileManager.default.removeItem(at: runtimeURL)
        }
        try Data("{ not valid json".utf8).write(to: policyURL)
        let providerSnapshot = NetworkExtensionStateProjector.snapshot(
            from: NetworkExtensionProviderInputs(
                installState: .installed,
                approval: .approved,
                providerKind: .contentFilter,
                backendHint: nil,
                filterRunning: true,
                policySynced: true,
                enforcementReady: true,
                counters: NetworkExtensionCounters(
                    flowsObserved: 9,
                    flowsBlocked: 3,
                    remediationRequests: 2,
                    droppedVerdicts: 0
                ),
                lastReloadObservation: NetworkExtensionProviderReloadObservation(
                    requestID: "runtime-snapshot-reload",
                    command: "reload_policy",
                    policySnapshotPath: policyURL.path,
                    generation: 88,
                    accepted: true,
                    reloaded: true,
                    error: nil
                )
            )
        )
        try FileNetworkExtensionProviderRuntimeSnapshotStore(snapshotURL: runtimeURL)
            .saveSnapshot(providerSnapshot)

        let snapshot = NetworkExtensionStatusTool.liveSnapshot(
            runtimeSnapshotURL: runtimeURL,
            fallbackPolicySnapshotURL: policyURL
        )

        XCTAssertEqual(snapshot.hostStatus.runtime, .active)
        XCTAssertEqual(snapshot.attestationState.availability, .active)
        XCTAssertEqual(snapshot.counters.flowsObserved, 9)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 3)
        XCTAssertEqual(snapshot.counters.remediationRequests, 2)
        XCTAssertEqual(snapshot.lastReloadObservation?.requestID, "runtime-snapshot-reload")
        XCTAssertEqual(snapshot.lastReloadObservation?.generation, 88)
    }

    func testContentFilterRuntimePersistsProviderRuntimeSnapshot() throws {
        let policyURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-runtime-policy-\(UUID().uuidString).json")
        let runtimeURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-runtime-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: policyURL)
            try? FileManager.default.removeItem(at: runtimeURL)
        }
        try writePolicySnapshot(
            to: policyURL,
            target: "persist-runtime.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        let store = FileNetworkExtensionProviderRuntimeSnapshotStore(snapshotURL: runtimeURL)
        let runtime = NetworkExtensionContentFilterRuntime(
            policySnapshotURL: policyURL,
            runtimeSnapshotStore: store
        )

        XCTAssertTrue(runtime.requestPolicyReloadFromHostApp(
            requestID: "persist-runtime-reload",
            policySnapshotPath: policyURL.path,
            generation: 5150
        ))
        let decision = runtime.recordFlow(
            target: NetworkExtensionFlowTarget(
                host: "persist-runtime.example.invalid",
                port: 443
            ),
            now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        )

        XCTAssertEqual(
            decision,
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "persist-runtime.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2026-05-15T15:10:00Z")!
            ))
        )
        XCTAssertTrue(runtime.persistSnapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        ))

        let snapshot = try store.loadSnapshot()
        XCTAssertEqual(snapshot.hostStatus.runtime, .active)
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertTrue(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.remediationRequests, 1)
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 1)
        XCTAssertEqual(snapshot.lastReloadObservation?.requestID, "persist-runtime-reload")
        XCTAssertEqual(snapshot.lastReloadObservation?.generation, 5150)
    }

    func testPolicyReloaderReloadsOnlyChangedSnapshots() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-reload-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        try writePolicySnapshot(
            to: url,
            target: "first.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        var reloader = NetworkExtensionEgressPolicyReloader(snapshotURL: url)

        XCTAssertTrue(try reloader.reloadIfChanged())
        XCTAssertEqual(reloader.policy?.restrictions.first?.target, "first.example.invalid:443")
        XCTAssertFalse(try reloader.reloadIfChanged())

        Thread.sleep(forTimeInterval: 0.01)
        try writePolicySnapshot(
            to: url,
            target: "second.example.invalid:443",
            generatedAt: "2026-05-15T15:00:01Z"
        )

        XCTAssertTrue(try reloader.reloadIfChanged())
        XCTAssertEqual(reloader.policy?.restrictions.first?.target, "second.example.invalid:443")
    }

    func testContentFilterRuntimeRemediationReloadRequestRefreshesPolicyAndCounters() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-reload-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try writePolicySnapshot(
            to: url,
            target: "first.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let evaluationTime = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!

        runtime.requestPolicyReloadFromHostApp()

        XCTAssertEqual(
            runtime.snapshot(
                installState: .installed,
                approval: .approved,
                backendHint: nil,
                filterRunning: true
            ).counters.remediationRequests,
            1
        )
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "first.example.invalid", port: 443),
                now: evaluationTime
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "first.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2026-05-15T15:10:00Z")!
            ))
        )

        Thread.sleep(forTimeInterval: 0.01)
        try writePolicySnapshot(
            to: url,
            target: "second.example.invalid:443",
            generatedAt: "2026-05-15T15:00:01Z"
        )

        runtime.requestPolicyReloadFromHostApp()

        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: evaluationTime
        )
        XCTAssertEqual(snapshot.counters.remediationRequests, 2)
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertTrue(snapshot.enforcementReady)
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "first.example.invalid", port: 443),
                now: evaluationTime
            ),
            .allow
        )
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "second.example.invalid", port: 443),
                now: evaluationTime
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "second.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2026-05-15T15:10:00Z")!
            ))
        )
    }

    func testContentFilterRuntimeFlowVerdictDoesNotSynchronouslyReloadWatchedPolicy() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-hot-path-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try writePolicySnapshot(
            to: url,
            target: "first.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let evaluationTime = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        XCTAssertTrue(runtime.requestPolicyReloadFromHostApp())

        Thread.sleep(forTimeInterval: 0.01)
        try writePolicySnapshot(
            to: url,
            target: "second.example.invalid:443",
            generatedAt: "2026-05-15T15:00:01Z"
        )

        XCTAssertEqual(
            runtime.recordFlow(
                target: NetworkExtensionFlowTarget(host: "second.example.invalid", port: 443),
                now: evaluationTime
            ),
            .allow
        )
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: evaluationTime
        )
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.remediationRequests, 1)
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertTrue(snapshot.enforcementReady)
    }

    func testContentFilterRuntimeFailsClosedWithoutPolicy() throws {
        let runtime = NetworkExtensionContentFilterRuntime()
        let now = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!

        let decision = runtime.recordFlow(
            target: NetworkExtensionFlowTarget(host: "missing-policy.example.invalid", port: 443),
            now: now
        )

        guard case .block(let restriction) = decision else {
            return XCTFail("missing policy must block")
        }
        XCTAssertEqual(restriction.target, "missing-policy.example.invalid:443")
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: now
        )
        XCTAssertFalse(snapshot.policySynced)
        XCTAssertFalse(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 1)
        XCTAssertEqual(snapshot.counters.droppedVerdicts, 1)
        XCTAssertEqual(snapshot.lastError, "policy_not_enforcing")
    }

    func testContentFilterRuntimeAllowsWithSyncedEmptyPolicy() throws {
        let runtime = NetworkExtensionContentFilterRuntime()
        let now = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        runtime.updatePolicy(NetworkExtensionEgressPolicy(restrictions: []))

        let decision = runtime.recordFlow(
            target: NetworkExtensionFlowTarget(host: "allowed-empty-policy.example.invalid", port: 443),
            now: now
        )

        guard case .allow = decision else {
            return XCTFail("synced empty policy must allow because no containment is active")
        }
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: now
        )
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertFalse(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 0)
        XCTAssertEqual(snapshot.counters.droppedVerdicts, 0)
        XCTAssertNil(snapshot.lastError)
    }

    func testContentFilterRuntimeAllowsAfterAllRestrictionsExpire() throws {
        let runtime = NetworkExtensionContentFilterRuntime()
        let now = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        runtime.updatePolicy(NetworkExtensionEgressPolicy(restrictions: [
            NetworkExtensionEgressRestriction(
                restrictionID: "restriction-expired",
                actionID: "action-expired",
                executionID: "execution-expired",
                target: "expired.example.invalid:443",
                expiresAt: now.addingTimeInterval(-1)
            ),
        ]))

        let decision = runtime.recordFlow(
            target: NetworkExtensionFlowTarget(host: "expired.example.invalid", port: 443),
            now: now
        )

        guard case .allow = decision else {
            return XCTFail("expired-only policy must allow because rollback/TTL removed containment")
        }
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: now
        )
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertFalse(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 0)
        XCTAssertEqual(snapshot.counters.droppedVerdicts, 0)
        XCTAssertNil(snapshot.lastError)
    }

    func testContentFilterRuntimeFailsClosedForUnresolvedTarget() throws {
        let runtime = NetworkExtensionContentFilterRuntime()
        let now = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
        runtime.updatePolicy(NetworkExtensionEgressPolicy(restrictions: [
            NetworkExtensionEgressRestriction(
                restrictionID: "restriction-active",
                actionID: "action-active",
                executionID: "execution-active",
                target: "configured.example.invalid:443",
                expiresAt: now.addingTimeInterval(60)
            ),
        ]))

        let decision = runtime.recordFlow(target: nil, now: now)

        guard case .block(let restriction) = decision else {
            return XCTFail("unresolved flow target must block")
        }
        XCTAssertEqual(restriction.target, "unresolved-flow-target")
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true,
            now: now
        )
        XCTAssertTrue(snapshot.policySynced)
        XCTAssertTrue(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.flowsObserved, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 1)
        XCTAssertEqual(snapshot.counters.droppedVerdicts, 1)
        XCTAssertEqual(snapshot.lastError, "flow_target_unresolved")
    }

    func testContentFilterRuntimeFailsClosedAfterReloadFailure() throws {
        let missingURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-missing-\(UUID().uuidString).json")
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: missingURL)
        let now = ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!

        XCTAssertFalse(runtime.requestPolicyReloadFromHostApp(
            requestID: "reload-missing-policy",
            policySnapshotPath: missingURL.path,
            generation: 7
        ))
        let decision = runtime.recordFlow(
            target: NetworkExtensionFlowTarget(host: "reload-failed.example.invalid", port: 443),
            now: now
        )

        guard case .block(let restriction) = decision else {
            return XCTFail("reload failure must block")
        }
        XCTAssertEqual(restriction.target, "reload-failed.example.invalid:443")
        let snapshot = runtime.snapshot(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true
        )
        XCTAssertFalse(snapshot.policySynced)
        XCTAssertFalse(snapshot.enforcementReady)
        XCTAssertEqual(snapshot.counters.remediationRequests, 1)
        XCTAssertEqual(snapshot.counters.flowsBlocked, 1)
        XCTAssertEqual(snapshot.counters.droppedVerdicts, 1)
    }

    func testProviderCommandReloadPolicyRefreshesWatchedSnapshotAndReturnsCounters() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-command-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try writePolicySnapshot(
            to: url,
            target: "first.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z",
            expiresAt: "2099-05-15T15:10:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: .legacyProxyOnlyRuntime,
            filterRunning: true
        )

        let firstResponseData = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-test-1",
                  "policySnapshotPath": "\(url.path)"
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )
        let decoder = JSONDecoder()
        let firstResponse = try decoder.decode(
            NetworkExtensionProviderCommandResponse.self,
            from: firstResponseData
        )

        XCTAssertEqual(firstResponse.requestID, "reload-test-1")
        XCTAssertEqual(firstResponse.command, "reload_policy")
        XCTAssertTrue(firstResponse.accepted)
        XCTAssertTrue(firstResponse.reloaded)
        XCTAssertNil(firstResponse.error)
        XCTAssertEqual(firstResponse.snapshot?.counters.remediationRequests, 1)
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "first.example.invalid", port: 443),
                now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "first.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2099-05-15T15:10:00Z")!
            ))
        )

        Thread.sleep(forTimeInterval: 0.01)
        try writePolicySnapshot(
            to: url,
            target: "second.example.invalid:443",
            generatedAt: "2026-05-15T15:00:01Z",
            expiresAt: "2099-05-15T15:10:00Z"
        )

        let secondResponseData = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-test-2"
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )
        let secondResponse = try decoder.decode(
            NetworkExtensionProviderCommandResponse.self,
            from: secondResponseData
        )

        XCTAssertEqual(secondResponse.requestID, "reload-test-2")
        XCTAssertTrue(secondResponse.accepted)
        XCTAssertTrue(secondResponse.reloaded)
        XCTAssertEqual(secondResponse.snapshot?.counters.remediationRequests, 2)
        XCTAssertTrue(secondResponse.snapshot?.policySynced == true)
        XCTAssertTrue(secondResponse.snapshot?.enforcementReady == true)
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "second.example.invalid", port: 443),
                now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "second.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2099-05-15T15:10:00Z")!
            ))
        )
    }

    func testProviderCommandDoesNotRedirectWatchedSnapshotPath() throws {
        let trustedURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-trusted-\(UUID().uuidString).json")
        let untrustedURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-untrusted-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: trustedURL)
            try? FileManager.default.removeItem(at: untrustedURL)
        }
        try writePolicySnapshot(
            to: trustedURL,
            target: "trusted.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z",
            expiresAt: "2099-05-15T15:10:00Z"
        )
        try writePolicySnapshot(
            to: untrustedURL,
            target: "untrusted.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z",
            expiresAt: "2099-05-15T15:10:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: trustedURL)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: .legacyProxyOnlyRuntime,
            filterRunning: true
        )

        let responseData = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-untrusted-path",
                  "policySnapshotPath": "\(untrustedURL.path)",
                  "generation": 4242
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )
        let response = try JSONDecoder().decode(
            NetworkExtensionProviderCommandResponse.self,
            from: responseData
        )

        XCTAssertTrue(response.accepted)
        XCTAssertTrue(response.reloaded)
        XCTAssertEqual(response.snapshot?.lastReloadObservation?.policySnapshotPath, untrustedURL.path)
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "trusted.example.invalid", port: 443),
                now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "trusted.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2099-05-15T15:10:00Z")!
            ))
        )
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "untrusted.example.invalid", port: 443),
                now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
            ),
            .allow
        )
    }

    func testProviderVendorConfigurationBuildsReloadPolicyCommandEnvelope() throws {
        let vendorConfiguration = NetworkExtensionProviderVendorConfiguration.reloadPolicy(
            requestID: "reload-vendor-test",
            policySnapshotPath: "/tmp/clawdstrike/network-extension-egress-policy.json",
            generation: 42
        )

        XCTAssertEqual(
            vendorConfiguration[NetworkExtensionProviderVendorConfiguration.commandKey] as? String,
            NetworkExtensionProviderCommand.reloadPolicyCommand
        )
        XCTAssertEqual(
            vendorConfiguration[NetworkExtensionProviderVendorConfiguration.requestIDKey] as? String,
            "reload-vendor-test"
        )
        XCTAssertEqual(
            vendorConfiguration[NetworkExtensionProviderVendorConfiguration.policySnapshotPathKey] as? String,
            "/tmp/clawdstrike/network-extension-egress-policy.json"
        )
        XCTAssertEqual(
            vendorConfiguration[NetworkExtensionProviderVendorConfiguration.generationKey] as? UInt64,
            42
        )

        let commandData = try NetworkExtensionProviderVendorConfiguration.commandData(
            from: vendorConfiguration
        )
        let decoded = try JSONSerialization.jsonObject(with: commandData) as? [String: Any]

        XCTAssertEqual(decoded?["command"] as? String, NetworkExtensionProviderCommand.reloadPolicyCommand)
        XCTAssertEqual(decoded?["requestId"] as? String, "reload-vendor-test")
        XCTAssertEqual(
            decoded?["policySnapshotPath"] as? String,
            "/tmp/clawdstrike/network-extension-egress-policy.json"
        )
        XCTAssertEqual(decoded?["generation"] as? Int, 42)
    }

    func testProviderVendorConfigurationHandlerAppliesReloadCommandOnce() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-vendor-handler-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try writePolicySnapshot(
            to: url,
            target: "vendor-handler.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true
        )
        let vendorConfiguration = NetworkExtensionProviderVendorConfiguration.reloadPolicy(
            requestID: "reload-vendor-observed",
            policySnapshotPath: url.path,
            generation: 99
        )
        var handler = NetworkExtensionProviderVendorConfigurationHandler()

        let firstResponse = try XCTUnwrap(handler.handleIfChanged(
            vendorConfiguration,
            runtime: runtime,
            context: context
        ))

        XCTAssertEqual(firstResponse.requestID, "reload-vendor-observed")
        XCTAssertEqual(firstResponse.command, NetworkExtensionProviderCommand.reloadPolicyCommand)
        XCTAssertTrue(firstResponse.accepted)
        XCTAssertTrue(firstResponse.reloaded)
        XCTAssertNil(firstResponse.error)
        XCTAssertEqual(firstResponse.snapshot?.counters.remediationRequests, 1)
        XCTAssertEqual(
            runtime.evaluate(
                target: NetworkExtensionFlowTarget(host: "vendor-handler.example.invalid", port: 443),
                now: ISO8601DateFormatter().date(from: "2026-05-15T15:01:00Z")!
            ),
            .block(NetworkExtensionEgressRestriction(
                restrictionID: "egress_restriction_test",
                actionID: "action_test",
                executionID: "execution_test",
                target: "vendor-handler.example.invalid:443",
                expiresAt: ISO8601DateFormatter().date(from: "2026-05-15T15:10:00Z")!
            ))
        )

        XCTAssertNil(try handler.handleIfChanged(
            vendorConfiguration,
            runtime: runtime,
            context: context
        ))
        XCTAssertEqual(
            runtime.snapshot(
                installState: .installed,
                approval: .approved,
                backendHint: nil,
                filterRunning: true
            ).counters.remediationRequests,
            1
        )
    }

    func testProviderCommandSnapshotBindsLastReloadObservation() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-reload-observation-\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try writePolicySnapshot(
            to: url,
            target: "reload-observed.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: .legacyProxyOnlyRuntime,
            filterRunning: true
        )

        let responseData = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-observation-test",
                  "policySnapshotPath": "\(url.path)",
                  "generation": 5150
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )
        let responseJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: responseData) as? [String: Any]
        )
        let snapshot = try XCTUnwrap(responseJSON["snapshot"] as? [String: Any])
        let observation = try XCTUnwrap(snapshot["last_reload_observation"] as? [String: Any])

        XCTAssertEqual(observation["request_id"] as? String, "reload-observation-test")
        XCTAssertEqual(observation["command"] as? String, "reload_policy")
        XCTAssertEqual(observation["policy_snapshot_path"] as? String, url.path)
        XCTAssertEqual(observation["generation"] as? Int, 5150)
        XCTAssertEqual(observation["accepted"] as? Bool, true)
        XCTAssertEqual(observation["reloaded"] as? Bool, true)
    }

    func testProviderCommandPersistsRuntimeSnapshotForWatchedPolicySource() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-late-source-\(UUID().uuidString).json")
        let runtimeURL = NetworkExtensionStatusTool.runtimeSnapshotURL(for: url)
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: runtimeURL)
        }
        try writePolicySnapshot(
            to: url,
            target: "late-source.example.invalid:443",
            generatedAt: "2026-05-15T15:00:00Z",
            expiresAt: "2099-05-15T15:10:00Z"
        )
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: nil,
            filterRunning: true
        )

        _ = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-late-source",
                  "policySnapshotPath": "\(url.path)",
                  "generation": 6161
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )

        let persisted = try FileNetworkExtensionProviderRuntimeSnapshotStore(
            snapshotURL: runtimeURL
        ).loadSnapshot()
        XCTAssertEqual(persisted.hostStatus.runtime, .active)
        XCTAssertTrue(persisted.policySynced)
        XCTAssertTrue(persisted.enforcementReady)
        XCTAssertEqual(persisted.counters.remediationRequests, 1)
        XCTAssertEqual(persisted.lastReloadObservation?.requestID, "reload-late-source")
        XCTAssertEqual(persisted.lastReloadObservation?.generation, 6161)
    }

    func testProviderCommandSnapshotBindsReloadFailureError() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdstrike-ne-provider-reload-failure-\(UUID().uuidString).json")
        try Data("{ not valid json".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let runtime = NetworkExtensionContentFilterRuntime(policySnapshotURL: url)
        let context = NetworkExtensionProviderCommandContext(
            installState: .installed,
            approval: .approved,
            backendHint: .legacyProxyOnlyRuntime,
            filterRunning: true
        )

        let responseData = try NetworkExtensionProviderCommand.handle(
            Data(
                """
                {
                  "command": "reload_policy",
                  "requestId": "reload-failure-test",
                  "policySnapshotPath": "\(url.path)",
                  "generation": 5151
                }
                """.utf8
            ),
            runtime: runtime,
            context: context
        )
        let responseJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: responseData) as? [String: Any]
        )
        let snapshot = try XCTUnwrap(responseJSON["snapshot"] as? [String: Any])
        let observation = try XCTUnwrap(snapshot["last_reload_observation"] as? [String: Any])
        let attestation = try XCTUnwrap(snapshot["attestation_state"] as? [String: Any])

        XCTAssertEqual(responseJSON["requestId"] as? String, "reload-failure-test")
        XCTAssertEqual(responseJSON["accepted"] as? Bool, true)
        XCTAssertEqual(responseJSON["reloaded"] as? Bool, false)
        XCTAssertEqual(responseJSON["error"] as? String, "policy_reload_failed")
        XCTAssertEqual(snapshot["policy_synced"] as? Bool, false)
        XCTAssertEqual(snapshot["enforcement_ready"] as? Bool, false)
        XCTAssertEqual(snapshot["last_error"] as? String, "policy_reload_failed")
        XCTAssertEqual(observation["request_id"] as? String, "reload-failure-test")
        XCTAssertEqual(observation["accepted"] as? Bool, true)
        XCTAssertEqual(observation["reloaded"] as? Bool, false)
        XCTAssertEqual(observation["error"] as? String, "policy_reload_failed")
        XCTAssertEqual(
            attestation["degraded_reasons"] as? [String],
            ["policy_reload_failed", "policy_not_synced"]
        )
    }

    func testReloadRequesterPersistsVendorConfigurationWithoutDroppingExistingKeys() throws {
        let store = FakeVendorConfigurationStore(
            loadedVendorConfiguration: [
                "existing.key": "preserved",
            ]
        )

        let result = try NetworkExtensionProviderReloadRequester.requestReload(
            policySnapshotPath: "/tmp/clawdstrike/network-extension-egress-policy.json",
            generation: 7,
            requestID: "reload-request-test",
            store: store
        )

        XCTAssertTrue(result.saved)
        XCTAssertEqual(result.command, NetworkExtensionProviderCommand.reloadPolicyCommand)
        XCTAssertEqual(result.requestID, "reload-request-test")
        XCTAssertEqual(result.policySnapshotPath, "/tmp/clawdstrike/network-extension-egress-policy.json")
        XCTAssertEqual(result.generation, 7)
        XCTAssertEqual(store.savedVendorConfigurations.count, 1)

        let saved = try XCTUnwrap(store.savedVendorConfigurations.first)
        XCTAssertEqual(saved["existing.key"] as? String, "preserved")
        XCTAssertEqual(
            saved[NetworkExtensionProviderVendorConfiguration.commandKey] as? String,
            NetworkExtensionProviderCommand.reloadPolicyCommand
        )
        XCTAssertEqual(
            saved[NetworkExtensionProviderVendorConfiguration.requestIDKey] as? String,
            "reload-request-test"
        )
        XCTAssertEqual(
            saved[NetworkExtensionProviderVendorConfiguration.policySnapshotPathKey] as? String,
            "/tmp/clawdstrike/network-extension-egress-policy.json"
        )
        XCTAssertEqual(
            saved[NetworkExtensionProviderVendorConfiguration.generationKey] as? UInt64,
            7
        )
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
        XCTAssertFalse(selectionFixture.enforcementReady)
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

    private final class FakeVendorConfigurationStore: NetworkExtensionProviderVendorConfigurationStore {
        var loadedVendorConfiguration: [String: Any]
        var savedVendorConfigurations: [[String: Any]]

        init(loadedVendorConfiguration: [String: Any]) {
            self.loadedVendorConfiguration = loadedVendorConfiguration
            self.savedVendorConfigurations = []
        }

        func loadVendorConfiguration() throws -> [String: Any] {
            loadedVendorConfiguration
        }

        func saveVendorConfiguration(_ vendorConfiguration: [String: Any]) throws {
            savedVendorConfigurations.append(vendorConfiguration)
        }
    }

    private func writePolicySnapshot(
        to url: URL,
        target: String,
        generatedAt: String,
        expiresAt: String = "2026-05-15T15:10:00Z"
    ) throws {
        let data = Data(
            """
            {
              "schemaVersion": 1,
              "generatedAt": "\(generatedAt)",
              "restrictions": [
                {
                  "restrictionId": "egress_restriction_test",
                  "executionId": "execution_test",
                  "actionId": "action_test",
                  "target": "\(target)",
                  "active": true,
                  "expiresAt": "\(expiresAt)"
                }
              ]
            }
            """.utf8
        )
        try data.write(to: url)
    }
}
