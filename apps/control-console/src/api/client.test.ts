import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  approveBrokerPreview,
  attachEndpointEvidenceArchiveToCase,
  backfillEndpointEvidenceArchivesToControl,
  bulkUpdateFleetCaseStatus,
  createCausalContext,
  createCausalSubgraph,
  createDetectionCandidate,
  createFleetCase,
  createPolicyDelta,
  createPolicyReplay,
  createPrivacyReport,
  createResponseAction,
  createStagedDetection,
  downloadEndpointEvidenceArchive,
  downloadFleetEvidenceBundle,
  dryRunPolicyDeltaApply,
  exportBrokerCompletionBundle,
  exportFleetCaseEvidenceBundle,
  exportGraphSlice,
  fetchAgentSecretTouches,
  fetchAgentStatus,
  fetchAuditEvents,
  fetchAuditStats,
  fetchBrokerCapabilities,
  fetchBrokerCapability,
  fetchBrokerPreview,
  fetchBrokerPreviews,
  fetchEndpointEvidenceArchive,
  fetchFindingGroups,
  fetchFleetCase,
  fetchFleetCases,
  fetchFleetCaseTimeline,
  fetchFrozenBrokerProviders,
  fetchHealth,
  fetchIntegrationSettings,
  fetchNetworkExtensionEgressPolicyProof,
  fetchPolicy,
  fetchResponseExecutionProof,
  fetchResponseExecutions,
  freezeBrokerProvider,
  publishAgentSecretTouchesToFleet,
  publishEndpointEvidenceBundleToFleet,
  replayBrokerCapability,
  revokeAllBrokerCapabilities,
  revokeBrokerCapability,
  rollbackResponseExecution,
  saveIntegrationSettings,
  testIntegrationDelivery,
  unfreezeBrokerProvider,
  updateFleetCase,
} from "./client";

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal("fetch", mockFetch);
  // Clear localStorage mock
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

describe("fetchHealth", () => {
  it("returns health data on success", async () => {
    mockFetch.mockReturnValue(jsonResponse({ status: "ok", version: "0.2.0" }));
    const result = await fetchHealth();
    expect(result.status).toBe("ok");
    expect(result.version).toBe("0.2.0");
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockReturnValue(jsonResponse({}, 500));
    await expect(fetchHealth()).rejects.toThrow("Health check failed: 500");
  });
});

describe("fetchAuditEvents", () => {
  it("builds query string from filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ events: [], total: 0 }));
    await fetchAuditEvents({
      decision: "blocked",
      limit: 10,
      offset: 5,
      runtime_agent_id: "runtime-1",
      runtime_agent_kind: "claude_code",
    });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("decision=blocked");
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=5");
    expect(url).toContain("runtime_agent_id=runtime-1");
    expect(url).toContain("runtime_agent_kind=claude_code");
  });

  it("omits empty filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ events: [], total: 0 }));
    await fetchAuditEvents({});

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("/api/v1/audit");
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockReturnValue(jsonResponse({}, 403));
    await expect(fetchAuditEvents()).rejects.toThrow("Audit query failed: 403");
  });
});

describe("fetchAgentStatus", () => {
  it("queries agent status endpoint with filters", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        generated_at: "2026-03-04T00:00:00Z",
        stale_after_secs: 90,
        endpoints: [],
        runtimes: [],
      }),
    );
    await fetchAgentStatus({
      endpoint_agent_id: "endpoint-1",
      include_stale: true,
      limit: 25,
    });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v1/agents/status");
    expect(url).toContain("endpoint_agent_id=endpoint-1");
    expect(url).toContain("include_stale=true");
    expect(url).toContain("limit=25");
  });
});

describe("endpoint evidence archive helpers", () => {
  it("fetches archive metadata and raw archive download by encoded archive id", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse({
          archiveId: "archive/with spaces",
          archiveHash: "0xarchive",
          rawRef: "endpoint-evidence-bundle-archive:archive/with spaces:0xarchive",
          bundleId: "bundle-1",
          endpointAgentId: "endpoint-agent-1",
          eventId: "evidence-bundle-archive:endpoint-agent-1:archive/with spaces",
          uploadedAt: "2026-05-16T12:00:00Z",
          expiresAt: "2026-06-15T12:00:00Z",
          retentionDays: 30,
          sizeBytes: 4096,
          verification: { verified: true },
          metadata: { source: "clawdstrike-agent" },
        }),
      )
      .mockReturnValueOnce(
        jsonResponse({
          record: {
            archiveId: "archive/with spaces",
            archiveHash: "0xarchive",
            rawRef: "endpoint-evidence-bundle-archive:archive/with spaces:0xarchive",
            bundleId: "bundle-1",
            uploadedAt: "2026-05-16T12:00:00Z",
            expiresAt: "2026-06-15T12:00:00Z",
            retentionDays: 30,
            sizeBytes: 4096,
            verification: { verified: true },
            metadata: { source: "clawdstrike-agent" },
          },
          archive: { bundle: { bundleId: "bundle-1" }, receipts: [] },
        }),
      );

    const metadata = await fetchEndpointEvidenceArchive("archive/with spaces");
    const download = await downloadEndpointEvidenceArchive("archive/with spaces");

    expect(metadata.archiveId).toBe("archive/with spaces");
    expect(download.archive.bundle).toMatchObject({ bundleId: "bundle-1" });
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/hunt/evidence-bundle-archives/archive%2Fwith%20spaces",
    );
    expect(mockFetch.mock.calls[1][0]).toBe(
      "/api/v1/hunt/evidence-bundle-archives/archive%2Fwith%20spaces/download",
    );
  });

  it("attaches endpoint evidence archives to remote cases", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        id: "artifact-1",
        caseId: "case/with spaces",
        artifactKind: "endpoint_evidence_archive",
        artifactId: "archive/with spaces",
        summary: "endpoint evidence archive bundle-1",
        metadata: {
          artifactClass: "verified_reference",
          sourceTable: "endpoint_evidence_archives",
        },
        addedBy: "operator@example.com",
        addedAt: "2026-05-16T12:00:00Z",
      }),
    );

    const artifact = await attachEndpointEvidenceArchiveToCase(
      "case/with spaces",
      "archive/with spaces",
    );

    expect(artifact.artifactKind).toBe("endpoint_evidence_archive");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/cases/case%2Fwith%20spaces/artifacts");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(JSON.parse(mockFetch.mock.calls[0][1].body as string)).toEqual({
      artifactKind: "endpoint_evidence_archive",
      artifactId: "archive/with spaces",
    });
  });
});

describe("fleet case helpers", () => {
  it("lists fleet cases and creates a case with encoded JSON body", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse([
          {
            id: "case-1",
            tenantId: "tenant-1",
            title: "Existing case",
            severity: "high",
            status: "open",
            createdBy: "operator@example.com",
            principalIds: [],
            detectionIds: [],
            responseActionIds: [],
            grantIds: [],
            tags: ["endpoint-evidence"],
            metadata: {},
            createdAt: "2026-05-16T12:00:00Z",
            updatedAt: "2026-05-16T12:00:00Z",
          },
        ]),
      )
      .mockReturnValueOnce(
        jsonResponse({
          id: "case-2",
          tenantId: "tenant-1",
          title: "Endpoint evidence archive evidence_bundle-1",
          summary: "Remote case created from retained endpoint archive evidence_bundle_archive-1",
          severity: "high",
          status: "open",
          createdBy: "operator@example.com",
          principalIds: ["principal-1"],
          detectionIds: [],
          responseActionIds: [],
          grantIds: [],
          tags: ["endpoint-evidence", "case-handoff"],
          metadata: { archiveId: "evidence_bundle_archive-1" },
          createdAt: "2026-05-16T12:01:00Z",
          updatedAt: "2026-05-16T12:01:00Z",
        }),
      );

    const cases = await fetchFleetCases();
    const created = await createFleetCase({
      title: " Endpoint evidence archive evidence_bundle-1 ",
      summary: "Remote case created from retained endpoint archive evidence_bundle_archive-1",
      severity: "high",
      principalIds: ["principal-1"],
      tags: ["endpoint-evidence", "case-handoff"],
      metadata: { archiveId: "evidence_bundle_archive-1" },
    });

    expect(cases[0].id).toBe("case-1");
    expect(created.id).toBe("case-2");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/cases");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/cases");
    expect(mockFetch.mock.calls[1][1]).toMatchObject({
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(JSON.parse(mockFetch.mock.calls[1][1].body as string)).toEqual({
      title: "Endpoint evidence archive evidence_bundle-1",
      summary: "Remote case created from retained endpoint archive evidence_bundle_archive-1",
      severity: "high",
      principalIds: ["principal-1"],
      tags: ["endpoint-evidence", "case-handoff"],
      metadata: { archiveId: "evidence_bundle_archive-1" },
    });
  });

  it("lists fleet cases with server-side query filters", async () => {
    mockFetch.mockReturnValue(jsonResponse([]));

    await fetchFleetCases({
      query: "endpoint archive",
      status: "closed",
      severity: "low",
    });

    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/cases?q=endpoint+archive&status=closed&severity=low",
    );
  });

  it("loads case detail, timeline, and requests a signed evidence export", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse({
          case: {
            id: "case/with spaces",
            tenantId: "tenant-1",
            title: "Existing case",
            severity: "high",
            status: "open",
            createdBy: "operator@example.com",
            principalIds: [],
            detectionIds: [],
            responseActionIds: [],
            grantIds: [],
            tags: [],
            metadata: {},
            createdAt: "2026-05-16T12:00:00Z",
            updatedAt: "2026-05-16T12:00:00Z",
          },
          artifacts: [],
          evidenceBundles: [],
        }),
      )
      .mockReturnValueOnce(
        jsonResponse([
          {
            id: "timeline-1",
            caseId: "case/with spaces",
            eventKind: "artifact_added",
            actorId: "operator@example.com",
            payload: { artifactKind: "endpoint_evidence_archive" },
            createdAt: "2026-05-16T12:01:00Z",
          },
        ]),
      )
      .mockReturnValueOnce(
        jsonResponse({
          exportId: "caseexp-1",
          tenantId: "tenant-1",
          caseId: "case/with spaces",
          status: "completed",
          requestedBy: "operator@example.com",
          requestedAt: "2026-05-16T12:02:00Z",
          retentionDays: 30,
          filters: {},
          artifactCounts: { endpoint_evidence_archive: 1 },
          metadata: { manifestRef: "manifest.json" },
        }),
      );

    const detail = await fetchFleetCase("case/with spaces");
    const timeline = await fetchFleetCaseTimeline("case/with spaces");
    const bundle = await exportFleetCaseEvidenceBundle("case/with spaces", {
      includeRawEnvelopes: true,
      retentionDays: 7,
    });

    expect(detail.case.id).toBe("case/with spaces");
    expect(timeline[0].eventKind).toBe("artifact_added");
    expect(bundle.exportId).toBe("caseexp-1");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/cases/case%2Fwith%20spaces");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/cases/case%2Fwith%20spaces/timeline");
    expect(mockFetch.mock.calls[2][0]).toBe("/api/v1/cases/case%2Fwith%20spaces/evidence/export");
    expect(JSON.parse(mockFetch.mock.calls[2][1].body as string)).toEqual({
      includeRawEnvelopes: true,
      retentionDays: 7,
    });
  });

  it("updates a fleet case by encoded id", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        id: "case/with spaces",
        tenantId: "tenant-1",
        title: "Existing case",
        severity: "critical",
        status: "closed",
        createdBy: "operator@example.com",
        principalIds: [],
        detectionIds: [],
        responseActionIds: [],
        grantIds: [],
        tags: ["case-management"],
        metadata: { closedBy: "operator" },
        createdAt: "2026-05-16T12:00:00Z",
        updatedAt: "2026-05-16T12:04:00Z",
      }),
    );

    const updated = await updateFleetCase("case/with spaces", {
      status: "closed",
      severity: "critical",
      tags: ["case-management"],
      metadata: { closedBy: "operator" },
    });

    expect(updated.status).toBe("closed");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/cases/case%2Fwith%20spaces");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
    });
    expect(JSON.parse(mockFetch.mock.calls[0][1].body as string)).toEqual({
      status: "closed",
      severity: "critical",
      tags: ["case-management"],
      metadata: { closedBy: "operator" },
    });
  });

  it("bulk updates selected fleet case status", async () => {
    mockFetch.mockReturnValue(
      jsonResponse([
        {
          id: "case-1",
          tenantId: "tenant-1",
          title: "Selected case 1",
          severity: "high",
          status: "closed",
          createdBy: "operator@example.com",
          principalIds: [],
          detectionIds: [],
          responseActionIds: [],
          grantIds: [],
          tags: ["case-management"],
          metadata: {},
          createdAt: "2026-05-16T12:00:00Z",
          updatedAt: "2026-05-16T12:05:00Z",
        },
        {
          id: "case-2",
          tenantId: "tenant-1",
          title: "Selected case 2",
          severity: "medium",
          status: "closed",
          createdBy: "operator@example.com",
          principalIds: [],
          detectionIds: [],
          responseActionIds: [],
          grantIds: [],
          tags: ["case-management"],
          metadata: {},
          createdAt: "2026-05-16T12:01:00Z",
          updatedAt: "2026-05-16T12:05:00Z",
        },
      ]),
    );

    const updated = await bulkUpdateFleetCaseStatus(["case-1", "case-2"], "closed");

    expect(updated).toHaveLength(2);
    expect(updated.every((fleetCase) => fleetCase.status === "closed")).toBe(true);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/cases/bulk");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
    });
    expect(JSON.parse(mockFetch.mock.calls[0][1].body as string)).toEqual({
      caseIds: ["case-1", "case-2"],
      status: "closed",
    });
  });

  it("downloads a signed fleet evidence bundle by encoded export id", async () => {
    const bundle = new Blob(["zip"], { type: "application/zip" });
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: true,
        status: 200,
        blob: () => Promise.resolve(bundle),
        text: () => Promise.resolve(""),
      }),
    );

    const downloaded = await downloadFleetEvidenceBundle("caseexp/with spaces");

    expect(downloaded).toBe(bundle);
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/evidence-bundles/caseexp%2Fwith%20spaces/download",
    );
  });
});

describe("endpoint response execution proof helpers", () => {
  it("publishes an endpoint evidence bundle with raw archive approval query fields", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        bundleId: "evidence_bundle-1",
        archiveId: "evidence_bundle_archive-1",
        archiveHash: "0xarchive",
        published: true,
        queued: false,
        controlUpload: {
          attempted: true,
          accepted: true,
          rawArtifactUploadAllowed: true,
          rawArtifactApprovalRequired: true,
          rawArtifactApprovalProvided: true,
          rawArtifactApprovalId: "approval-archive-ui-1",
          rawArtifactApprovalReasonHash: "0xapproval",
          policySource: "/tmp/policy.yml",
          retryQueued: false,
        },
        eventId: "evidence-bundle-archive:endpoint-agent-1:evidence_bundle_archive-1",
        rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
      }),
    );

    const result = await publishEndpointEvidenceBundleToFleet("evidence_bundle-1", {
      rawArtifactApprovalId: " approval-archive-ui-1 ",
      rawArtifactApprovalReason: " incident ir-ui-1 raw archive approved ",
    });

    expect(result.controlUpload?.rawArtifactApprovalId).toBe("approval-archive-ui-1");
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/agent/edr/evidence-bundles/evidence_bundle-1/fleet-publish?rawArtifactApprovalId=approval-archive-ui-1&rawArtifactApprovalReason=incident+ir-ui-1+raw+archive+approved",
    );
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
    });
  });

  it("backfills endpoint evidence archives with raw archive approval body fields", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        attempted: 1,
        delivered: 1,
        failed: 0,
        skipped: 0,
        records: [
          {
            bundleId: "evidence_bundle-1",
            archiveId: "evidence_bundle_archive-1",
            archiveHash: "0xarchive",
            rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
            controlUpload: {
              attempted: true,
              accepted: true,
              rawArtifactUploadAllowed: true,
              rawArtifactApprovalRequired: true,
              rawArtifactApprovalProvided: true,
              rawArtifactApprovalId: "approval-backfill-ui-1",
              rawArtifactApprovalReasonHash: "0xapproval",
              policySource: "/tmp/policy.yml",
              retryQueued: false,
            },
          },
        ],
      }),
    );

    const result = await backfillEndpointEvidenceArchivesToControl({
      bundleId: " evidence_bundle-1 ",
      limit: 5,
      rawArtifactApprovalId: " approval-backfill-ui-1 ",
      rawArtifactApprovalReason: " incident ir-ui-2 raw archive backfill approved ",
    });

    expect(result.delivered).toBe(1);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/control-archive-uploads/backfill");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        bundleId: "evidence_bundle-1",
        limit: 5,
        rawArtifactApprovalId: "approval-backfill-ui-1",
        rawArtifactApprovalReason: "incident ir-ui-2 raw archive backfill approved",
      }),
    });
  });

  it("queries agent-secret touches with credential graph filters", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        touchCount: 1,
        touches: [
          {
            credentialNodeId: "credential:aws",
            credentialLabel: "/Users/alice/.aws/credentials",
            credentialKind: "cloud_credential",
            path: "/Users/alice/.aws/credentials",
            name: "aws-credentials",
            agentNodeIds: ["agent:codex"],
            agentLabels: ["agent:codex", "mcp__filesystem__read_file"],
            processNodeIds: ["process:python"],
            graph: {
              nodes: {
                "credential:aws": { kind: "credential", label: "/Users/alice/.aws/credentials" },
                "agent:codex": { kind: "agent", label: "agent:codex" },
              },
              edges: [],
            },
            receipt: {
              receipt: { metadata: { endpointDecision: { receiptFamily: "graph_slice" } } },
            },
          },
        ],
      }),
    );

    const result = await fetchAgentSecretTouches({
      sessionId: "agent-secret-session-1",
      credentialKind: "cloud_credential",
      requireAgentContext: true,
      upstreamDepth: 3,
      downstreamDepth: 1,
      limit: 10,
    });

    expect(result.touchCount).toBe(1);
    expect(result.touches[0].agentLabels).toContain("mcp__filesystem__read_file");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/agent-secret-touches");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        sessionId: "agent-secret-session-1",
        credentialKind: "cloud_credential",
        requireAgentContext: true,
        upstreamDepth: 3,
        downstreamDepth: 1,
        limit: 10,
      }),
    });
  });

  it("publishes filtered agent-secret touches to the fleet hunt stream", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        touchCount: 1,
        publishedCount: 1,
        events: [
          {
            eventId: "hunt-event-1",
            rawRef: "nats://hunt.raw/hunt-event-1",
            credentialNodeId: "credential:aws",
          },
        ],
      }),
    );

    const result = await publishAgentSecretTouchesToFleet({
      sessionId: "agent-secret-session-1",
      credentialKind: "cloud_credential",
      limit: 10,
    });

    expect(result.publishedCount).toBe(1);
    expect(result.events[0].rawRef).toBe("nats://hunt.raw/hunt-event-1");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/agent-secret-touches/fleet-publish");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        sessionId: "agent-secret-session-1",
        credentialKind: "cloud_credential",
        limit: 10,
      }),
    });
  });

  it("creates a dry-run local containment response action", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        plan: {
          actionId: "response-action-1",
          action: "suspend_process_tree",
          dryRun: true,
          rootNodeId: "process:proc-1",
          graphSliceId: "graph-slice-1",
          ttlSeconds: 600,
          rollbackRef: "rollback:response-action-1",
          reason: "contain process tree for 10 minutes",
          createdAt: "2026-05-16T12:00:00Z",
          expiresAt: "2026-05-16T12:10:00Z",
          nodeCount: 3,
          edgeCount: 2,
        },
        graph: { nodes: {}, edges: [] },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "response_request" } } },
        },
      }),
    );

    const result = await createResponseAction({
      process: { processGuid: "proc-1" },
      action: "suspend_process_tree",
      ttlSeconds: 600,
      dryRun: true,
      reason: "contain process tree for 10 minutes",
    });

    expect(result.plan.rollbackRef).toBe("rollback:response-action-1");
    expect(result.plan.ttlSeconds).toBe(600);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/response-action");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        process: { processGuid: "proc-1" },
        action: "suspend_process_tree",
        ttlSeconds: 600,
        dryRun: true,
        reason: "contain process tree for 10 minutes",
      }),
    });
  });

  it("rolls back a rollback-capable response execution by encoded execution id", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        path: "/tmp/response-executions.jsonl",
        execution: {
          execution: {
            executionId: "exec/with spaces",
            action: "suspend_process_tree",
            status: "succeeded",
            ttlSeconds: 600,
            rollbackRef: "rollback:exec-1",
          },
          expiresAt: "2026-05-16T12:10:00Z",
          expired: false,
          rollbackRef: "rollback:exec-1",
        },
        rollback: {
          rollbackId: "rollback-1",
          executionId: "exec/with spaces",
          action: "suspend_process_tree",
          status: "succeeded",
          ttlSeconds: 600,
          rollbackRef: "rollback:exec-1",
          reason: "operator rollback",
          effects: [
            {
              effectId: "effect-1",
              effectType: "resume_process_tree",
              target: "pid:4242",
            },
          ],
        },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "response_rollback" } } },
        },
      }),
    );

    const result = await rollbackResponseExecution("exec/with spaces", {
      reason: "operator rollback",
    });

    expect(result.rollback.effects[0].effectType).toBe("resume_process_tree");
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/agent/edr/response-executions/exec%2Fwith%20spaces/rollback",
    );
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ reason: "operator rollback" }),
    });
  });

  it("queries recent response executions with a bounded limit", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        path: "/tmp/response-executions.jsonl",
        execution_count: 1,
        executions: [
          {
            execution: {
              executionId: "exec-1",
              actionId: "action-1",
              status: "succeeded",
              action: "collect_evidence",
              completedAt: "2026-05-16T12:00:00Z",
              evidenceBundle: { bundleId: "bundle-1" },
            },
            expiresAt: "2026-05-16T12:10:00Z",
            expired: false,
            rollbackRef: "rollback:exec-1",
          },
        ],
      }),
    );

    const result = await fetchResponseExecutions({ limit: 25 });

    expect(result.execution_count).toBe(1);
    expect(result.executions[0].execution.executionId).toBe("exec-1");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/response-executions?limit=25");
  });

  it("fetches a proof package by encoded execution id", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        executionPath: "/tmp/response-executions.jsonl",
        receiptPath: "/tmp/decision-receipts.jsonl",
        execution: {
          execution: {
            executionId: "exec/with spaces",
            actionId: "action-1",
            status: "succeeded",
            action: "collect_evidence",
            evidenceBundle: { bundleId: "bundle-1" },
          },
          expiresAt: "2026-05-16T12:10:00Z",
          expired: false,
          rollbackRef: "rollback:exec-1",
        },
        graph: { graphSliceId: "graph-1" },
        providerState: { providers: [{ providerId: "agent-api", healthy: true }] },
        requestReceipt: { receipt: { receipt_id: "request-1" } },
        executionReceipt: { receipt: { receipt_id: "execution-1" } },
        evidenceBundleReceipt: { receipt: { receipt_id: "bundle-1" } },
        transitionReceipts: [{ receipt: { receipt_id: "expired-1" } }],
        rollbackReceipts: [{ receipt: { receipt_id: "rollback-1" } }],
        acknowledgementReceipts: [{ receipt: { receipt_id: "ack-1" } }],
      }),
    );

    const result = await fetchResponseExecutionProof("exec/with spaces");

    expect(result.graph.graphSliceId).toBe("graph-1");
    expect(result.providerState.providers[0].providerId).toBe("agent-api");
    expect(result.transitionReceipts?.[0]).toEqual({ receipt: { receipt_id: "expired-1" } });
    expect(result.rollbackReceipts?.[0]).toEqual({ receipt: { receipt_id: "rollback-1" } });
    expect(result.acknowledgementReceipts?.[0]).toEqual({ receipt: { receipt_id: "ack-1" } });
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/agent/edr/response-executions/exec%2Fwith%20spaces/proof",
    );
  });

  it("fetches the NetworkExtension egress policy proof with provider counters", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        providerPolicyPath: "/tmp/clawdstrike-network-egress-policy.json",
        snapshotPresent: true,
        snapshotDecodable: true,
        snapshotHash: "0xproof",
        restrictionCount: 1,
        activeRestrictionCount: 1,
        expiredRestrictionCount: 0,
        enforcementReady: true,
        flowCounterObserved: true,
        observedFlowCount: 11,
        blockedFlowCount: 3,
        remediationRequestCount: 1,
        droppedVerdictCount: 0,
        providerStatusRefresh: { requested: false, refreshed: false },
        networkExtensionProvider: { runtime: "active", policy_synced: true },
        sensorState: { providers: [{ providerId: "macos.network_extension", healthy: true }] },
        receipt: { receipt: { metadata: { endpointDecision: { receiptFamily: "sensor_state" } } } },
        degradedProviderReceipts: [],
      }),
    );

    const result = await fetchNetworkExtensionEgressPolicyProof({
      refreshProviders: false,
      providerRefreshTimeoutMs: 1000,
    });

    expect(result.flowCounterObserved).toBe(true);
    expect(result.observedFlowCount).toBe(11);
    expect(result.blockedFlowCount).toBe(3);
    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/v1/agent/edr/network-extension/egress-policy/proof",
    );
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ refreshProviders: false, providerRefreshTimeoutMs: 1000 }),
    });
  });

  it("creates a signed privacy report for submitted endpoint observations", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        report: {
          reportId: "privacy-1",
          privacyMode: "hashes_features",
          rawArtifactUploadPermitted: false,
          observationCount: 1,
          fieldCount: 3,
          hashOnlyCount: 1,
          metadataOnlyCount: 1,
          redactedCount: 0,
          rawSuppressedCount: 1,
          localOnlyCount: 1,
          observations: [
            {
              observationId: "obs-1",
              eventKind: "file_access",
              fieldCount: 3,
              rawSuppressedCount: 1,
              localOnlyCount: 1,
              projections: [
                {
                  fieldPath: "event.fileAccess.contentPreview",
                  redactionClass: "local_only",
                  valueHash: "0xabc",
                  reason: "raw artifact remains local",
                },
              ],
            },
          ],
        },
        privacy_policy: {
          requestedPrivacyMode: "raw_artifact_permitted",
          effectivePrivacyMode: "hashes_features",
          rawArtifactUploadRequested: true,
          rawArtifactUploadAllowed: false,
          policySource: "/tmp/policy.yml",
          deniedReason: "raw_artifact_permitted was requested",
        },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "privacy_report" } } },
        },
      }),
    );

    const result = await createPrivacyReport({
      privacyMode: "raw_artifact_permitted",
      rawArtifactApprovalId: "approval-privacy-api-1",
      rawArtifactApprovalReason: "incident ir-api-1 raw collection approved",
      observations: [{ event: { fileAccess: { contentPreview: "secret" } } }],
    });

    expect(result.report.rawSuppressedCount).toBe(1);
    expect(result.privacy_policy.effectivePrivacyMode).toBe("hashes_features");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/privacy-report");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        privacyMode: "raw_artifact_permitted",
        rawArtifactApprovalId: "approval-privacy-api-1",
        rawArtifactApprovalReason: "incident ir-api-1 raw collection approved",
        observations: [{ event: { fileAccess: { contentPreview: "secret" } } }],
      }),
    });
  });
});

describe("endpoint causal finding group helpers", () => {
  it("queries causal finding groups with bounded limit and max depth", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        groupCount: 1,
        findingCount: 2,
        groups: [
          {
            groupId: "group-1",
            rootNodeId: "process:proc-1",
            rootLabel: "/usr/local/bin/npm",
            findingCount: 2,
            nodeCount: 3,
            edgeCount: 2,
            ruleIds: ["supply_chain.developer_secret_access", "supply_chain.install_script.risky"],
            findingIds: ["finding-1", "finding-2"],
            findings: [],
            graph: {
              nodes: {
                "process:proc-1": { kind: "process", label: "/usr/local/bin/npm" },
                "package_script:postinstall": { kind: "package_script", label: "postinstall" },
                "credential:aws": { kind: "credential", label: "aws-credentials" },
              },
              edges: [{ from: "process:proc-1", to: "credential:aws", kind: "read" }],
            },
            receipt: {
              receipt: { metadata: { endpointDecision: { receiptFamily: "graph_slice" } } },
            },
          },
        ],
      }),
    );

    const result = await fetchFindingGroups({ limit: 10, maxDepth: 3 });

    expect(result.groupCount).toBe(1);
    expect(result.groups[0].ruleIds).toContain("supply_chain.install_script.risky");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/finding-groups?limit=10&maxDepth=3");
  });
});

describe("endpoint causal graph slice helpers", () => {
  it("creates a causal subgraph from a process guid and max depth", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        root_node_id: "process:proc-1",
        max_depth: 3,
        node_count: 2,
        edge_count: 1,
        graph: {
          nodes: {
            "process:proc-1": { kind: "process", label: "/usr/bin/python3" },
            "network:api.example.invalid:443": {
              kind: "network",
              label: "api.example.invalid:443",
            },
          },
          edges: [
            { from: "process:proc-1", to: "network:api.example.invalid:443", kind: "opened" },
          ],
        },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "graph_slice" } } },
        },
      }),
    );

    const result = await createCausalSubgraph({
      process: { processGuid: "proc-1" },
      maxDepth: 3,
    });

    expect(result.node_count).toBe(2);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/causal-subgraph");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ process: { processGuid: "proc-1" }, maxDepth: 3 }),
    });
  });

  it("creates causal context from a root node with bounded upstream and downstream depth", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        root_node_id: "network:api.example.invalid:443",
        upstream_depth: 2,
        downstream_depth: 1,
        node_count: 3,
        edge_count: 2,
        graph: { nodes: {}, edges: [] },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "graph_slice" } } },
        },
      }),
    );

    const result = await createCausalContext({
      rootNodeId: "network:api.example.invalid:443",
      upstreamDepth: 2,
      downstreamDepth: 1,
    });

    expect(result.upstream_depth).toBe(2);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/causal-context");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        rootNodeId: "network:api.example.invalid:443",
        upstreamDepth: 2,
        downstreamDepth: 1,
      }),
    });
  });

  it("exports a signed graph slice evidence bundle", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        rootNodeId: "process:proc-1",
        sliceKind: "causal_subgraph",
        nodeCount: 2,
        edgeCount: 1,
        graph: { nodes: {}, edges: [] },
        bundle: {
          bundleId: "bundle-1",
          graphSliceId: "graph-slice-1",
          contentHash: "0xabc",
          nodeCount: 2,
          edgeCount: 1,
        },
        artifact: {
          bundleId: "bundle-1",
          path: "/tmp/bundle-1.json",
          byteCount: 512,
        },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "graph_slice" } } },
        },
      }),
    );

    const result = await exportGraphSlice({
      rootNodeId: "process:proc-1",
      sliceKind: "causal_subgraph",
      maxDepth: 3,
      reason: "operator export",
    });

    expect(result.bundle.graphSliceId).toBe("graph-slice-1");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/graph-slices/export");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        rootNodeId: "process:proc-1",
        sliceKind: "causal_subgraph",
        maxDepth: 3,
        reason: "operator export",
      }),
    });
  });
});

describe("endpoint policy replay helpers", () => {
  it("replays a captured graph target under the current local policy", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        replay: {
          replayId: "policy-replay-1",
          replayedAt: "2026-05-16T12:00:00Z",
          mode: "current_policy_graph_replay",
          policy: {
            policyVersion: "test-edr-replay",
            policyHash: "sha256:policy",
            policyEpoch: 77,
          },
          rootNodeId: "process:proc-1",
          rootLabel: "/usr/local/bin/npm",
          rootKind: "process",
          action: "block",
          graphSliceId: "graph-slice-1",
          observationCount: 2,
          nodeCount: 3,
          edgeCount: 2,
          flightRecorderObservationCount: 5,
          wouldEnforce: true,
          developerBreakageScore: 72,
          impactLevel: "high",
          summary: "Replayed graph slice graph-slice-1 under current endpoint policy.",
        },
        simulation: {
          simulationId: "simulation-1",
          ruleId: "endpoint.current_policy_replay.epoch_77.block.process.npm",
          action: "block",
          rootNodeId: "process:proc-1",
          graphSliceId: "graph-slice-1",
          wouldBlock: true,
          createdAt: "2026-05-16T12:00:00Z",
          affectedNodeCount: 3,
          affectedEdgeCount: 2,
          affectedProcessCount: 1,
          affectedFileCount: 0,
          affectedNetworkCount: 1,
          affectedCredentialCount: 1,
          affectedToolCount: 0,
          developerBreakageScore: 72,
          impactLevel: "high",
          summary: "Would block captured graph.",
          affectedNodes: [],
        },
        graph: {
          nodes: {
            "process:proc-1": { kind: "process", label: "/usr/local/bin/npm" },
          },
          edges: [],
        },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "simulation" } } },
        },
      }),
    );

    const result = await createPolicyReplay({
      process: { processGuid: "proc-1" },
      action: "block",
      maxDepth: 8,
    });

    expect(result.replay.policy.policyEpoch).toBe(77);
    expect(result.simulation.ruleId).toContain("endpoint.current_policy_replay");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/policy-replay");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        process: { processGuid: "proc-1" },
        action: "block",
        maxDepth: 8,
      }),
    });
  });
});

describe("endpoint rule impact and staged enforcement helpers", () => {
  it("creates a detection candidate from a captured process graph", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        candidate: {
          ruleId: "endpoint.generated.block.process.npm",
          action: "block",
          description: "Block npm credential access",
          rootNodeId: "process:proc-1",
          rootLabel: "/usr/local/bin/npm",
          rootKind: "process",
          graphSliceId: "graph-slice-1",
        },
        recommendedStage: "audit",
        stagePlan: [
          {
            stage: "observe",
            action: "observe",
            promotionGate: "observe only",
            recommended: false,
          },
          { stage: "audit", action: "alert", promotionGate: "audit first", recommended: true },
        ],
        simulation: {
          simulationId: "simulation-1",
          ruleId: "endpoint.generated.block.process.npm",
          action: "block",
          rootNodeId: "process:proc-1",
          graphSliceId: "graph-slice-1",
          wouldBlock: true,
          createdAt: "2026-05-16T12:00:00Z",
          affectedNodeCount: 3,
          affectedEdgeCount: 2,
          affectedProcessCount: 1,
          affectedFileCount: 0,
          affectedNetworkCount: 1,
          affectedCredentialCount: 1,
          affectedToolCount: 0,
          developerBreakageScore: 72,
          impactLevel: "high",
          summary: "Would block captured graph.",
          affectedNodes: [],
        },
        graph: { nodes: {}, edges: [] },
        receipt: {
          receipt: { metadata: { endpointDecision: { receiptFamily: "simulation" } } },
        },
      }),
    );

    const result = await createDetectionCandidate({
      process: { processGuid: "proc-1" },
      action: "block",
      maxDepth: 8,
    });

    expect(result.recommendedStage).toBe("audit");
    expect(result.candidate.ruleId).toBe("endpoint.generated.block.process.npm");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/edr/detection-candidate");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        process: { processGuid: "proc-1" },
        action: "block",
        maxDepth: 8,
      }),
    });
  });

  it("stages a generated detection and promotes it to a dry-run policy delta apply", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse({
          path: "/tmp/staged-detections.jsonl",
          record: {
            stagedDetectionId: "staged-1",
            stagedAt: "2026-05-16T12:01:00Z",
            stagedBy: "operator:alice",
            stage: "audit",
            note: "stage npm rule",
            policy: {
              policyVersion: "test-edr",
              policyHash: "sha256:base",
              policyEpoch: 77,
            },
            candidate: {
              ruleId: "endpoint.generated.block.process.npm",
              action: "block",
              description: "Block npm credential access",
              rootNodeId: "process:proc-1",
              rootLabel: "/usr/local/bin/npm",
              rootKind: "process",
              graphSliceId: "graph-slice-1",
            },
            recommendedStage: "audit",
            stagePlan: [],
            simulation: {
              simulationId: "simulation-1",
              ruleId: "endpoint.generated.block.process.npm",
              action: "block",
              rootNodeId: "process:proc-1",
              graphSliceId: "graph-slice-1",
              wouldBlock: true,
              createdAt: "2026-05-16T12:00:00Z",
              affectedNodeCount: 3,
              affectedEdgeCount: 2,
              affectedProcessCount: 1,
              affectedFileCount: 0,
              affectedNetworkCount: 1,
              affectedCredentialCount: 1,
              affectedToolCount: 0,
              developerBreakageScore: 72,
              impactLevel: "high",
              summary: "Would block captured graph.",
              affectedNodes: [],
            },
            simulationReceipt: {
              receipt: { metadata: { endpointDecision: { receiptFamily: "simulation" } } },
            },
          },
          graph: { nodes: {}, edges: [] },
        }),
      )
      .mockReturnValueOnce(
        jsonResponse({
          path: "/tmp/policy-deltas",
          record: {
            policyDeltaId: "policy-delta-1",
            generatedAt: "2026-05-16T12:02:00Z",
            generatedBy: "operator:alice",
            ruleId: "endpoint.generated.block.process.npm",
            stage: "audit",
            action: "alert",
            artifactHash: "0xabc",
            artifactPath: "/tmp/policy-delta-1.json",
            artifact: {
              schemaVersion: "clawdstrike.endpoint_policy_delta.v1",
              policyDeltaId: "policy-delta-1",
              generatedAt: "2026-05-16T12:02:00Z",
              generatedBy: "operator:alice",
              stagedDetectionId: "staged-1",
              sourceSimulationId: "simulation-1",
              candidate: { ruleId: "endpoint.generated.block.process.npm" },
              targetPolicy: {
                basePolicyVersion: "test-edr",
                basePolicyHash: "sha256:base",
                basePolicyEpoch: 77,
                targetPolicyEpoch: 78,
              },
              rollout: {
                stage: "audit",
                action: "alert",
                recommendedStage: "audit",
                promotionGate: "audit first",
                developerBreakageScore: 72,
                impactLevel: "high",
                wouldBlock: true,
              },
              policyPatch: { guards: {} },
            },
            receipt: {
              receipt: { metadata: { endpointDecision: { receiptFamily: "policy_delta" } } },
            },
          },
        }),
      )
      .mockReturnValueOnce(
        jsonResponse({
          record: {
            policyDeltaId: "policy-delta-1",
            appliedAt: "2026-05-16T12:03:00Z",
            appliedBy: "operator:alice",
            dryRun: true,
            applied: false,
            allowBasePolicyDrift: false,
            policyPath: "/tmp/policy.yml",
            expectedBasePolicyHash: "sha256:base",
            previousPolicyHash: "sha256:base",
            newPolicyHash: "sha256:new",
            previousPolicyEpoch: 77,
            newPolicyEpoch: 78,
          },
          policyDelta: {
            policyDeltaId: "policy-delta-1",
            ruleId: "endpoint.generated.block.process.npm",
            stage: "audit",
            action: "alert",
            artifactHash: "0xabc",
            artifact: {
              targetPolicy: {
                basePolicyHash: "sha256:base",
                targetPolicyEpoch: 78,
              },
              rollout: { stage: "audit", action: "alert" },
            },
            receipt: {},
          },
          receipt: null,
          postApplyEnforcement: null,
        }),
      );

    const staged = await createStagedDetection({
      process: { processGuid: "proc-1" },
      selectedStage: "audit",
      stagedBy: "operator:alice",
      note: "stage npm rule",
      maxDepth: 8,
    });
    const delta = await createPolicyDelta({
      stagedDetectionId: staged.record.stagedDetectionId,
      generatedBy: "operator:alice",
      note: "promote staged rule",
    });
    const apply = await dryRunPolicyDeltaApply(delta.record.policyDeltaId, {
      appliedBy: "operator:alice",
    });
    const deltaReceipt = delta.record.receipt as {
      receipt: { metadata: { endpointDecision: { receiptFamily: string } } };
    };

    expect(staged.record.stagedDetectionId).toBe("staged-1");
    expect(deltaReceipt.receipt.metadata.endpointDecision.receiptFamily).toBe("policy_delta");
    expect(apply.record.dryRun).toBe(true);
    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/v1/agent/edr/staged-detections",
      "/api/v1/agent/edr/policy-deltas",
      "/api/v1/agent/edr/policy-deltas/policy-delta-1/apply",
    ]);
    expect(mockFetch.mock.calls[2][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ dryRun: true, appliedBy: "operator:alice" }),
    });
  });
});

describe("broker control-plane client helpers", () => {
  it("queries broker capabilities with filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ capabilities: [] }));

    await fetchBrokerCapabilities({ state: "active", provider: "github", limit: 25 });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v1/broker/capabilities");
    expect(url).toContain("state=active");
    expect(url).toContain("provider=github");
    expect(url).toContain("limit=25");
  });

  it("fetches a single broker capability detail envelope", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability: {
          capability_id: "cap-1",
          provider: "openai",
          state: "active",
          issued_at: "2026-03-12T00:00:00Z",
          expires_at: "2026-03-12T00:01:00Z",
          policy_hash: "hash-1",
          secret_ref_id: "openai/dev",
          url: "https://api.openai.com/v1/responses",
          method: "POST",
          execution_count: 0,
        },
        executions: [
          {
            execution_id: "exec-1",
            capability_id: "cap-1",
            provider: "openai",
            phase: "completed",
            executed_at: "2026-03-12T00:00:30Z",
            secret_ref_id: "openai/dev",
            url: "https://api.openai.com/v1/responses",
            method: "POST",
            bytes_sent: 12,
            bytes_received: 24,
          },
        ],
      }),
    );

    const result = await fetchBrokerCapability("cap-1");
    expect(result.capability.capability_id).toBe("cap-1");
    expect(result.executions).toHaveLength(1);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-1");
  });

  it("queries broker previews with filters and fetches a single preview", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse({
          previews: [
            {
              preview_id: "preview-1",
              provider: "github",
              operation: "issues.create",
              summary: "Create incident issue in production repo",
              created_at: "2026-03-12T00:00:00Z",
              risk_level: "high",
              data_classes: ["code", "secrets"],
              resources: [{ kind: "repo", value: "acme/api" }],
              egress_host: "api.github.com",
              approval_required: true,
              approval_state: "pending",
            },
          ],
        }),
      )
      .mockReturnValueOnce(
        jsonResponse({
          preview: {
            preview_id: "preview-1",
            provider: "github",
            operation: "issues.create",
            summary: "Create incident issue in production repo",
            created_at: "2026-03-12T00:00:00Z",
            risk_level: "high",
            data_classes: ["code", "secrets"],
            resources: [{ kind: "repo", value: "acme/api" }],
            egress_host: "api.github.com",
            approval_required: true,
            approval_state: "pending",
          },
        }),
      );

    const previews = await fetchBrokerPreviews({ provider: "github", limit: 10 });
    const preview = await fetchBrokerPreview("preview-1");

    expect(previews.previews).toHaveLength(1);
    expect(preview.preview.preview_id).toBe("preview-1");
    expect(mockFetch.mock.calls[0][0]).toContain("/api/v1/broker/previews");
    expect(mockFetch.mock.calls[0][0]).toContain("provider=github");
    expect(mockFetch.mock.calls[0][0]).toContain("limit=10");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/broker/previews/preview-1");
  });

  it("posts broker preview approval requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        preview: {
          preview_id: "preview-approve-1",
          provider: "slack",
          operation: "messages.post",
          summary: "Post incident update to on-call channel",
          created_at: "2026-03-12T00:00:00Z",
          risk_level: "medium",
          data_classes: ["incident_context"],
          resources: [{ kind: "channel", value: "#on-call" }],
          egress_host: "slack.com",
          approval_required: true,
          approval_state: "approved",
          approver: "operator@example.com",
          approved_at: "2026-03-12T00:01:00Z",
        },
      }),
    );

    const result = await approveBrokerPreview("preview-approve-1", "operator@example.com");
    expect(result.approval_state).toBe("approved");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/previews/preview-approve-1/approve");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).approver).toBe("operator@example.com");
  });

  it("posts capability revocation requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability: {
          capability_id: "cap-2",
          provider: "github",
          state: "revoked",
          issued_at: "2026-03-12T00:00:00Z",
          expires_at: "2026-03-12T00:01:00Z",
          policy_hash: "hash-2",
          secret_ref_id: "github/prod",
          url: "https://api.github.com/repos/acme/repo/issues",
          method: "POST",
          execution_count: 1,
        },
      }),
    );

    const result = await revokeBrokerCapability("cap-2", "panic revoke");
    expect(result.state).toBe("revoked");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-2/revoke");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).reason).toBe("panic revoke");
  });

  it("fetches and mutates provider freeze state", async () => {
    mockFetch
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [] }))
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [{ provider: "slack" }] }))
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [] }));

    await fetchFrozenBrokerProviders();
    await freezeBrokerProvider("slack", "incident response");
    await unfreezeBrokerProvider("slack");

    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/providers/freeze");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/broker/providers/slack/freeze");
    expect(mockFetch.mock.calls[1][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[1][1].body).reason).toBe("incident response");
    expect(mockFetch.mock.calls[2][1].method).toBe("DELETE");
  });

  it("posts broker replay requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability_id: "cap-3",
        current_policy_hash: "hash-3",
        current_state: "active",
        provider_frozen: false,
        egress_allowed: true,
        provider_allowed: true,
        policy_changed: true,
        approval_required: true,
        preview_still_approved: false,
        delegated_subject: "runtime:agent-7",
        minted_identity_kind: "github_app_installation",
        would_allow: true,
        reason: "current policy would still authorize this capability",
        diffs: [
          {
            field: "preview_approval",
            previous: "approved",
            current: "missing",
          },
        ],
      }),
    );

    const result = await replayBrokerCapability("cap-3");
    expect(result.would_allow).toBe(true);
    expect(result.policy_changed).toBe(true);
    expect(result.diffs?.[0]?.field).toBe("preview_approval");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-3/replay");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
  });

  it("exports completion bundles for a capability", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        envelope: "signed-bundle-envelope",
        bundle: {
          generated_at: "2026-03-12T00:02:00Z",
          capability: {
            capability_id: "cap-4",
            provider: "openai",
            state: "active",
            issued_at: "2026-03-12T00:00:00Z",
            expires_at: "2026-03-12T00:30:00Z",
            policy_hash: "hash-4",
            secret_ref_id: "openai/prod",
            url: "https://api.openai.com/v1/responses",
            method: "POST",
            execution_count: 2,
          },
          executions: [],
        },
      }),
    );

    const result = await exportBrokerCompletionBundle("cap-4");
    expect(result.envelope).toBe("signed-bundle-envelope");
    expect(result.bundle.capability.capability_id).toBe("cap-4");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-4/bundle");
    expect(mockFetch.mock.calls[0][1].headers["Content-Type"]).toBe("application/json");
  });

  it("posts panic revoke requests", async () => {
    mockFetch.mockReturnValue(jsonResponse({ revoked_count: 7 }));

    const result = await revokeAllBrokerCapabilities("incident drill");
    expect(result.revoked_count).toBe(7);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/revoke-all");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).reason).toBe("incident drill");
  });
});

describe("fetchAuditStats", () => {
  it("returns stats data on success", async () => {
    const data = { total_events: 100, violations: 5, allowed: 95, uptime_secs: 3600 };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchAuditStats();
    expect(result.total_events).toBe(100);
    expect(result.violations).toBe(5);
  });
});

describe("fetchPolicy", () => {
  it("returns policy data on success", async () => {
    const data = { name: "default", version: "1.0" };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchPolicy();
    expect(result.name).toBe("default");
  });
});

describe("fetchIntegrationSettings", () => {
  it("fetches from correct endpoint", async () => {
    const data = {
      siem: { provider: "datadog", endpoint: "", api_key: "", enabled: false },
      webhooks: { url: "", secret: "", enabled: false },
    };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchIntegrationSettings();
    expect(result.siem.provider).toBe("datadog");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/integrations");
  });
});

describe("saveIntegrationSettings", () => {
  it("sends PUT with body", async () => {
    const responseData = { integrations: {}, restarted: true };
    mockFetch.mockReturnValue(jsonResponse(responseData));

    await saveIntegrationSettings({ siem: { provider: "splunk" }, apply: true });

    expect(mockFetch.mock.calls[0][1].method).toBe("PUT");
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.siem.provider).toBe("splunk");
    expect(body.apply).toBe(true);
  });

  it("throws with response text on error", async () => {
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 400,
        text: () => Promise.resolve("bad request"),
      }),
    );
    await expect(saveIntegrationSettings({})).rejects.toThrow("bad request");
  });
});

describe("testIntegrationDelivery", () => {
  it("sends POST payload with target and retry count", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        target: "siem",
        endpoint: "https://collector.example",
        delivered: true,
        status_code: 200,
        attempts: 1,
        retry_count: 0,
        latency_ms: 42,
        tested_at: "2026-03-03T12:00:00Z",
      }),
    );

    const result = await testIntegrationDelivery("siem", 3);
    expect(result.target).toBe("siem");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/integrations/test");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.target).toBe("siem");
    expect(body.max_retries).toBe(3);
  });

  it("throws with response text on test failure", async () => {
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 502,
        text: () => Promise.resolve("upstream unavailable"),
      }),
    );
    await expect(testIntegrationDelivery("webhook")).rejects.toThrow("upstream unavailable");
  });
});

describe("auth header logic", () => {
  it("includes Authorization header when apiBase and apiKey are set", async () => {
    localStorage.setItem("hushd_url", "http://remote:9876");
    localStorage.setItem("hushd_api_key", "my-secret");
    mockFetch.mockReturnValue(jsonResponse({ status: "ok" }));

    await fetchHealth();

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer my-secret");
  });

  it("omits Authorization header when apiBase is empty", async () => {
    localStorage.setItem("hushd_api_key", "my-secret");
    mockFetch.mockReturnValue(jsonResponse({ status: "ok" }));

    await fetchHealth();

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBeUndefined();
  });
});
