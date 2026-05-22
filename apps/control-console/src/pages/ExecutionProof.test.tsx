import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchResponseExecutionProof,
  fetchResponseExecutions,
  type ResponseExecutionProofResponse,
  type ResponseExecutionsResponse,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { verifyReceipt } from "../utils/receiptVerify";
import { ExecutionProof } from "./ExecutionProof";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    fetchResponseExecutionProof: vi.fn(),
    fetchResponseExecutions: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

vi.mock("../utils/receiptVerify", () => ({
  verifyReceipt: vi.fn(),
}));

const executionsPayload: ResponseExecutionsResponse = {
  path: "/tmp/response-executions.jsonl",
  execution_count: 1,
  executions: [
    {
      execution: {
        executionId: "exec-1",
        actionId: "action-1",
        action: "collect_evidence",
        status: "succeeded",
        completedAt: "2026-05-16T12:00:00Z",
        ttlSeconds: 600,
        evidenceBundle: {
          bundleId: "bundle-1",
          graphSliceId: "graph-1",
          contentHash: "0xabc",
          nodeCount: 4,
          edgeCount: 3,
        },
        actor: {
          userId: "operator:test",
          sessionId: "session-1",
          agentId: "agent-api:test",
        },
      },
      expiresAt: "2026-05-16T12:10:00Z",
      expired: false,
      rollbackRef: "rollback:exec-1",
    },
  ],
};

const proofPayload: ResponseExecutionProofResponse = {
  executionPath: "/tmp/response-executions.jsonl",
  receiptPath: "/tmp/decision-receipts.jsonl",
  execution: executionsPayload.executions[0],
  graph: {
    graphSliceId: "graph-1",
    rootNodeId: "proc-1",
    nodeCount: 4,
    edgeCount: 3,
    contentHash: "0xgraph",
  },
  affectedIdentityCount: 6,
  affectedToolCount: 1,
  affectedIdentities: {
    hosts: [{ nodeId: "proc-1", label: "host-proof-1", id: "host-proof-1" }],
    users: [{ nodeId: "proc-1", label: "alice", id: "alice" }],
    sessions: [{ nodeId: "proc-1", label: "session-proof-1", id: "session-proof-1" }],
    agents: [{ nodeId: "proc-1", label: "agent-proof-1", id: "agent-proof-1" }],
    workloads: [{ nodeId: "proc-1", label: "workload-proof-1", id: "workload-proof-1" }],
    approvals: [{ nodeId: "proc-1", label: "approval-proof-1", id: "approval-proof-1" }],
  },
  affectedTools: [{ nodeId: "tool:mcp.shell", label: "mcp.shell", toolName: "mcp.shell" }],
  providerState: {
    providers: [
      { providerId: "agent-api", healthy: true, active: true },
      { providerId: "macos.endpoint_security", healthy: true, active: true },
      { providerId: "macos.network_extension", healthy: false, active: true },
    ],
  },
  requestReceipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "response_request",
          signer: { signerPublicKey: "11".repeat(32) },
          actor: {
            userId: "operator:test",
            sessionId: "session-1",
            agentId: "agent-api:test",
          },
          decision: { findingId: "action-1", action: "collect_evidence" },
          graph: { graphSliceId: "graph-1" },
          evidence: [
            {
              key: "responseActionId",
              valueHash: "0xbf0a9567032309b7baa0f4bd90dc12357f538dfe9ef120e5abd45d4c9b9039d6",
            },
            {
              key: "graphSliceId",
              valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
            },
            {
              key: "actorHash",
              valueHash: "0x46bebdb982b68e7c24e64bc10bfcc6e72a48698d82bcd366f99ab147ffe8d45b",
            },
          ],
        },
      },
    },
  },
  executionReceipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "response_execution",
          signer: { signerPublicKey: "11".repeat(32) },
          policy: { policyEpoch: 42 },
          actor: {
            userId: "operator:test",
            sessionId: "session-1",
            agentId: "agent-api:test",
          },
          decision: { findingId: "exec-1", action: "collect_evidence" },
          graph: { graphSliceId: "graph-1" },
          evidence: [
            {
              key: "responseActionId",
              valueHash: "0xbf0a9567032309b7baa0f4bd90dc12357f538dfe9ef120e5abd45d4c9b9039d6",
            },
            {
              key: "executionId",
              valueHash: "0xf42b7a9069c383bbfa5b0a4b3c29d4ebbc393a6d037f7e5be00a358d4f16e417",
            },
            {
              key: "evidenceBundleId",
              valueHash: "0x93db9dc111b649382b9b8914e26d78c6af16c78e0d0a588bd9198b7533e307a7",
            },
            {
              key: "graphSliceId",
              valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
            },
            {
              key: "actorHash",
              valueHash: "0x46bebdb982b68e7c24e64bc10bfcc6e72a48698d82bcd366f99ab147ffe8d45b",
            },
            {
              key: "executionActorHash",
              valueHash: "0x46bebdb982b68e7c24e64bc10bfcc6e72a48698d82bcd366f99ab147ffe8d45b",
            },
          ],
        },
      },
    },
  },
  evidenceBundleReceipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "evidence_bundle_manifest",
          signer: { signerPublicKey: "11".repeat(32) },
          decision: { findingId: "bundle-1", action: "collect_evidence" },
          graph: { graphSliceId: "graph-1" },
          evidence: [
            {
              key: "evidenceBundleId",
              valueHash: "0x93db9dc111b649382b9b8914e26d78c6af16c78e0d0a588bd9198b7533e307a7",
            },
            {
              key: "graphSliceId",
              valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
            },
            {
              key: "contentHash",
              valueHash: "0xeb4b9e8905923468a20ce3dc86bcdefef67f743a8156f44ca52e548e62e2c8f0",
            },
            {
              key: "nodeCount",
              valueHash: "0x4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            },
            {
              key: "edgeCount",
              valueHash: "0x4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
            },
          ],
        },
      },
    },
  },
};

const lifecycleProofPayload: ResponseExecutionProofResponse = {
  ...proofPayload,
  transitionReceipts: [
    {
      receipt: {
        receipt_id: "expired-receipt-1",
        metadata: {
          endpointDecision: {
            receiptFamily: "response_execution",
            signer: { signerPublicKey: "11".repeat(32) },
            policy: { policyEpoch: 42 },
            actor: {
              userId: "operator:test",
              sessionId: "session-1",
              agentId: "agent-api:test",
            },
            decision: {
              findingId: "response_execution_expired:1",
              action: "collect_evidence",
              title: "Endpoint response action expired",
              rollbackRef: "rollback:exec-1",
            },
            graph: { graphSliceId: "graph-1" },
            evidence: [
              {
                key: "responseActionId",
                valueHash: "0xbf0a9567032309b7baa0f4bd90dc12357f538dfe9ef120e5abd45d4c9b9039d6",
              },
              {
                key: "graphSliceId",
                valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
              },
              {
                key: "rollbackRef",
                valueHash: "0x512c6f9d51ecb9c9f791afc1c6f731ccc90f26ddf845d3dfef075f21d0770200",
              },
              {
                key: "executionStatus",
                valueHash: "0xfa64ea1e82e1206f828ab2a02917c7e92accb98e3b95881a1b4ad52b914b66e3",
              },
              {
                key: "actorHash",
                valueHash: "0x46bebdb982b68e7c24e64bc10bfcc6e72a48698d82bcd366f99ab147ffe8d45b",
              },
              {
                key: "executionActorHash",
                valueHash: "0x46bebdb982b68e7c24e64bc10bfcc6e72a48698d82bcd366f99ab147ffe8d45b",
              },
            ],
          },
        },
      },
    },
  ],
  rollbackReceipts: [
    {
      receipt: {
        receipt_id: "rollback-receipt-1",
        metadata: {
          endpointDecision: {
            receiptFamily: "response_rollback",
            signer: { signerPublicKey: "11".repeat(32) },
            policy: { policyEpoch: 42 },
            decision: {
              findingId: "response_rollback:1",
              action: "collect_evidence",
              title: "Endpoint response rollback executed",
              rollbackRef: "rollback:exec-1",
            },
            graph: { graphSliceId: "graph-1" },
            evidence: [
              {
                key: "responseActionId",
                valueHash: "0xbf0a9567032309b7baa0f4bd90dc12357f538dfe9ef120e5abd45d4c9b9039d6",
              },
              {
                key: "executionId",
                valueHash: "0xf42b7a9069c383bbfa5b0a4b3c29d4ebbc393a6d037f7e5be00a358d4f16e417",
              },
              {
                key: "graphSliceId",
                valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
              },
              {
                key: "rollbackRef",
                valueHash: "0x512c6f9d51ecb9c9f791afc1c6f731ccc90f26ddf845d3dfef075f21d0770200",
              },
            ],
          },
        },
      },
    },
  ],
  acknowledgementReceipts: [
    {
      receipt: {
        receipt_id: "acknowledgement-receipt-1",
        metadata: {
          endpointDecision: {
            receiptFamily: "response_acknowledgement",
            signer: { signerPublicKey: "11".repeat(32) },
            policy: { policyEpoch: 42 },
            actor: { agentId: "operator:test" },
            decision: {
              findingId: "ack-1",
              action: "collect_evidence",
              title: "Endpoint response execution acknowledged: succeeded",
              rollbackRef: "rollback:exec-1",
            },
            graph: { graphSliceId: "graph-1" },
            evidence: [
              {
                key: "acknowledgementId",
                valueHash: "0xa5213bae59cb90a6a964a446d6d56ab2e2c8e8fd7921594c265bd129cfca6eeb",
              },
              {
                key: "responseActionId",
                valueHash: "0xbf0a9567032309b7baa0f4bd90dc12357f538dfe9ef120e5abd45d4c9b9039d6",
              },
              {
                key: "executionId",
                valueHash: "0xf42b7a9069c383bbfa5b0a4b3c29d4ebbc393a6d037f7e5be00a358d4f16e417",
              },
              {
                key: "graphSliceId",
                valueHash: "0x2039ad4d2c9511f91337c2f1335a564efe0e8dafebd929c99e321e346b890845",
              },
              {
                key: "rollbackRef",
                valueHash: "0x512c6f9d51ecb9c9f791afc1c6f731ccc90f26ddf845d3dfef075f21d0770200",
              },
              {
                key: "acknowledgedBy",
                valueHash: "0x01d3ecfbe70b502943c658beabc203e15752cc820534118d1b0ecef0755edfd0",
              },
            ],
          },
        },
      },
    },
  ],
};

describe("ExecutionProof", () => {
  beforeEach(() => {
    vi.mocked(fetchResponseExecutions).mockReset();
    vi.mocked(fetchResponseExecutionProof).mockReset();
    vi.mocked(exportAsJSON).mockReset();
    vi.mocked(verifyReceipt).mockReset();
  });

  it("loads recent executions and renders proof state for the selected execution", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(proofPayload);

    render(<ExecutionProof />);

    expect(await screen.findByText("exec-1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /load proof for exec-1/i }));

    await waitFor(() => {
      expect(fetchResponseExecutionProof).toHaveBeenCalledWith("exec-1");
    });
    expect(await screen.findByText("response_execution")).toBeTruthy();
    expect(screen.getByText("macos.endpoint_security")).toBeTruthy();
    expect(screen.getByText("macos.network_extension")).toBeTruthy();
    expect(screen.getByText("graph-1")).toBeTruthy();
    expect(screen.getByText("Host: host-proof-1")).toBeTruthy();
    expect(screen.getByText("User: alice")).toBeTruthy();
    expect(screen.getByText("Session: session-proof-1")).toBeTruthy();
    expect(screen.getByText("mcp.shell")).toBeTruthy();
    expect(screen.getByText("epoch:42")).toBeTruthy();
    expect(screen.getByText("Request action ID match")).toBeTruthy();
    expect(screen.getByText("Execution ID match")).toBeTruthy();
    expect(screen.getByText("Bundle ID match")).toBeTruthy();
    expect(await screen.findByText("Request action hash match")).toBeTruthy();
    expect(screen.getByText("Execution ID hash match")).toBeTruthy();
    expect(screen.getByText("Bundle content hash match")).toBeTruthy();
    expect(screen.getByText("Bundle node count hash match")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Proof" }));
    expect(exportAsJSON).toHaveBeenCalledWith([proofPayload], "execution-proof-exec-1");
  });

  it("distinguishes healthy stale missing and degraded provider states", async () => {
    const providerStateProof: ResponseExecutionProofResponse = {
      ...proofPayload,
      providerState: {
        providers: [
          {
            providerId: "agent-api",
            installed: true,
            active: true,
            healthy: true,
            degraded: false,
          },
          {
            providerId: "darwin-bridge",
            installed: true,
            active: true,
            healthy: true,
            degraded: false,
            stale: true,
            lastSeen: "2000-01-01T00:00:00Z",
          },
          {
            providerId: "macos.endpoint_security",
            installed: false,
            active: false,
            healthy: false,
            degraded: true,
            degradationReasons: ["system extension not installed"],
          },
          {
            providerId: "macos.network_extension",
            installed: true,
            active: true,
            healthy: false,
            degraded: true,
            degradationReasons: ["policy sync missing"],
          },
        ],
      },
    };
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(providerStateProof);

    render(<ExecutionProof />);

    fireEvent.click(await screen.findByRole("button", { name: /load proof for exec-1/i }));

    expect(await screen.findByText("HEALTHY")).toBeTruthy();
    expect(screen.getByText("STALE")).toBeTruthy();
    expect(screen.getByText("MISSING")).toBeTruthy();
    expect(screen.getByText("DEGRADED")).toBeTruthy();
    expect(screen.getByText("system extension not installed")).toBeTruthy();
    expect(screen.getByText("policy sync missing")).toBeTruthy();
  });

  it("verifies the displayed receipt chain", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(proofPayload);
    vi.mocked(verifyReceipt)
      .mockResolvedValueOnce({ valid: true })
      .mockResolvedValueOnce({ valid: true })
      .mockResolvedValueOnce({ valid: false, error: "Invalid signer signature" });

    render(<ExecutionProof />);

    fireEvent.click(await screen.findByRole("button", { name: /load proof for exec-1/i }));
    await screen.findByText("response_execution");

    fireEvent.click(screen.getByRole("button", { name: "Verify Chain" }));

    await waitFor(() => {
      expect(verifyReceipt).toHaveBeenCalledTimes(3);
    });
    expect(await screen.findByText("Request verified")).toBeTruthy();
    expect(screen.getByText("Execution verified")).toBeTruthy();
    expect(screen.getByText("Evidence Bundle failed: Invalid signer signature")).toBeTruthy();
  });

  it("renders and verifies terminal transition, rollback, and acknowledgement receipts", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(lifecycleProofPayload);
    vi.mocked(verifyReceipt).mockResolvedValue({ valid: true });

    render(<ExecutionProof />);

    fireEvent.click(await screen.findByRole("button", { name: /load proof for exec-1/i }));

    expect(await screen.findByText("Transition 1")).toBeTruthy();
    expect(screen.getByText("Rollback 1")).toBeTruthy();
    expect(screen.getByText("Acknowledgement 1")).toBeTruthy();
    expect(screen.getByText("response_rollback")).toBeTruthy();
    expect(screen.getByText("response_acknowledgement")).toBeTruthy();
    expect(screen.getByText("Transition action type match")).toBeTruthy();
    expect(screen.getByText("Rollback rollback ref match")).toBeTruthy();
    expect(screen.getByText("Acknowledgement action type match")).toBeTruthy();
    expect(screen.getByText("Response actor identity match")).toBeTruthy();
    expect(screen.getByText("Response actor hash continuity match")).toBeTruthy();
    expect(screen.getByText("Transition actor hash continuity match")).toBeTruthy();
    expect(await screen.findByText("Transition 1 rollback hash match")).toBeTruthy();
    expect(screen.getByText("Rollback 1 execution hash match")).toBeTruthy();
    expect(screen.getByText("Acknowledgement 1 execution hash match")).toBeTruthy();
    expect(screen.getByText("Acknowledgement 1 acknowledged-by hash match")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Verify Chain" }));

    await waitFor(() => {
      expect(verifyReceipt).toHaveBeenCalledTimes(6);
    });
    expect(await screen.findByText("Transition 1 verified")).toBeTruthy();
    expect(screen.getByText("Rollback 1 verified")).toBeTruthy();
    expect(screen.getByText("Acknowledgement 1 verified")).toBeTruthy();
  });

  it("flags proof chains with mixed receipt signers", async () => {
    const mixedSignerProofPayload: ResponseExecutionProofResponse = JSON.parse(
      JSON.stringify(lifecycleProofPayload),
    );
    const rollbackReceipt = mixedSignerProofPayload.rollbackReceipts?.[0].receipt as {
      metadata: {
        endpointDecision: {
          signer: {
            signerPublicKey: string;
          };
        };
      };
    };
    rollbackReceipt.metadata.endpointDecision.signer.signerPublicKey = "22".repeat(32);
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(mixedSignerProofPayload);
    vi.mocked(verifyReceipt).mockResolvedValue({ valid: true });

    render(<ExecutionProof />);

    fireEvent.click(await screen.findByRole("button", { name: /load proof for exec-1/i }));

    expect(await screen.findByText("Receipt signer continuity mismatch")).toBeTruthy();
  });

  it("exports a unified verification verdict for incident handoff", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(proofPayload);
    vi.mocked(verifyReceipt)
      .mockResolvedValueOnce({ valid: true })
      .mockResolvedValueOnce({ valid: true })
      .mockResolvedValueOnce({ valid: false, error: "Invalid signer signature" });

    render(<ExecutionProof />);

    fireEvent.click(await screen.findByRole("button", { name: /load proof for exec-1/i }));
    await screen.findByText("response_execution");
    await screen.findByText("Bundle content hash match");

    fireEvent.click(screen.getByRole("button", { name: "Verify Chain" }));
    await screen.findByText("Evidence Bundle failed: Invalid signer signature");

    fireEvent.click(screen.getByRole("button", { name: "Export Verdict" }));

    expect(exportAsJSON).toHaveBeenCalledWith(
      [
        expect.objectContaining({
          kind: "clawdstrike.execution_proof.verdict.v1",
          executionId: "exec-1",
          actionId: "action-1",
          action: "collect_evidence",
          status: "succeeded",
          proof: expect.objectContaining({
            graphSliceId: "graph-1",
            affectedIdentityCount: 6,
            affectedToolCount: 1,
            affectedIdentities: proofPayload.affectedIdentities,
            affectedTools: proofPayload.affectedTools,
          }),
          signatures: [
            { receipt: "requestReceipt", label: "Request", status: "valid" },
            { receipt: "executionReceipt", label: "Execution", status: "valid" },
            {
              receipt: "evidenceBundleReceipt",
              label: "Evidence Bundle",
              status: "invalid",
              error: "Invalid signer signature",
            },
          ],
          correlations: expect.arrayContaining([
            expect.objectContaining({ label: "Request action ID", passed: true }),
            expect.objectContaining({ label: "Graph slice", passed: true }),
          ]),
          evidenceHashes: expect.arrayContaining([
            expect.objectContaining({ label: "Request action hash", passed: true }),
            expect.objectContaining({ label: "Bundle content hash", passed: true }),
          ]),
        }),
      ],
      "execution-proof-verdict-exec-1",
    );
  });

  it("fetches proof for a manually entered execution id", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue({ execution_count: 0, executions: [] });
    vi.mocked(fetchResponseExecutionProof).mockResolvedValue(proofPayload);

    render(<ExecutionProof />);

    fireEvent.change(screen.getByLabelText("Execution ID"), {
      target: { value: "manual-exec-9" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Fetch Proof" }));

    await waitFor(() => {
      expect(fetchResponseExecutionProof).toHaveBeenCalledWith("manual-exec-9");
    });
  });
});
