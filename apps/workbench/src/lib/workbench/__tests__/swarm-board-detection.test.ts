import { describe, expect, it, vi, beforeEach } from "vitest";

import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "../swarm-board-types";
import type {
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  PublicationManifest,
} from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";
import {
  createDetectionRuleNode,
  createEvidencePackNode,
  createLabRunNode,
  createPublicationNode,
  verifyPublishState,
  countDatasetItems,
} from "../detection-workflow/swarm-detection-nodes";
import {
  getSessionTemplates,
  getReviewTemplate,
  getPublishTemplate,
} from "../detection-workflow/swarm-session-templates";
import { linkReceiptToPublication } from "../detection-workflow/swarm-receipt-linking";

// ---------------------------------------------------------------------------
// Mock the publication store for verifyPublishState tests
// ---------------------------------------------------------------------------

const {
  mockGetManifest,
  mockGetOutputContent,
  mockInit,
  mockVerifyPublicationProvenance,
} = vi.hoisted(() => ({
  mockGetManifest: vi.fn(),
  mockGetOutputContent: vi.fn(),
  mockInit: vi.fn().mockResolvedValue(undefined),
  mockVerifyPublicationProvenance: vi.fn(),
}));

vi.mock("../detection-workflow/publication-store", () => ({
  getPublicationStore: () => ({
    init: mockInit,
    getManifest: mockGetManifest,
    getOutputContent: mockGetOutputContent,
  }),
  PublicationStore: vi.fn(),
}));

vi.mock("../detection-workflow/publication-provenance", () => ({
  verifyPublicationProvenance: mockVerifyPublicationProvenance,
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeDocRef(overrides?: Partial<DetectionDocumentRef>): DetectionDocumentRef {
  return {
    documentId: "doc-001",
    fileType: "sigma_rule",
    tabId: "tab-1",
    filePath: "/rules/test.yaml",
    name: "Test Sigma Rule",
    sourceHash: "sha256:abc123",
    ...overrides,
  };
}

function makeEvidencePack(overrides?: Partial<EvidencePack>): EvidencePack {
  return {
    id: "ep-001",
    documentId: "doc-001",
    fileType: "sigma_rule",
    title: "Test Evidence Pack",
    createdAt: "2026-03-15T10:00:00Z",
    datasets: {
      ...createEmptyDatasets(),
      positive: [
        {
          id: "item-1",
          kind: "structured_event",
          format: "json",
          payload: { CommandLine: "powershell.exe -enc" },
          expected: "match",
        },
      ],
      negative: [
        {
          id: "item-2",
          kind: "structured_event",
          format: "json",
          payload: { CommandLine: "notepad.exe" },
          expected: "no_match",
        },
      ],
    },
    redactionState: "clean",
    ...overrides,
  };
}

function makeLabRun(overrides?: Partial<LabRun>): LabRun {
  return {
    id: "lr-001",
    documentId: "doc-001",
    evidencePackId: "ep-001",
    fileType: "sigma_rule",
    startedAt: "2026-03-15T10:00:00Z",
    completedAt: "2026-03-15T10:00:01Z",
    summary: {
      totalCases: 10,
      passed: 8,
      failed: 2,
      matched: 6,
      missed: 1,
      falsePositives: 1,
      engine: "native",
    },
    results: [],
    explainability: [],
    ...overrides,
  };
}

function makeManifest(overrides?: Partial<PublicationManifest>): PublicationManifest {
  return {
    id: "pub-001",
    documentId: "doc-001",
    sourceFileType: "sigma_rule",
    target: "native_policy",
    createdAt: "2026-03-15T10:00:00Z",
    sourceHash: "a".repeat(64),
    outputHash: "31d48aa78a90ae82944d48a5f7f55e9a7c7a6ef8280b09c2f76262abace49e65",
    validationSnapshot: { valid: true, diagnosticCount: 0 },
    runSnapshot: {
      evidencePackId: "ep-001",
      labRunId: "lr-001",
      passed: true,
    },
    coverageSnapshot: null,
    converter: { id: "sigma-to-policy", version: "1.0.0" },
    signer: null,
    provenance: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// createDetectionRuleNode
// ---------------------------------------------------------------------------

describe("createDetectionRuleNode", () => {
  it("produces a valid node with correct metadata", () => {
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 100, y: 200 });

    expect(node.id).toBeDefined();
    expect(node.type).toBe("artifact");
    expect(node.position).toEqual({ x: 100, y: 200 });

    const data = node.data as SwarmBoardNodeData;
    expect(data.artifactKind).toBe("detection_rule");
    expect(data.documentId).toBe("doc-001");
    expect(data.format).toBe("sigma_rule");
    expect(data.title).toBe("Test Sigma Rule");
    expect(data.publishState).toBe("draft");
    expect(data.nodeType).toBe("artifact");
  });

  it("handles null filePath", () => {
    const doc = makeDocRef({ filePath: null });
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });

    const data = node.data as SwarmBoardNodeData;
    expect(data.filePath).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// createEvidencePackNode
// ---------------------------------------------------------------------------

describe("createEvidencePackNode", () => {
  it("produces a valid node with correct metadata", () => {
    const pack = makeEvidencePack();
    const node = createEvidencePackNode(pack, { x: 50, y: 100 });

    expect(node.id).toBeDefined();
    expect(node.type).toBe("artifact");

    const data = node.data as SwarmBoardNodeData;
    expect(data.artifactKind).toBe("evidence_pack");
    expect(data.documentId).toBe("doc-001");
    expect(data.evidencePackId).toBe("ep-001");
    expect(data.title).toBe("Test Evidence Pack");
    expect(data.format).toBe("sigma_rule");
  });
});

// ---------------------------------------------------------------------------
// createLabRunNode
// ---------------------------------------------------------------------------

describe("createLabRunNode", () => {
  it("produces a valid node with correct metadata", () => {
    const run = makeLabRun();
    const node = createLabRunNode(run, { x: 300, y: 400 });

    expect(node.id).toBeDefined();
    expect(node.type).toBe("artifact");

    const data = node.data as SwarmBoardNodeData;
    expect(data.artifactKind).toBe("lab_run");
    expect(data.documentId).toBe("doc-001");
    expect(data.labRunId).toBe("lr-001");
    expect(data.evidencePackId).toBe("ep-001");
    expect(data.format).toBe("sigma_rule");
    expect(data.title).toContain("8/10");
  });

  it("sets status to failed when there are failures", () => {
    const run = makeLabRun({ summary: { ...makeLabRun().summary, failed: 3 } });
    const node = createLabRunNode(run, { x: 0, y: 0 });
    const data = node.data as SwarmBoardNodeData;
    expect(data.status).toBe("failed");
  });

  it("sets status to completed when all pass", () => {
    const run = makeLabRun({ summary: { ...makeLabRun().summary, failed: 0 } });
    const node = createLabRunNode(run, { x: 0, y: 0 });
    const data = node.data as SwarmBoardNodeData;
    expect(data.status).toBe("completed");
  });
});

// ---------------------------------------------------------------------------
// createPublicationNode
// ---------------------------------------------------------------------------

describe("createPublicationNode", () => {
  it("produces a valid node with correct metadata", () => {
    const manifest = makeManifest();
    const node = createPublicationNode(manifest, { x: 200, y: 300 });

    expect(node.id).toBeDefined();
    expect(node.type).toBe("artifact");

    const data = node.data as SwarmBoardNodeData;
    expect(data.artifactKind).toBe("publication_manifest");
    expect(data.documentId).toBe("doc-001");
    expect(data.publicationId).toBe("pub-001");
    expect(data.format).toBe("sigma_rule");
    expect(data.publishState).toBe("published");
    expect(data.title).toContain("native_policy");
  });

  it("sets publishState to deployed when deployResponse is successful", () => {
    const manifest = makeManifest({
      deployResponse: { success: true, hash: "abc", destination: "fleet-1" },
    });
    const node = createPublicationNode(manifest, { x: 0, y: 0 });
    const data = node.data as SwarmBoardNodeData;
    expect(data.publishState).toBe("deployed");
  });

  it("sets publishState to published when deployResponse is unsuccessful", () => {
    const manifest = makeManifest({
      deployResponse: { success: false },
    });
    const node = createPublicationNode(manifest, { x: 0, y: 0 });
    const data = node.data as SwarmBoardNodeData;
    expect(data.publishState).toBe("published");
  });
});

// ---------------------------------------------------------------------------
// verifyPublishState
// ---------------------------------------------------------------------------

describe("verifyPublishState", () => {
  beforeEach(() => {
    mockGetManifest.mockReset();
    mockGetOutputContent.mockReset().mockResolvedValue("published output for tests");
    mockInit.mockReset().mockResolvedValue(undefined);
    mockVerifyPublicationProvenance.mockReset().mockResolvedValue({ valid: true });
  });

  it("accepts nodes in draft state", async () => {
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    const result = await verifyPublishState(node);
    expect(result.valid).toBe(true);
  });

  it("accepts nodes in validated state", async () => {
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "validated";
    const result = await verifyPublishState(node);
    expect(result.valid).toBe(true);
  });

  it("rejects published nodes without publicationId", async () => {
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "published";
    const result = await verifyPublishState(node);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("no publicationId");
  });

  it("rejects published nodes when manifest not found", async () => {
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "published";
    (node.data as SwarmBoardNodeData).publicationId = "pub-missing";
    mockGetManifest.mockResolvedValue(null);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("not found");
  });

  it("accepts published nodes with valid manifest", async () => {
    const manifest = makeManifest();
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "published";
    (node.data as SwarmBoardNodeData).publicationId = "pub-001";
    mockGetManifest.mockResolvedValue(manifest);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(true);
  });

  it("rejects deployed nodes without deployResponse", async () => {
    const manifest = makeManifest({ deployResponse: undefined });
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "deployed";
    (node.data as SwarmBoardNodeData).publicationId = "pub-001";
    mockGetManifest.mockResolvedValue(manifest);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("no deployResponse");
  });

  it("rejects deployed nodes with failed deployResponse", async () => {
    const manifest = makeManifest({ deployResponse: { success: false } });
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "deployed";
    (node.data as SwarmBoardNodeData).publicationId = "pub-001";
    mockGetManifest.mockResolvedValue(manifest);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("failure");
  });

  it("accepts deployed nodes with successful deployResponse", async () => {
    const manifest = makeManifest({
      deployResponse: { success: true, hash: "abc", destination: "fleet-1" },
    });
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "deployed";
    (node.data as SwarmBoardNodeData).publicationId = "pub-001";
    mockGetManifest.mockResolvedValue(manifest);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(true);
  });

  it("rejects published nodes when validation snapshot is invalid", async () => {
    const manifest = makeManifest({
      validationSnapshot: { valid: false, diagnosticCount: 3 },
    });
    const doc = makeDocRef();
    const node = createDetectionRuleNode(doc, { x: 0, y: 0 });
    (node.data as SwarmBoardNodeData).publishState = "published";
    (node.data as SwarmBoardNodeData).publicationId = "pub-001";
    mockGetManifest.mockResolvedValue(manifest);

    const result = await verifyPublishState(node);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("validation snapshot");
  });
});

// ---------------------------------------------------------------------------
// countDatasetItems
// ---------------------------------------------------------------------------

describe("countDatasetItems", () => {
  it("counts items across all datasets", () => {
    const pack = makeEvidencePack();
    const result = countDatasetItems(pack.datasets);
    expect(result.total).toBe(2);
    expect(result.byKind.positive).toBe(1);
    expect(result.byKind.negative).toBe(1);
    expect(result.byKind.regression).toBe(0);
    expect(result.byKind.false_positive).toBe(0);
  });

  it("handles empty datasets", () => {
    const datasets = createEmptyDatasets();
    const result = countDatasetItems(datasets);
    expect(result.total).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// getSessionTemplates
// ---------------------------------------------------------------------------

describe("getSessionTemplates", () => {
  it("returns templates for detection_rule artifact kind", () => {
    const templates = getSessionTemplates("detection_rule");
    expect(templates.length).toBeGreaterThan(0);

    // Should include review, harden, publish, and convert templates
    const kinds = new Set(templates.map((t) => t.kind));
    expect(kinds.has("review")).toBe(true);
    expect(kinds.has("harden")).toBe(true);
    expect(kinds.has("publish")).toBe(true);
    expect(kinds.has("convert")).toBe(true);
  });

  it("returns templates for evidence_pack artifact kind", () => {
    const templates = getSessionTemplates("evidence_pack");
    expect(templates.length).toBeGreaterThan(0);
    // Evidence packs are used by harden templates
    const kinds = new Set(templates.map((t) => t.kind));
    expect(kinds.has("harden")).toBe(true);
  });

  it("returns templates for lab_run artifact kind", () => {
    const templates = getSessionTemplates("lab_run");
    expect(templates.length).toBeGreaterThan(0);
  });

  it("returns templates for publication_manifest artifact kind", () => {
    const templates = getSessionTemplates("publication_manifest");
    expect(templates.length).toBeGreaterThan(0);
    const kinds = new Set(templates.map((t) => t.kind));
    expect(kinds.has("publish")).toBe(true);
  });

  it("returns templates for conversion_output artifact kind", () => {
    const templates = getSessionTemplates("conversion_output");
    expect(templates.length).toBeGreaterThan(0);
    const kinds = new Set(templates.map((t) => t.kind));
    expect(kinds.has("convert")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getReviewTemplate
// ---------------------------------------------------------------------------

describe("getReviewTemplate", () => {
  it("returns a review template for sigma_rule", () => {
    const template = getReviewTemplate("sigma_rule");
    expect(template.kind).toBe("review");
    expect(template.name).toContain("Sigma");
    expect(template.id).toBe("review-sigma_rule");
    expect(template.commands.length).toBeGreaterThan(0);
  });

  it("returns format-specific template for yara_rule", () => {
    const template = getReviewTemplate("yara_rule");
    expect(template.name).toContain("YARA");
    expect(template.id).toBe("review-yara_rule");
  });

  it("returns format-specific template for clawdstrike_policy", () => {
    const template = getReviewTemplate("clawdstrike_policy");
    expect(template.name).toContain("Policy");
    expect(template.id).toBe("review-clawdstrike_policy");
  });

  it("returns format-specific template for ocsf_event", () => {
    const template = getReviewTemplate("ocsf_event");
    expect(template.name).toContain("OCSF");
    expect(template.id).toBe("review-ocsf_event");
  });
});

// ---------------------------------------------------------------------------
// getPublishTemplate
// ---------------------------------------------------------------------------

describe("getPublishTemplate", () => {
  it("returns a publish template for sigma_rule", () => {
    const template = getPublishTemplate("sigma_rule");
    expect(template.kind).toBe("publish");
    expect(template.name).toContain("Sigma");
    expect(template.commands.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// linkReceiptToPublication
// ---------------------------------------------------------------------------

describe("linkReceiptToPublication", () => {
  it("creates an edge between receipt and publication nodes", async () => {
    const receiptNode = {
      id: "receipt-1",
      data: { title: "Receipt", nodeType: "receipt", status: "completed" as const } as SwarmBoardNodeData,
    };
    const pubNode = {
      id: "pub-1",
      data: {
        title: "Publish",
        nodeType: "artifact",
        status: "idle" as const,
        artifactKind: "publication_manifest" as const,
        publicationId: "pub-001",
        publishState: "validated" as const,
      } as SwarmBoardNodeData,
    };

    const addEdge = vi.fn();
    const updateNode = vi.fn();
    const store = {
      state: {
        nodes: [receiptNode, pubNode],
        edges: [],
      },
      addEdge,
      updateNode,
    };

    await linkReceiptToPublication(store, "receipt-1", "pub-1");

    expect(addEdge).toHaveBeenCalledOnce();
    const edgeArg = addEdge.mock.calls[0][0];
    expect(edgeArg.source).toBe("receipt-1");
    expect(edgeArg.target).toBe("pub-1");
    expect(edgeArg.type).toBe("receipt");
  });

  it("throws if receipt node not found", async () => {
    const store = {
      state: { nodes: [], edges: [] },
      addEdge: vi.fn(),
      updateNode: vi.fn(),
    };

    await expect(
      linkReceiptToPublication(store, "missing", "pub-1"),
    ).rejects.toThrow("not found");
  });

  it("throws if publication node not found", async () => {
    const receiptNode = {
      id: "receipt-1",
      data: { title: "Receipt", nodeType: "receipt", status: "completed" as const } as SwarmBoardNodeData,
    };
    const store = {
      state: { nodes: [receiptNode], edges: [] },
      addEdge: vi.fn(),
      updateNode: vi.fn(),
    };

    await expect(
      linkReceiptToPublication(store, "receipt-1", "missing"),
    ).rejects.toThrow("not found");
  });

  it("updates publishState after successful verification", async () => {
    const receiptNode = {
      id: "receipt-1",
      data: { title: "Receipt", nodeType: "receipt", status: "completed" as const } as SwarmBoardNodeData,
    };
    const pubNode = {
      id: "pub-1",
      data: {
        title: "Publish",
        nodeType: "artifact",
        status: "idle" as const,
        artifactKind: "publication_manifest" as const,
        publicationId: "pub-001",
        publishState: "validated" as const,
      } as SwarmBoardNodeData,
    };

    const updateNode = vi.fn();
    const store = {
      state: { nodes: [receiptNode, pubNode], edges: [] },
      addEdge: vi.fn(),
      updateNode,
    };

    const mockVerify = vi.fn().mockResolvedValue({ valid: true });

    await linkReceiptToPublication(store, "receipt-1", "pub-1", mockVerify);

    expect(updateNode).toHaveBeenCalledWith("pub-1", { publishState: "published" });
  });

  it("does not update publishState when verification fails", async () => {
    const receiptNode = {
      id: "receipt-1",
      data: { title: "Receipt", nodeType: "receipt", status: "completed" as const } as SwarmBoardNodeData,
    };
    const pubNode = {
      id: "pub-1",
      data: {
        title: "Publish",
        nodeType: "artifact",
        status: "idle" as const,
        artifactKind: "publication_manifest" as const,
        publicationId: "pub-001",
        publishState: "validated" as const,
      } as SwarmBoardNodeData,
    };

    const updateNode = vi.fn();
    const store = {
      state: { nodes: [receiptNode, pubNode], edges: [] },
      addEdge: vi.fn(),
      updateNode,
    };

    const mockVerify = vi.fn().mockResolvedValue({
      valid: false,
      reason: "missing manifest",
    });

    await linkReceiptToPublication(store, "receipt-1", "pub-1", mockVerify);

    // Edge should still be created
    expect(store.addEdge).toHaveBeenCalledOnce();
    // But publishState should NOT be updated
    expect(updateNode).not.toHaveBeenCalled();
  });
});
