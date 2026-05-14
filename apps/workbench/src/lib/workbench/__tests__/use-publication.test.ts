import "fake-indexeddb/auto";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
// Import policy adapter to trigger auto-registration
import "../detection-workflow/policy-adapter";
import { getAdapter, hasAdapter } from "../detection-workflow/adapters";
import { PublicationStore } from "../detection-workflow/publication-store";
import type { PublicationManifest, LabRun } from "../detection-workflow/shared-types";
import type { PublicationRequest, PublicationBuildResult } from "../detection-workflow/execution-types";
import { getAvailableTargets } from "../detection-workflow/use-publication";

// ---- SHA-256 helper (mirrors the one in use-publication.ts) ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Helpers ----

function makeManifest(overrides: Partial<PublicationManifest> = {}): PublicationManifest {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-pub-1",
    sourceFileType: "clawdstrike_policy",
    target: "native_policy",
    createdAt: new Date().toISOString(),
    sourceHash: "abc123",
    outputHash: "def456",
    validationSnapshot: { valid: true, diagnosticCount: 0 },
    runSnapshot: null,
    coverageSnapshot: null,
    converter: { id: "identity", version: "1.0.0" },
    signer: null,
    provenance: null,
    ...overrides,
  };
}

function makeLabRun(overrides: Partial<LabRun> = {}): LabRun {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-pub-1",
    evidencePackId: "pack-1",
    fileType: "clawdstrike_policy",
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    summary: {
      totalCases: 3,
      passed: 3,
      failed: 0,
      matched: 2,
      missed: 0,
      falsePositives: 0,
      engine: "client",
    },
    results: [],
    explainability: [],
    ...overrides,
  };
}

// ---- Gate computation helper (mirrors hook logic) ----

function computeGateStatus(
  validationPassed: boolean,
  labRunPassed: boolean | null,
): { gateOpen: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!validationPassed) reasons.push("Validation has errors");
  if (labRunPassed === false) reasons.push("Latest lab run has failures");
  const gateOpen = validationPassed && labRunPassed !== false;
  return { gateOpen, reasons };
}

// ---- Tests: publish creates and saves manifest ----

describe("Publication pipeline (adapter-level)", () => {
  it("publish creates and saves manifest via adapter", async () => {
    const adapter = getAdapter("clawdstrike_policy");
    expect(adapter).not.toBeNull();

    const source = `version: "1.5.0"\nname: Test\nguards:\n  shell_command:\n    enabled: true\nsettings: {}`;
    const sourceHash = await sha256Hex(source);

    const request: PublicationRequest = {
      document: {
        documentId: "doc-pub-test",
        fileType: "clawdstrike_policy",
        filePath: null,
        name: "Test Policy",
        sourceHash,
      },
      source,
      targetFormat: "native_policy",
    };

    const result = await adapter!.buildPublication(request);
    expect(result.manifest).toBeDefined();
    expect(result.manifest.documentId).toBe("doc-pub-test");
    expect(result.manifest.sourceFileType).toBe("clawdstrike_policy");
    expect(result.manifest.target).toBe("native_policy");
    expect(result.manifest.sourceHash).toBe(sourceHash);
    expect(result.outputContent).toBe(source);
    expect(result.outputHash).toBe(sourceHash); // identity converter

    // Save to store
    const store = new PublicationStore();
    await store.init();
    try {
      const manifest: PublicationManifest = {
        ...result.manifest,
        id: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
      };
      await store.saveManifest(manifest);

      const retrieved = await store.getManifest(manifest.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.sourceHash).toBe(sourceHash);
    } finally {
      store.close();
    }
  });

  it("publish fails if validation is invalid (gate logic)", async () => {
    // The hook enforces this gate, but we verify the logic here:
    // If validationValid is false, publish should be blocked.
    // We test the gate status computation directly.
    const { gateOpen, reasons } = computeGateStatus(false, true);

    expect(gateOpen).toBe(false);
    expect(reasons).toContain("Validation has errors");
  });
});

// ---- Tests: publishGateStatus reflects current state ----

describe("PublishGateStatus computation", () => {
  it("gateOpen is true when validation passes and no lab failures", () => {
    const { gateOpen } = computeGateStatus(true, true);
    expect(gateOpen).toBe(true);
  });

  it("gateOpen is true when validation passes and no lab run exists", () => {
    const { gateOpen } = computeGateStatus(true, null);
    expect(gateOpen).toBe(true);
  });

  it("gateOpen is false when lab run has failures", () => {
    const { gateOpen } = computeGateStatus(true, false);
    expect(gateOpen).toBe(false);
  });

  it("gateOpen is false when validation fails", () => {
    const { gateOpen } = computeGateStatus(false, true);
    expect(gateOpen).toBe(false);
  });

  it("labRunPassed reflects lab run failures", () => {
    const passingRun = makeLabRun({ summary: { totalCases: 2, passed: 2, failed: 0, matched: 1, missed: 0, falsePositives: 0, engine: "client" } });
    expect(passingRun.summary.failed === 0).toBe(true);

    const failingRun = makeLabRun({ summary: { totalCases: 2, passed: 1, failed: 1, matched: 0, missed: 1, falsePositives: 0, engine: "client" } });
    expect(failingRun.summary.failed === 0).toBe(false);
  });
});

// ---- Tests: canPublish is false for unregistered formats ----

describe("canPublish for file types", () => {
  it("canPublish is true for registered adapter (policy)", () => {
    expect(hasAdapter("clawdstrike_policy")).toBe(true);
  });

  it("canPublish is false for unregistered format (yara — no adapter)", () => {
    // Note: yara adapter is not auto-registered in this test context
    expect(hasAdapter("yara_rule")).toBe(false);
  });
});

// ---- Tests: publication history loads from store ----

describe("Publication history (store-level)", () => {
  let store: PublicationStore;

  beforeEach(async () => {
    store = new PublicationStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("loads manifests for a document in descending order", async () => {
    const m1 = makeManifest({ documentId: "doc-hist", createdAt: "2026-03-15T10:00:00.000Z" });
    const m2 = makeManifest({ documentId: "doc-hist", createdAt: "2026-03-15T11:00:00.000Z" });
    await store.saveManifest(m1);
    await store.saveManifest(m2);

    const manifests = await store.getManifestsForDocument("doc-hist");
    expect(manifests).toHaveLength(2);
    expect(manifests[0].id).toBe(m2.id); // newer first
  });

  it("getLatestManifest returns the most recent", async () => {
    const m1 = makeManifest({ documentId: "doc-latest", createdAt: "2026-03-15T09:00:00.000Z" });
    const m2 = makeManifest({ documentId: "doc-latest", createdAt: "2026-03-15T12:00:00.000Z" });
    await store.saveManifest(m1);
    await store.saveManifest(m2);

    const latest = await store.getLatestManifest("doc-latest");
    expect(latest).not.toBeNull();
    expect(latest!.id).toBe(m2.id);
  });
});

// ---- Tests: sourceHashChanged detects changes ----

describe("Source hash change detection", () => {
  it("detects when source hash differs from latest manifest", async () => {
    const originalSource = "version: '1.0.0'\nname: Original";
    const modifiedSource = "version: '1.0.0'\nname: Modified";

    const originalHash = await sha256Hex(originalSource);
    const modifiedHash = await sha256Hex(modifiedSource);

    expect(originalHash).not.toBe(modifiedHash);

    const manifest = makeManifest({ sourceHash: originalHash });

    // Simulating what the hook does: compare current source hash to manifest
    const currentHash = await sha256Hex(modifiedSource);
    const sourceHashChanged = currentHash !== manifest.sourceHash;

    expect(sourceHashChanged).toBe(true);
  });

  it("no change when source matches latest manifest", async () => {
    const source = "version: '1.0.0'\nname: Same";
    const hash = await sha256Hex(source);

    const manifest = makeManifest({ sourceHash: hash });
    const currentHash = await sha256Hex(source);
    const sourceHashChanged = currentHash !== manifest.sourceHash;

    expect(sourceHashChanged).toBe(false);
  });
});

// ---- Tests: available targets ----

describe("getAvailableTargets", () => {
  it("returns correct targets for clawdstrike_policy", () => {
    const targets = getAvailableTargets("clawdstrike_policy");
    expect(targets).toContain("native_policy");
    expect(targets).toContain("fleet_deploy");
    expect(targets).not.toContain("spl");
  });

  it("returns correct targets for sigma_rule", () => {
    const targets = getAvailableTargets("sigma_rule");
    expect(targets).toContain("native_policy");
    expect(targets).toContain("fleet_deploy");
    expect(targets).toContain("json_export");
    expect(targets).toContain("spl");
    expect(targets).toContain("kql");
    expect(targets).toContain("esql");
  });

  it("returns json_export for yara_rule", () => {
    const targets = getAvailableTargets("yara_rule");
    expect(targets).toEqual(["json_export"]);
  });

  it("returns json_export for ocsf_event", () => {
    const targets = getAvailableTargets("ocsf_event");
    expect(targets).toEqual(["json_export"]);
  });
});
