import { describe, it, expect, beforeEach } from "vitest";
import { useFindingStore } from "@/features/findings/stores/finding-store";
import type { Finding, Enrichment } from "@/lib/workbench/finding-engine";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

let findingSeq = 0;

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const id = `test-finding-${++findingSeq}`;
  const now = Date.now();
  return {
    id,
    title: "Test finding",
    status: "emerging",
    severity: "high",
    confidence: 0.8,
    signalIds: ["sig-1"],
    signalCount: 1,
    scope: {
      agentIds: ["agent-1"],
      sessionIds: ["session-1"],
      timeRange: {
        start: new Date(now).toISOString(),
        end: new Date(now).toISOString(),
      },
    },
    timeline: [
      {
        timestamp: now,
        type: "signal_added",
        summary: "Test signal added",
        actor: "test-actor",
      },
    ],
    enrichments: [],
    annotations: [],
    verdict: null,
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: "test-actor",
    updatedBy: "test-actor",
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function makeEnrichment(overrides: Partial<Enrichment> = {}): Enrichment {
  return {
    id: `enr-test-${Date.now()}`,
    type: "mitre_attack",
    label: "MITRE ATT&CK: test technique",
    data: { techniques: [] },
    addedAt: Date.now(),
    source: "test-source",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("finding-store", () => {
  beforeEach(() => {
    findingSeq = 0;
    useFindingStore.setState({ findings: [], activeFindingId: null });
  });

  it("confirm() updates finding status to confirmed", () => {
    const finding = makeFinding({ status: "emerging" });
    useFindingStore.setState({ findings: [finding], activeFindingId: finding.id });

    useFindingStore.getState().actions.confirm(finding.id, "analyst-1");

    const updated = useFindingStore.getState().findings[0];
    expect(updated).toBeDefined();
    expect(updated.status).toBe("confirmed");
    expect(updated.updatedBy).toBe("analyst-1");
  });

  it("dismiss() updates finding status to dismissed", () => {
    // dismiss is valid from "emerging" state
    const finding = makeFinding({ status: "emerging" });
    useFindingStore.setState({ findings: [finding], activeFindingId: finding.id });

    useFindingStore.getState().actions.dismiss(finding.id, "analyst-2", "Not actionable");

    const updated = useFindingStore.getState().findings[0];
    expect(updated).toBeDefined();
    expect(updated.status).toBe("dismissed");
    expect(updated.updatedBy).toBe("analyst-2");
  });

  it("load() replaces findings array and adjusts activeFindingId", () => {
    const f1 = makeFinding({ id: "f-1" });
    const f2 = makeFinding({ id: "f-2" });

    useFindingStore.getState().actions.load([f1, f2]);

    const state = useFindingStore.getState();
    expect(state.findings).toHaveLength(2);
    // activeFindingId should default to first finding when current active is not in list
    expect(state.activeFindingId).toBe("f-1");
  });

  it("archiveExpired() archives findings past TTL", () => {
    const oldTime = Date.now() - 2 * 24 * 60 * 60 * 1000; // 2 days ago
    const finding = makeFinding({
      status: "emerging",
      createdAt: oldTime,
    });
    useFindingStore.setState({ findings: [finding], activeFindingId: finding.id });

    // TTL of 1 day -- finding created 2 days ago should be archived
    useFindingStore.getState().actions.archiveExpired(24 * 60 * 60 * 1000);

    const updated = useFindingStore.getState().findings[0];
    expect(updated).toBeDefined();
    expect(updated.status).toBe("archived");
  });

  it("addEnrichment() adds enrichment to existing finding", () => {
    const finding = makeFinding();
    useFindingStore.setState({ findings: [finding], activeFindingId: finding.id });

    const enrichment = makeEnrichment();
    useFindingStore.getState().actions.addEnrichment(finding.id, enrichment, "enricher");

    const updated = useFindingStore.getState().findings[0];
    expect(updated).toBeDefined();
    expect(updated.enrichments).toHaveLength(1);
    expect(updated.enrichments[0].type).toBe("mitre_attack");
  });
});
