import { describe, expect, it, vi } from "vitest";

// Mock @react-three/fiber so R3F hooks are no-ops in unit tests
vi.mock("@react-three/fiber", () => ({ useFrame: vi.fn() }));

// ─── getThreatDistricts ───────────────────────────────────────────────────────
import { getThreatDistricts } from "../components/ThreatPresetOverlay";
import type { ObservatoryDistrictRecipe } from "../world/deriveObservatoryWorld";

function makeDistrict(
  id: string,
  active: boolean,
  artifactCount: number,
): ObservatoryDistrictRecipe {
  return {
    id: id as any,
    colorHex: "#ffffff",
    position: [0, 0, 0],
    active,
    likely: false,
    artifactCount,
    emphasis: 0,
    label: id,
    baseDiscRadius: 8,
    outerRingInnerRadius: 9,
    outerRingOuterRadius: 11,
    torusRadius: 4.5,
    torusTubeRadius: 0.22,
    floatAmplitude: 0.12,
    pulseSpeed: 0.0018,
    microInteraction: "sweep",
    growthAnchors: [],
  } as unknown as ObservatoryDistrictRecipe;
}

describe("getThreatDistricts", () => {
  it("returns empty array for empty input", () => {
    expect(getThreatDistricts([])).toEqual([]);
  });

  it("excludes district with active=false and artifactCount=2", () => {
    const result = getThreatDistricts([makeDistrict("signal", false, 2)]);
    expect(result).toHaveLength(0);
  });

  it("includes district with active=true and artifactCount=0", () => {
    const result = getThreatDistricts([makeDistrict("signal", true, 0)]);
    expect(result).toHaveLength(1);
  });

  it("includes district with active=false and artifactCount=3", () => {
    const result = getThreatDistricts([makeDistrict("signal", false, 3)]);
    expect(result).toHaveLength(1);
  });

  it("includes district with active=true and artifactCount=5", () => {
    const result = getThreatDistricts([makeDistrict("targets", true, 5)]);
    expect(result).toHaveLength(1);
  });

  it("filters a mixed list correctly", () => {
    const districts = [
      makeDistrict("signal", true, 0),    // included (active)
      makeDistrict("targets", false, 2),  // excluded (not active, count<3)
      makeDistrict("run", false, 3),      // included (count>=3)
      makeDistrict("receipts", false, 0), // excluded
    ];
    const result = getThreatDistricts(districts);
    expect(result).toHaveLength(2);
    expect(result.map((d) => d.id)).toContain("signal");
    expect(result.map((d) => d.id)).toContain("run");
  });
});

// ─── getEvidenceStationIds ────────────────────────────────────────────────────
import { getEvidenceStationIds } from "../components/EvidencePresetOverlay";
import type { ObservatoryGhostTrace } from "../world/observatory-ghost-memory";

function makeTrace(
  id: string,
  stationId: string,
  sourceKind: "finding" | "receipt",
  headline = "Test headline",
  detail = "Test detail",
  score = 1.0,
): ObservatoryGhostTrace {
  return {
    id,
    stationId: stationId as any,
    route: "/test",
    routeLabel: "Test",
    sourceKind,
    sourceId: id,
    authorLabel: "agent",
    headline,
    detail,
    timestampMs: 0,
    score,
  };
}

describe("getEvidenceStationIds", () => {
  it("returns empty array for empty input", () => {
    expect(getEvidenceStationIds([])).toEqual([]);
  });

  it("returns empty array when only finding traces exist", () => {
    const traces = [makeTrace("f1", "signal", "finding")];
    expect(getEvidenceStationIds(traces)).toEqual([]);
  });

  it("returns unique stationIds from receipt traces", () => {
    const traces = [
      makeTrace("r1", "signal", "receipt"),
      makeTrace("r2", "targets", "receipt"),
    ];
    expect(getEvidenceStationIds(traces)).toEqual(["signal", "targets"]);
  });

  it("deduplicates two receipt traces at the same station", () => {
    const traces = [
      makeTrace("r1", "signal", "receipt"),
      makeTrace("r2", "signal", "receipt"),
    ];
    const result = getEvidenceStationIds(traces);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe("signal");
  });

  it("preserves insertion order of first occurrence", () => {
    const traces = [
      makeTrace("r1", "targets", "receipt"),
      makeTrace("r2", "signal", "receipt"),
      makeTrace("r3", "targets", "receipt"),
    ];
    expect(getEvidenceStationIds(traces)).toEqual(["targets", "signal"]);
  });

  it("ignores finding traces mixed with receipt traces", () => {
    const traces = [
      makeTrace("f1", "watch", "finding"),
      makeTrace("r1", "run", "receipt"),
    ];
    expect(getEvidenceStationIds(traces)).toEqual(["run"]);
  });
});

// ─── groupReceiptTracesByStation ──────────────────────────────────────────────
import {
  groupReceiptTracesByStation,
  verdictColor,
} from "../components/ReceiptsPresetOverlay";

describe("groupReceiptTracesByStation", () => {
  it("returns empty map for empty input", () => {
    expect(groupReceiptTracesByStation([])).toEqual(new Map());
  });

  it("excludes finding traces", () => {
    const traces = [makeTrace("f1", "signal", "finding")];
    expect(groupReceiptTracesByStation(traces).size).toBe(0);
  });

  it("groups receipt traces by stationId", () => {
    const traces = [
      makeTrace("r1", "signal", "receipt"),
      makeTrace("r2", "targets", "receipt"),
      makeTrace("r3", "signal", "receipt"),
    ];
    const map = groupReceiptTracesByStation(traces);
    expect(map.size).toBe(2);
    expect(map.get("signal" as any)).toHaveLength(2);
    expect(map.get("targets" as any)).toHaveLength(1);
  });

  it("only includes stations with at least one receipt trace", () => {
    const traces = [
      makeTrace("f1", "watch", "finding"),
      makeTrace("r1", "run", "receipt"),
    ];
    const map = groupReceiptTracesByStation(traces);
    expect(map.has("watch" as any)).toBe(false);
    expect(map.has("run" as any)).toBe(true);
  });
});

// ─── verdictColor ─────────────────────────────────────────────────────────────

describe("verdictColor", () => {
  it("returns red (#ef4444) when headline includes 'Denied' (case-insensitive)", () => {
    const trace = makeTrace("r1", "signal", "receipt", "Denied Receipt 42");
    expect(verdictColor(trace)).toBe("#ef4444");
  });

  it("returns red for lowercase 'denied' in headline", () => {
    const trace = makeTrace("r1", "signal", "receipt", "denied action");
    expect(verdictColor(trace)).toBe("#ef4444");
  });

  it("returns amber (#f59e0b) when detail includes 'audit' (case-insensitive)", () => {
    const trace = makeTrace("r1", "signal", "receipt", "Some receipt", "audit trail present");
    expect(verdictColor(trace)).toBe("#f59e0b");
  });

  it("returns amber when score < 0", () => {
    const trace = makeTrace("r1", "signal", "receipt", "Some receipt", "detail", -1);
    expect(verdictColor(trace)).toBe("#f59e0b");
  });

  it("returns green (#22c55e) otherwise (allow)", () => {
    const trace = makeTrace("r1", "signal", "receipt", "Receipt 42", "allowed", 1.0);
    expect(verdictColor(trace)).toBe("#22c55e");
  });
});
