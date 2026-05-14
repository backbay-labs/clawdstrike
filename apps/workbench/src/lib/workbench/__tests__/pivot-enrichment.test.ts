import { describe, it, expect, vi } from "vitest";
import {
  extractRelatedIndicators,
  triggerPivotEnrichment,
} from "../pivot-enrichment";
import type { RelatedIndicator } from "../pivot-enrichment";
import type { Enrichment } from "../finding-engine";

function makeEnrichment(
  overrides: Partial<Enrichment> & { id: string },
): Enrichment {
  return {
    type: "custom",
    label: "Test",
    data: {},
    addedAt: Date.now(),
    source: "test",
    ...overrides,
  };
}

describe("extractRelatedIndicators", () => {
  it("extracts relatedIndicators from enrichment data", () => {
    const enrichment = makeEnrichment({
      id: "enr_1",
      data: {
        relatedIndicators: [
          { type: "ip", value: "1.2.3.4" },
          { type: "domain", value: "evil.com", context: "resolved from IP" },
        ],
      },
    });

    const result = extractRelatedIndicators([enrichment]);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({
      type: "ip",
      value: "1.2.3.4",
      sourceEnrichmentId: "enr_1",
    });
    expect(result[1]).toEqual({
      type: "domain",
      value: "evil.com",
      context: "resolved from IP",
      sourceEnrichmentId: "enr_1",
    });
  });

  it("returns empty array when no relatedIndicators present", () => {
    const enrichment = makeEnrichment({
      id: "enr_2",
      data: { verdict: "malicious" },
    });

    const result = extractRelatedIndicators([enrichment]);
    expect(result).toEqual([]);
  });

  it("deduplicates by (type, value) tuple", () => {
    const enrichment1 = makeEnrichment({
      id: "enr_a",
      data: {
        relatedIndicators: [{ type: "ip", value: "1.2.3.4" }],
      },
    });
    const enrichment2 = makeEnrichment({
      id: "enr_b",
      data: {
        relatedIndicators: [
          { type: "ip", value: "1.2.3.4" },
          { type: "domain", value: "evil.com" },
        ],
      },
    });

    const result = extractRelatedIndicators([enrichment1, enrichment2]);
    expect(result).toHaveLength(2);
    // First occurrence wins
    expect(result[0].sourceEnrichmentId).toBe("enr_a");
    expect(result[1].type).toBe("domain");
  });

  it("handles enrichments with empty relatedIndicators array", () => {
    const enrichment = makeEnrichment({
      id: "enr_empty",
      data: { relatedIndicators: [] },
    });

    const result = extractRelatedIndicators([enrichment]);
    expect(result).toEqual([]);
  });

  it("handles non-array relatedIndicators gracefully", () => {
    const enrichment = makeEnrichment({
      id: "enr_bad",
      data: { relatedIndicators: "not an array" },
    });

    const result = extractRelatedIndicators([enrichment]);
    expect(result).toEqual([]);
  });
});

describe("triggerPivotEnrichment", () => {
  it("calls enrichFn with indicator type and value", () => {
    const enrichFn = vi.fn();
    const indicator: RelatedIndicator = {
      type: "ip",
      value: "1.2.3.4",
      sourceEnrichmentId: "enr_1",
    };

    triggerPivotEnrichment(indicator, enrichFn);
    expect(enrichFn).toHaveBeenCalledWith("ip", "1.2.3.4");
    expect(enrichFn).toHaveBeenCalledTimes(1);
  });
});
