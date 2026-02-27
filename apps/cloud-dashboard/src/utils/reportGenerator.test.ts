import { describe, it, expect } from "vitest";
import { generateReportHTML, type ReportConfig } from "./reportGenerator";

function makeConfig(overrides: Partial<ReportConfig["stats"]> = {}): ReportConfig {
  return {
    timeRange: "7d",
    framework: "SOC2",
    events: [],
    stats: {
      total: 100,
      blocked: 5,
      blockedPct: 5.0,
      activeGuards: ["ForbiddenPathGuard", "EgressAllowlistGuard"],
      policyVersion: "1.0.0",
      topViolations: [{ guard: "ForbiddenPathGuard", count: 3 }],
      ...overrides,
    },
  };
}

describe("generateReportHTML", () => {
  it("generates valid HTML with framework name", () => {
    const html = generateReportHTML(makeConfig());
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("SOC2");
    expect(html).toContain("ClawdStrike Compliance Report");
  });

  it("includes stats in the output", () => {
    const html = generateReportHTML(makeConfig());
    expect(html).toContain("100"); // total
    expect(html).toContain("5.0%"); // blockedPct
    expect(html).toContain("ForbiddenPathGuard");
    expect(html).toContain("1.0.0"); // policyVersion
  });

  it("includes time range", () => {
    const html = generateReportHTML(makeConfig());
    expect(html).toContain("7d");
  });

  it("escapes HTML in guard names to prevent XSS", () => {
    const html = generateReportHTML(
      makeConfig({
        topViolations: [{ guard: '<script>alert("xss")</script>', count: 1 }],
        activeGuards: ['<img src=x onerror="alert(1)">'],
      }),
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain('onerror="alert');
    expect(html).toContain("&lt;script&gt;");
  });

  it("handles empty violations array", () => {
    const html = generateReportHTML(makeConfig({ topViolations: [], activeGuards: [] }));
    expect(html).toContain("<!DOCTYPE html>");
  });
});
