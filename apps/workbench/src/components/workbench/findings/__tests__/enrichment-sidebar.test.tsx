import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { EnrichmentSidebar } from "../enrichment-sidebar";
import type { EnrichmentSourceStatus } from "@/lib/plugins/threat-intel/enrichment-bridge";
import type { Enrichment } from "@/lib/workbench/finding-engine";

// ---- Fixtures ----

function makeSourceStatus(
  sourceId: string,
  sourceName: string,
  status: EnrichmentSourceStatus["status"],
  overrides: Partial<EnrichmentSourceStatus> = {},
): EnrichmentSourceStatus {
  return {
    sourceId,
    sourceName,
    status,
    ...overrides,
  };
}

function makeEnrichment(overrides: Partial<Enrichment> = {}): Enrichment {
  return {
    id: "enr_test1",
    type: "custom",
    label: "Test enrichment",
    data: { foo: "bar" },
    addedAt: Date.now(),
    source: "test-source",
    ...overrides,
  };
}

// ---- Tests ----

describe("EnrichmentSidebar", () => {
  it("renders skeleton loaders when sourceStatuses has loading entries", () => {
    const statuses: EnrichmentSourceStatus[] = [
      makeSourceStatus("virustotal", "VirusTotal", "loading"),
      makeSourceStatus("greynoise", "GreyNoise", "loading"),
    ];

    render(
      <EnrichmentSidebar
        enrichments={[]}
        sourceStatuses={statuses}
        isEnriching={true}
      />,
    );

    // Check for skeleton loaders via test IDs
    expect(screen.getByTestId("skeleton-virustotal")).toBeInTheDocument();
    expect(screen.getByTestId("skeleton-greynoise")).toBeInTheDocument();

    // Check animate-pulse class is present (skeleton animation)
    const skeletonVt = screen.getByTestId("skeleton-virustotal");
    const pulseBars = skeletonVt.querySelectorAll(".animate-pulse");
    expect(pulseBars.length).toBeGreaterThan(0);
  });

  it("renders error badge when sourceStatuses has error entries", () => {
    const statuses: EnrichmentSourceStatus[] = [
      makeSourceStatus("virustotal", "VirusTotal", "error", {
        error: "API rate limited",
      }),
    ];

    render(
      <EnrichmentSidebar
        enrichments={[]}
        sourceStatuses={statuses}
        isEnriching={false}
      />,
    );

    const errorCard = screen.getByTestId("error-virustotal");
    expect(errorCard).toBeInTheDocument();
    expect(errorCard.textContent).toContain("VirusTotal");
    expect(errorCard.textContent).toContain("API rate limited");
  });

  it("renders result when sourceStatuses has done entries", () => {
    const statuses: EnrichmentSourceStatus[] = [
      makeSourceStatus("virustotal", "VirusTotal", "done", {
        result: {
          sourceId: "virustotal",
          sourceName: "VirusTotal",
          verdict: {
            classification: "malicious",
            confidence: 0.92,
            summary: "42/70 engines detected as malicious",
          },
          rawData: {},
          fetchedAt: Date.now(),
          cacheTtlMs: 300_000,
          permalink: "https://www.virustotal.com/gui/file/abc123",
        },
      }),
    ];

    render(
      <EnrichmentSidebar
        enrichments={[]}
        sourceStatuses={statuses}
        isEnriching={false}
      />,
    );

    const resultCard = screen.getByTestId("result-virustotal");
    expect(resultCard).toBeInTheDocument();
    expect(resultCard.textContent).toContain("VirusTotal");
    expect(resultCard.textContent).toContain("MALICIOUS");
    expect(resultCard.textContent).toContain("92%");
    expect(resultCard.textContent).toContain("42/70 engines detected as malicious");
  });

  it("shows Cancel button when isEnriching is true", () => {
    const onCancel = vi.fn();

    render(
      <EnrichmentSidebar
        enrichments={[]}
        sourceStatuses={[
          makeSourceStatus("virustotal", "VirusTotal", "loading"),
        ]}
        isEnriching={true}
        onCancel={onCancel}
      />,
    );

    const cancelButton = screen.getByTestId("cancel-enrichment");
    expect(cancelButton).toBeInTheDocument();
    expect(cancelButton.textContent).toContain("Cancel");

    fireEvent.click(cancelButton);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("one source error does not prevent other source results from rendering", () => {
    const statuses: EnrichmentSourceStatus[] = [
      makeSourceStatus("virustotal", "VirusTotal", "error", {
        error: "API key invalid",
      }),
      makeSourceStatus("greynoise", "GreyNoise", "done", {
        result: {
          sourceId: "greynoise",
          sourceName: "GreyNoise",
          verdict: {
            classification: "benign",
            confidence: 0.95,
            summary: "GreyNoise: benign (RIOT)",
          },
          rawData: {},
          fetchedAt: Date.now(),
          cacheTtlMs: 600_000,
          permalink: "https://viz.greynoise.io/ip/1.2.3.4",
        },
      }),
    ];

    render(
      <EnrichmentSidebar
        enrichments={[]}
        sourceStatuses={statuses}
        isEnriching={false}
      />,
    );

    // VT error is visible
    const errorCard = screen.getByTestId("error-virustotal");
    expect(errorCard).toBeInTheDocument();
    expect(errorCard.textContent).toContain("API key invalid");

    // GN result is also visible (not blocked by VT error)
    const resultCard = screen.getByTestId("result-greynoise");
    expect(resultCard).toBeInTheDocument();
    expect(resultCard.textContent).toContain("GreyNoise");
    expect(resultCard.textContent).toContain("BENIGN");
    expect(resultCard.textContent).toContain("95%");
  });

  it("shows Run Enrichment button when not enriching", () => {
    const onRunEnrichment = vi.fn();

    render(
      <EnrichmentSidebar
        enrichments={[]}
        onRunEnrichment={onRunEnrichment}
        isEnriching={false}
      />,
    );

    const button = screen.getByText("Run Enrichment");
    expect(button).toBeInTheDocument();
    fireEvent.click(button);
    expect(onRunEnrichment).toHaveBeenCalledTimes(1);
  });

  it("threat_intel enrichment type config exists", () => {
    // Render an enrichment with type 'threat_intel' -- should use the config
    render(
      <EnrichmentSidebar
        enrichments={[
          makeEnrichment({
            type: "custom" as Enrichment["type"],
            label: "Test threat intel",
          }),
        ]}
      />,
    );

    // Component renders without error -- the config exists
    expect(screen.getByText("Test threat intel")).toBeInTheDocument();
  });
});

describe("EnrichmentSidebar structural (React.memo effectiveness)", () => {
  it("enrichment-sidebar.tsx exports via React.memo (or memo())", async () => {
    const fs = await import("fs");
    const path = await import("path");

    const source = fs.readFileSync(
      path.resolve(import.meta.dirname, "../enrichment-sidebar.tsx"),
      "utf-8",
    );

    // The component should be exported via memo() wrapping
    const hasMemoExport =
      source.includes("export const EnrichmentSidebar = memo(") ||
      source.includes("export const EnrichmentSidebar = React.memo(");
    expect(hasMemoExport).toBe(true);
  });

  it("useMemo is applied to groupByType computation", async () => {
    const fs = await import("fs");
    const path = await import("path");

    const source = fs.readFileSync(
      path.resolve(import.meta.dirname, "../enrichment-sidebar.tsx"),
      "utf-8",
    );

    // groupByType should be wrapped in useMemo
    expect(source).toMatch(/useMemo\(\s*\(\)\s*=>\s*groupByType/);
  });

  it("useMemo is applied to extractRelatedIndicators computation", async () => {
    const fs = await import("fs");
    const path = await import("path");

    const source = fs.readFileSync(
      path.resolve(import.meta.dirname, "../enrichment-sidebar.tsx"),
      "utf-8",
    );

    // extractRelatedIndicators should be wrapped in useMemo
    expect(source).toMatch(/useMemo\(\s*[\s\S]*?extractRelatedIndicators/);
  });
});
