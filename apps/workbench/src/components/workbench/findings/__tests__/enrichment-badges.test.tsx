import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EnrichmentBadges } from "../enrichment-badges";
import type { Enrichment } from "@/lib/workbench/finding-engine";

// ---- Helpers ----

function makeEnrichment(source: string, overrides: Partial<Enrichment> = {}): Enrichment {
  return {
    id: `enr_${source}_1`,
    type: "custom",
    label: `${source} enrichment`,
    data: {},
    addedAt: Date.now(),
    source,
    ...overrides,
  };
}

// ---- Tests ----

describe("EnrichmentBadges", () => {
  it("renders nothing when enrichments array is empty", () => {
    const { container } = render(<EnrichmentBadges enrichments={[]} />);
    // Should render no badge elements
    expect(container.querySelectorAll("[data-testid^='badge-']").length).toBe(0);
  });

  it("renders a VT badge with VirusTotal brand color when enrichments include source virustotal", () => {
    render(<EnrichmentBadges enrichments={[makeEnrichment("virustotal")]} />);

    const badge = screen.getByTestId("badge-virustotal");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("VT");
    expect(badge).toHaveStyle({ color: "#394EFF" });
  });

  it("renders a GN badge with GreyNoise brand color when enrichments include source greynoise", () => {
    render(<EnrichmentBadges enrichments={[makeEnrichment("greynoise")]} />);

    const badge = screen.getByTestId("badge-greynoise");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("GN");
    expect(badge).toHaveStyle({ color: "#28A745" });
  });

  it("renders SH, AB, OTX, MISP badges with correct brand colors", () => {
    const enrichments = [
      makeEnrichment("shodan"),
      makeEnrichment("abuseipdb"),
      makeEnrichment("otx"),
      makeEnrichment("misp"),
    ];

    render(<EnrichmentBadges enrichments={enrichments} />);

    const sh = screen.getByTestId("badge-shodan");
    expect(sh).toHaveTextContent("SH");
    expect(sh).toHaveStyle({ color: "#B80000" });

    const ab = screen.getByTestId("badge-abuseipdb");
    expect(ab).toHaveTextContent("AB");
    expect(ab).toHaveStyle({ color: "#D32F2F" });

    const otx = screen.getByTestId("badge-otx");
    expect(otx).toHaveTextContent("OTX");
    expect(otx).toHaveStyle({ color: "#00B0A6" });

    const misp = screen.getByTestId("badge-misp");
    expect(misp).toHaveTextContent("MISP");
    expect(misp).toHaveStyle({ color: "#1A237E" });
  });

  it("renders multiple badges in a row for multiple source enrichments", () => {
    const enrichments = [
      makeEnrichment("virustotal"),
      makeEnrichment("greynoise"),
      makeEnrichment("shodan"),
    ];

    render(<EnrichmentBadges enrichments={enrichments} />);

    expect(screen.getByTestId("badge-virustotal")).toBeInTheDocument();
    expect(screen.getByTestId("badge-greynoise")).toBeInTheDocument();
    expect(screen.getByTestId("badge-shodan")).toBeInTheDocument();
  });

  it("deduplicates sources (only one badge per source)", () => {
    const enrichments = [
      makeEnrichment("virustotal", { id: "enr_1", type: "reputation" }),
      makeEnrichment("virustotal", { id: "enr_2", type: "custom" }),
      makeEnrichment("virustotal", { id: "enr_3", type: "external_feed" }),
    ];

    const { container } = render(<EnrichmentBadges enrichments={enrichments} />);

    // Should only have one VT badge
    const vtBadges = container.querySelectorAll("[data-testid='badge-virustotal']");
    expect(vtBadges.length).toBe(1);
  });

  it("renders unknown sources with generic gray badge and first 2 chars", () => {
    render(<EnrichmentBadges enrichments={[makeEnrichment("customfeed")]} />);

    const badge = screen.getByTestId("badge-customfeed");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("CU");
    expect(badge).toHaveStyle({ color: "#6f7f9a" });
  });
});
