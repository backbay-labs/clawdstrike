import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { FindingsIntelPage } from "../findings-intel-page";
import { FindingProvider } from "@/lib/workbench/finding-store";
import { IntelProvider } from "@/lib/workbench/intel-store";
import type { Finding } from "@/lib/workbench/finding-engine";

const FINDING_STORAGE_KEY = "clawdstrike_workbench_findings";
const INTEL_STORAGE_KEY = "clawdstrike_workbench_intel";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_confirmed_01",
    title: "Credential reuse across agents",
    status: "confirmed",
    severity: "high",
    confidence: 0.91,
    signalIds: ["sig_01", "sig_02"],
    signalCount: 2,
    scope: {
      agentIds: ["agent-01"],
      sessionIds: ["session-01"],
      timeRange: {
        start: new Date(1_715_000_000_000).toISOString(),
        end: new Date(1_715_000_060_000).toISOString(),
      },
    },
    timeline: [
      {
        timestamp: 1_715_000_000_000,
        type: "status_changed",
        summary: "Finding confirmed by analyst",
        actor: "operator-alpha",
      },
    ],
    enrichments: [],
    annotations: [],
    verdict: "threat_confirmed",
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: "operator-alpha",
    updatedBy: "operator-alpha",
    createdAt: 1_715_000_000_000,
    updatedAt: 1_715_000_000_000,
    ...overrides,
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("FindingsIntelPage", () => {
  it("promotes confirmed findings into store-backed local intel", () => {
    vi.useFakeTimers();

    const finding = makeFinding();
    localStorage.setItem(
      FINDING_STORAGE_KEY,
      JSON.stringify({
        findings: [finding],
        activeFindingId: finding.id,
      }),
    );

    render(
      <MemoryRouter initialEntries={["/findings"]}>
        <FindingProvider>
          <IntelProvider>
            <FindingsIntelPage />
          </IntelProvider>
        </FindingProvider>
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Promote" }));
    fireEvent.click(screen.getByRole("button", { name: "Intel" }));

    expect(screen.getByText("Credential reuse across agents")).toBeTruthy();

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}");
    expect(persisted.localIntel).toHaveLength(1);
    expect(persisted.localIntel[0]).toMatchObject({
      title: "Credential reuse across agents",
      derivedFrom: ["fnd_confirmed_01"],
    });
  });
});
