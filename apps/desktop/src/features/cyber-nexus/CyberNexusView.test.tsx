// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { MemoryRouter } from "react-router-dom";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("@backbay/glia/primitives", () => ({
  Badge: ({ children }: { children: unknown }) => <span>{children as any}</span>,
}));

vi.mock("@/context/ConnectionContext", () => ({
  useConnection: () => ({ status: "connected" }),
}));

vi.mock("@/services/socDataService", () => ({
  useSocData: (type: string) => {
    if (type === "threats") {
      return {
        data: [
          {
            id: "threat-1",
            angle: 0,
            distance: 0.4,
            severity: 0.8,
            type: "intrusion",
            active: true,
            label: "Suspicious shell",
          },
        ],
      };
    }

    if (type === "attacks") {
      return {
        data: [
          {
            id: "chain-1",
            name: "Chain",
            actor: "agent-1",
            status: "active",
            techniques: [
              {
                id: "T1",
                name: "Technique",
                tactic: "execution",
                detected: true,
                confidence: 0.7,
              },
            ],
          },
        ],
      };
    }

    if (type === "network") {
      return {
        data: {
          nodes: [
            {
              id: "node-1",
              type: "server",
              hostname: "srv-1",
              ip: "10.0.0.1",
              status: "healthy",
              services: ["https"],
              vulnerabilities: 0,
            },
          ],
          edges: [],
        },
      };
    }

    if (type === "overview") {
      return {
        data: {
          shield: { level: 1, status: "active", threatsBlocked: 3 },
          threats: [],
          auditEvents: [
            {
              id: "evt-1",
              timestamp: new Date(),
              type: "alert",
              severity: "warning",
              actor: "agent-1",
              resource: "file",
              action: "blocked write",
              success: false,
            },
          ],
          kpis: {
            totalChecks: 20,
            blockedCount: 5,
            allowedCount: 15,
            activeAgents: 2,
            uptimePercent: 99.9,
            avgResponseMs: 11,
          },
        },
      };
    }

    return { data: null };
  },
}));

vi.mock("@/services/tauri", () => ({
  isTauri: () => false,
  listWorkflows: vi.fn(async () => []),
  listMarketplacePolicies: vi.fn(async () => ({ policies: [] })),
}));

vi.mock("@/services/marketplaceSettings", () => ({
  loadMarketplaceFeedSources: () => [],
}));

vi.mock("./components/NexusCanvas", () => ({
  NexusCanvas: ({ onSelectStrikecell }: { onSelectStrikecell: (id: "events") => void }) => (
    <button data-testid="mock-canvas" onClick={() => onSelectStrikecell("events")}>
      mock canvas
    </button>
  ),
}));

describe("CyberNexusView", () => {
  let CyberNexusView: (typeof import("./CyberNexusView"))["CyberNexusView"];
  let container: HTMLDivElement | null = null;
  let root: Root | null = null;

  beforeAll(async () => {
    ({ CyberNexusView } = await import("./CyberNexusView"));
  });

  beforeEach(() => {
    localStorage.setItem("sdr:cyber-nexus:heroDismissed", "1");
  });

  afterEach(() => {
    if (root) {
      act(() => root?.unmount());
    }
    if (container) {
      container.remove();
    }
    root = null;
    container = null;
    vi.clearAllMocks();
  });

  afterAll(() => {
    localStorage.clear();
  });

  it("renders shell and reacts to strikecell selection", async () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    await act(async () => {
      root?.render(
        <MemoryRouter initialEntries={["/cyber-nexus"]}>
          <CyberNexusView />
        </MemoryRouter>
      );
    });

    expect(container.textContent).toContain("Cyber Nexus");
    expect(container.textContent).not.toContain("Strikecell Arc");

    const canvasButton = container.querySelector('[data-testid="mock-canvas"]') as HTMLButtonElement;
    expect(canvasButton).toBeTruthy();

    act(() => {
      canvasButton.click();
    });

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab" }));
    });

    expect(container.textContent).toContain("Strikecell Arc");
    expect(container.textContent).not.toContain("Nexus Detail");
    expect(container.textContent).not.toContain("Activity Feed");
  });
});
