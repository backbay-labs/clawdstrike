// apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx
// Covers OBS-03 (ObservatoryTab renders at /observatory), OBS-04 (probe state machine), OBS-05 (mode toggle)
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, act, fireEvent } from "@testing-library/react";

// Mock @react-three/fiber Canvas — standard jsdom pattern
vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

// Mock drei so Text and other components don't crash in jsdom
vi.mock("@react-three/drei", () => ({
  Text: vi.fn(() => null),
  Stars: vi.fn(() => null),
  OrbitControls: vi.fn(() => null),
  CameraControls: vi.fn(() => null),
  Line: vi.fn(() => null),
}));

// Mock observatory store
vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: {
    use: {
      stations: vi.fn(() => []),
    },
  },
}));

// Mock spirit store
vi.mock("@/features/spirit/stores/spirit-store", () => ({
  useSpiritStore: {
    use: {
      kind: vi.fn(() => null),
      accentColor: vi.fn(() => null),
    },
  },
}));

import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";

// @ts-expect-error — ObservatoryTab does not exist yet (Wave 0 scaffold)
import { ObservatoryTab } from "@/features/observatory/components/ObservatoryTab";

const mockUseStations = useObservatoryStore.use.stations as ReturnType<typeof vi.fn>;
const mockUseKind = useSpiritStore.use.kind as ReturnType<typeof vi.fn>;
const mockUseAccentColor = useSpiritStore.use.accentColor as ReturnType<typeof vi.fn>;

describe("ObservatoryTab (OBS-03, OBS-05)", () => {
  beforeEach(() => {
    mockUseStations.mockReturnValue([]);
    mockUseKind.mockReturnValue(null);
    mockUseAccentColor.mockReturnValue(null);
  });

  it("renders without crash when no stations are in the store", () => {
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders without crash when 3 stations are in the store", () => {
    mockUseStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 2 },
      { id: "targets", kind: "hunt", label: "Subjects", route: "/hunt", artifactCount: 0 },
      { id: "run", kind: "hunt", label: "Operations", route: "/hunt", artifactCount: 1 },
    ]);
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders ObservatoryWorldCanvas (r3f-canvas mock) when there are stations", () => {
    mockUseStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 0 },
    ]);
    const { getByTestId } = render(<ObservatoryTab />);
    expect(getByTestId("r3f-canvas")).toBeDefined();
  });

  it("mode prop defaults to atlas on first render", () => {
    // The ObservatoryWorldCanvas receives mode="atlas" by default.
    // We verify the wrapper renders (mode state exists in component).
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
    // Detailed mode assertion deferred until setMode is exposed (OBS-05 Task 3)
  });
});

describe("ObservatoryTab — probe state machine (OBS-04)", () => {
  beforeEach(() => {
    mockUseStations.mockReturnValue([]);
    mockUseKind.mockReturnValue(null);
    mockUseAccentColor.mockReturnValue(null);
    // Reset window event listeners between tests
  });

  afterEach(() => {
    // Clean up any lingering event listeners
    vi.restoreAllMocks();
  });

  it("renders with data-observatory-mode=atlas by default", () => {
    const { container } = render(<ObservatoryTab />);
    // The mode indicator div should be present with atlas as default
    const modeDiv = container.querySelector("[data-observatory-mode]");
    expect(modeDiv).not.toBeNull();
    expect(modeDiv?.getAttribute("data-observatory-mode")).toBe("atlas");
  });

  it("registers observatory:probe window event listener on mount", () => {
    const addEventSpy = vi.spyOn(window, "addEventListener");
    render(<ObservatoryTab />);
    const probeListenerRegistered = addEventSpy.mock.calls.some(
      (call) => call[0] === "observatory:probe",
    );
    expect(probeListenerRegistered).toBe(true);
  });

  it("removes observatory:probe window event listener on unmount", () => {
    const removeEventSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = render(<ObservatoryTab />);
    unmount();
    const probeListenerRemoved = removeEventSpy.mock.calls.some(
      (call) => call[0] === "observatory:probe",
    );
    expect(probeListenerRemoved).toBe(true);
  });

  it("ATLAS/FLOW toggle button is rendered in the tab", () => {
    const { getByRole } = render(<ObservatoryTab />);
    // The mode toggle button should be present
    const buttons = document.querySelectorAll("button");
    const toggleBtn = Array.from(buttons).find(
      (btn) => btn.textContent === "ATLAS" || btn.textContent === "FLOW",
    );
    expect(toggleBtn).toBeDefined();
  });

  it("clicking ATLAS button toggles mode to flow", () => {
    const { container, getByText } = render(<ObservatoryTab />);
    const atlasBtn = getByText("ATLAS");
    expect(atlasBtn).toBeDefined();

    act(() => {
      fireEvent.click(atlasBtn);
    });

    // After clicking, mode should switch to flow — button text becomes FLOW
    const modeDiv = container.querySelector("[data-observatory-mode]");
    expect(modeDiv?.getAttribute("data-observatory-mode")).toBe("flow");
  });
});

describe("ObservatoryProbeHud (OBS-04 HUD overlay)", () => {
  // ObservatoryProbeHud renders null when status=ready, shows status text otherwise
  // @ts-expect-error — component created in Task 2
  let ObservatoryProbeHud: typeof import("@/features/observatory/components/ObservatoryProbeHud").ObservatoryProbeHud;

  beforeEach(async () => {
    const mod = await import("@/features/observatory/components/ObservatoryProbeHud");
    // @ts-expect-error — accessing named export
    ObservatoryProbeHud = mod.ObservatoryProbeHud;
  });

  it("renders null when probeState.status is ready", async () => {
    const { createInitialObservatoryProbeState } = await import(
      "@/features/observatory/world/probeRuntime"
    );
    const state = createInitialObservatoryProbeState();
    const { container } = render(<ObservatoryProbeHud probeState={state} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders PROBING text when probeState.status is active", async () => {
    const { dispatchObservatoryProbe, createInitialObservatoryProbeState } = await import(
      "@/features/observatory/world/probeRuntime"
    );
    const initial = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(initial, "signal", 0);
    const { container } = render(<ObservatoryProbeHud probeState={active} />);
    expect(container.firstChild).not.toBeNull();
    expect(container.textContent?.toLowerCase()).toContain("probing");
  });

  it("renders charge bar when probeState.status is cooldown", async () => {
    const {
      dispatchObservatoryProbe,
      advanceObservatoryProbeState,
      createInitialObservatoryProbeState,
      OBSERVATORY_PROBE_ACTIVE_MS,
    } = await import("@/features/observatory/world/probeRuntime");
    const initial = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(initial, "signal", 0);
    const cooldown = advanceObservatoryProbeState(active, OBSERVATORY_PROBE_ACTIVE_MS + 20);
    const { container } = render(<ObservatoryProbeHud probeState={cooldown} />);
    expect(container.firstChild).not.toBeNull();
    // Should show some cooldown indicator
    expect(container.textContent?.toLowerCase()).toMatch(/cooldown/);
  });

  it("exports getObservatoryProbeCharge function", async () => {
    const { getObservatoryProbeCharge } = await import(
      "@/features/observatory/world/probeRuntime"
    );
    expect(typeof getObservatoryProbeCharge).toBe("function");
  });
});

describe("hunt-commands.ts — observatory.probe (OBS-04)", () => {
  it("registers observatory.probe command that dispatches observatory:probe CustomEvent", async () => {
    const { registerHuntronomerCommands } = await import("@/lib/commands/hunt-commands");
    const { commandRegistry } = await import("@/lib/command-registry");

    // Register commands
    registerHuntronomerCommands();

    // Find the observatory.probe command
    const allCommands = commandRegistry.getAll();
    const probeCmd = allCommands.find((cmd) => cmd.id === "observatory.probe");
    expect(probeCmd).toBeDefined();
    expect(probeCmd?.category).toBe("Hunt");
    expect(probeCmd?.title).toBe("Probe Active Station");

    // Executing the command should dispatch the "observatory:probe" event
    const events: Event[] = [];
    const handler = (e: Event) => events.push(e);
    window.addEventListener("observatory:probe", handler);

    probeCmd?.execute();

    window.removeEventListener("observatory:probe", handler);
    expect(events).toHaveLength(1);
    expect(events[0]).toBeInstanceOf(CustomEvent);
    expect(events[0].type).toBe("observatory:probe");
  });
});
