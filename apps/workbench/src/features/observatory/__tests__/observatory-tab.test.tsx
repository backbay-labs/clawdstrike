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
  CameraShake: vi.fn(() => null),
  Line: vi.fn(() => null),
  useGLTF: Object.assign(vi.fn(() => ({ scene: { clone: () => null } })), {
    preload: vi.fn(),
  }),
}));

// Mock observatory store
vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: {
    use: {
      stations: vi.fn(() => []),
      mission: vi.fn(() => null),
    },
    getState: vi.fn(() => ({
      actions: {
        startMission: vi.fn(),
        resetMission: vi.fn(),
      },
    })),
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

  it("dispatches observatory:shake event on probe dispatch (CAM-03)", () => {
    render(<ObservatoryTab />);
    const shakeEvents: CustomEvent[] = [];
    const handler = (e: Event) => shakeEvents.push(e as CustomEvent);
    window.addEventListener("observatory:shake", handler);

    act(() => {
      window.dispatchEvent(new CustomEvent("observatory:probe"));
    });

    window.removeEventListener("observatory:shake", handler);
    expect(shakeEvents.length).toBe(1);
    expect(shakeEvents[0].detail.intensity).toBeGreaterThan(0);
  });
});

describe("ObservatoryProbeHud (OBS-04 HUD overlay)", () => {
  // ObservatoryProbeHud renders null when status=ready, shows status text otherwise
  let ObservatoryProbeHud: typeof import("@/features/observatory/components/ObservatoryProbeHud").ObservatoryProbeHud;

  beforeEach(async () => {
    const mod = await import("@/features/observatory/components/ObservatoryProbeHud");
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

describe("ObservatoryTab — fly-by cinematics (CAM-01)", () => {
  beforeEach(() => {
    mockUseStations.mockReturnValue([]);
    mockUseKind.mockReturnValue(null);
    mockUseAccentColor.mockReturnValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows letterbox bars (h-12) on initial render (CAM-01)", () => {
    const { container } = render(<ObservatoryTab />);
    // At least one element should have the h-12 class (letterbox bars are active on mount)
    const bars = container.querySelectorAll(".h-12");
    expect(bars.length).toBeGreaterThanOrEqual(1);
  });

  it("letterbox bars hide (h-0) after Escape key press skips fly-by (CAM-01)", () => {
    const { container } = render(<ObservatoryTab />);
    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    // bars should have h-0 now (fly-by ended)
    const bars = container.querySelectorAll(".h-0");
    expect(bars.length).toBeGreaterThanOrEqual(1);
  });

  it("registers keydown listener for Escape skip on mount (CAM-01)", () => {
    const addEventSpy = vi.spyOn(window, "addEventListener");
    render(<ObservatoryTab />);
    const keydownRegistered = addEventSpy.mock.calls.some((call) => call[0] === "keydown");
    expect(keydownRegistered).toBe(true);
  });

  it("renders without crash with flyByActive=true on mount (CAM-01)", () => {
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
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
