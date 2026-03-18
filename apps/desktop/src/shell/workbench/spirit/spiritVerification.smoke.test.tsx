// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deriveNexusSpiritSceneActor } from "@/features/cyber-nexus/scene/spirits/runtime";
import type { Strikecell } from "@/features/cyber-nexus/types";
import { deriveHuntSpiritSceneActor } from "@/features/forensics/components/hunt-spirit/runtime";
import { huntReducer } from "../huntReducer";
import { createInitialWorkbenchState } from "../workbenchState";
import { SpiritBindSheet } from "../spirit-bind";
import { buildSpiritBindCommit } from "../spirit-bind/suggestions";
import { createInitialSpiritBindDraft } from "../spirit-bind/useSpiritBindDraft";
import {
  createHuntSpiritState,
  deriveHuntSpiritRuntimeState,
  selectActiveHuntSpiritSignalSnapshot,
} from ".";
import { SpiritConsoleCard, SpiritInlineSummary } from "./components/SpiritIdentity";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

const STRIKECELLS: Strikecell[] = [
  {
    id: "security-overview",
    name: "Security Overview",
    routeId: "security-overview",
    description: "",
    status: "healthy",
    activityCount: 5,
    nodeCount: 3,
    nodes: [],
    tags: [],
  },
  {
    id: "threat-radar",
    name: "Threat Radar",
    routeId: "threat-radar",
    description: "",
    status: "warning",
    activityCount: 7,
    nodeCount: 5,
    nodes: [],
    tags: [],
  },
  {
    id: "attack-graph",
    name: "Attack Graph",
    routeId: "attack-graph",
    description: "",
    status: "healthy",
    activityCount: 4,
    nodeCount: 4,
    nodes: [],
    tags: [],
  },
  {
    id: "network-map",
    name: "Network Map",
    routeId: "network-map",
    description: "",
    status: "healthy",
    activityCount: 6,
    nodeCount: 4,
    nodes: [],
    tags: [],
  },
  {
    id: "forensics-river",
    name: "Forensics River",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 3,
    nodeCount: 2,
    nodes: [],
    tags: [],
  },
  {
    id: "workflows",
    name: "Workflows",
    routeId: "workflows",
    description: "",
    status: "healthy",
    activityCount: 2,
    nodeCount: 2,
    nodes: [],
    tags: [],
  },
];

function reduceHuntActions(
  actions: Parameters<typeof huntReducer>[1][],
) {
  return actions.reduce((state, action) => huntReducer(state, action), createInitialWorkbenchState().huntStore);
}

function buildQuickBindHarness() {
  let huntStore = reduceHuntActions([
    { type: "HUNT_CREATE", payload: { title: "Receipt Forge Hunt" } },
  ]);

  const huntId = huntStore.dock.activeHuntId;
  if (!huntId) {
    throw new Error("Expected hunt creation to set an active hunt");
  }

  huntStore = huntReducer(huntStore, {
    type: "HUNT_ADD_ARTIFACT",
    payload: {
      huntId,
      artifact: {
        id: "smoke_receipt",
        kind: "receipt",
        title: "Receipt cluster",
        sourceUri: "receipts://smoke/1",
      },
    },
  });
  huntStore = huntReducer(huntStore, {
    type: "HUNT_ADD_ARTIFACT",
    payload: {
      huntId,
      artifact: {
        id: "smoke_file",
        kind: "file",
        title: "Sandbox payload",
        sourceUri: "files://smoke/payload",
      },
    },
  });
  huntStore = huntReducer(huntStore, {
    type: "HUNT_ASSIGN_ARTIFACT_SEMANTIC",
    payload: {
      huntId,
      artifactId: "smoke_receipt",
      semantic: "evidence",
    },
  });
  huntStore = huntReducer(huntStore, {
    type: "HUNT_ASSIGN_ARTIFACT_SEMANTIC",
    payload: {
      huntId,
      artifactId: "smoke_file",
      semantic: "mount",
    },
  });
  huntStore = huntReducer(huntStore, {
    type: "HUNT_CREATE_RUN",
    payload: {
      huntId,
      label: "Replay sandbox execution",
    },
  });

  const runId = huntStore.hunts[huntId]?.runIds[0];
  if (!runId) {
    throw new Error("Expected run creation to attach a run to the active hunt");
  }

  huntStore = huntReducer(huntStore, {
    type: "HUNT_ATTACH_ARTIFACT_TO_RUN",
    payload: {
      runId,
      artifactId: "smoke_file",
      semantic: "run-input",
    },
  });

  const hunt = huntStore.hunts[huntId];
  const context = {
    hunt,
    artifacts: huntStore.artifacts,
    runs: huntStore.runs,
    currentLens: "files" as const,
    currentShell: "hunt" as const,
    activeStationId: "forensics-river",
  };

  return { huntStore, huntId, hunt, context };
}

describe("hunt spirit verification smoke", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
  });

  it("proves create stays instant while default spirit creation and reconfiguration propagate across dock, sidebar, and 3D runtimes", async () => {
    const { huntStore, huntId, hunt, context } = buildQuickBindHarness();
    expect(hunt.spirit).not.toBeNull();
    expect(hunt.spirit?.bindSource).toBe("default-create");

    const commit = buildSpiritBindCommit(context, createInitialSpiritBindDraft());
    expect(commit.bindSource).toBe("quick-configure");
    expect(commit.anchorArtifactIds).toContain("smoke_receipt");

    const state = createInitialWorkbenchState();
    state.shell = "hunt";
    state.lens = "files";
    state.huntStore = huntStore;
    state.huntStore = huntReducer(state.huntStore, {
      type: "HUNT_RECONFIGURE_SPIRIT",
      payload: {
        huntId,
        spirit: createHuntSpiritState(commit),
      },
    });
    state.huntStore.dock.activeHuntId = huntId;

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state);
    expect(snapshot?.huntId).toBe(huntId);
    expect(snapshot?.boundSpirit?.kind).toBe(commit.kind);

    const runtime = deriveHuntSpiritRuntimeState(snapshot?.boundSpirit ?? null, {
      currentShell: snapshot?.currentShell,
      currentLens: snapshot?.currentLens,
      likelyIntent: snapshot?.likelyIntent,
      confidenceScore: snapshot?.confidenceScore,
      activeStationId: "forensics-river",
      isActive: true,
    });

    await act(async () => {
      root.render(
        <>
          <SpiritInlineSummary hunt={state.huntStore.hunts[huntId]} />
          <SpiritConsoleCard hunt={state.huntStore.hunts[huntId]} />
        </>,
      );
    });

    expect(container.textContent).toContain(runtime.label ?? "");
    expect(container.textContent).toContain("Biasing");
    expect(container.textContent).toContain("Leaning forward");

    const forensicsActor = deriveHuntSpiritSceneActor({
      runtime,
      snapshot,
      activeStationId: "forensics-river",
      cue: null,
    });
    expect(forensicsActor?.label).toBe(runtime.label);
    expect(forensicsActor?.presenceStrength).toBeGreaterThan(0.25);

    const nexusActor = deriveNexusSpiritSceneActor({
      runtime,
      snapshot,
      strikecells: STRIKECELLS,
      activeStrikecellId: "forensics-river",
      cue: null,
    });
    expect(nexusActor?.label).toBe(runtime.label);
    expect(nexusActor?.anchorStrikecellId).toBe("forensics-river");
    expect(nexusActor?.stationAffinities["forensics-river"]).toBeGreaterThan(0.3);
  });

  it("keeps the public bind seam pointed at the ritual chamber with keyboard-reachable controls", async () => {
    const { context } = buildQuickBindHarness();
    const onBindCalls: Array<unknown> = [];

    await act(async () => {
      root.render(
        <SpiritBindSheet
          context={context}
          isOpen
          onBind={(commit) => onBindCalls.push(commit)}
          onDismiss={() => {}}
          onSkip={() => {}}
        />,
      );
    });

    const chamber = container.querySelector('[data-testid="spirit-bind-sheet"]') as HTMLElement | null;
    const stationRail = container.querySelector('[role="tablist"][aria-label="Spirit modes"]');
    const manualTab = container.querySelector('[data-testid="spirit-bind-mode-manual"]') as HTMLButtonElement | null;
    const pinToggle = container.querySelector('[data-testid="spirit-bind-pin-toggle"]') as HTMLButtonElement | null;
    const submit = container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement | null;

    expect(chamber?.textContent).toContain("Spirit");
    expect(chamber?.textContent).toContain("Keep current");
    expect(chamber?.textContent).toContain("Pin to hunt");
    expect(chamber?.textContent).toContain("Apply spirit");
    expect(chamber?.getAttribute("aria-label")).toBe("Configure Spirit");
    expect(stationRail).toBeTruthy();
    expect(manualTab?.disabled).toBe(false);
    expect(pinToggle?.disabled).toBe(false);
    expect(submit?.disabled).toBe(false);

    manualTab?.focus();
    expect(document.activeElement).toBe(manualTab);

    await act(async () => {
      manualTab?.click();
    });

    const radioGroup = container.querySelector('[role="radiogroup"][aria-label="Manual spirit selection"]');
    const radioButtons = Array.from(
      container.querySelectorAll<HTMLButtonElement>('[role="radio"]'),
    );
    const currentCheckedIndex = radioButtons.findIndex(
      (button) => button.getAttribute("aria-checked") === "true",
    );
    const nextCheckedIndex = currentCheckedIndex >= 0
      ? (currentCheckedIndex + 1) % radioButtons.length
      : 0;

    expect(radioGroup).toBeTruthy();
    expect(radioButtons.length).toBeGreaterThan(1);
    expect(currentCheckedIndex).toBeGreaterThanOrEqual(0);

    radioButtons[currentCheckedIndex]?.focus();
    await act(async () => {
      radioButtons[currentCheckedIndex]?.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }),
      );
    });

    expect(document.activeElement).toBe(radioButtons[nextCheckedIndex]);
    expect(radioButtons[nextCheckedIndex]?.getAttribute("aria-checked")).toBe("true");
    const manualPinToggle = container.querySelector('[data-testid="spirit-bind-pin-toggle"]') as HTMLButtonElement | null;

    expect(manualPinToggle?.getAttribute("role")).toBe("switch");
    expect(manualPinToggle?.getAttribute("aria-checked")).toBe("false");

    await act(async () => {
      manualPinToggle?.click();
      submit?.click();
    });

    expect(onBindCalls).toHaveLength(1);
    expect(onBindCalls[0]).toMatchObject({
      bindSource: "manual",
      isPinned: true,
    });
  });
});
