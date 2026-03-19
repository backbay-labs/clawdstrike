// ObservatoryTab — store bridge wrapper that reads workbench stores and passes
// pre-built HuntObservatorySceneState to ObservatoryWorldCanvas.
// Pattern 1 from Phase 03 RESEARCH.md: ObservatoryTab as Store Bridge.
//
// This component intentionally props the canvas with a pre-built sceneState —
// it is the ONLY place that reads workbench stores and converts to huntronomer types.

import { useState, useCallback } from "react";
import type { HuntObservatorySceneState, HuntStationId, HuntStationState } from "../world/types";
import { HUNT_STATION_LABELS, HUNT_STATION_PLACEMENTS } from "../world/stations";
import { useObservatoryStore } from "../stores/observatory-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { ObservatoryWorldCanvas } from "./ObservatoryWorldCanvas";
import type { SpiritKind } from "@/features/spirit/types";

// Fixed station IDs that huntronomer recognizes — maps workbench stations to world positions.
const WORKBENCH_STATION_IDS: HuntStationId[] = HUNT_STATION_PLACEMENTS.map((p) => p.id);

// Maps workbench SpiritKind to ObservatorySpiritVisual.kind
const SPIRIT_KIND_MAP: Record<SpiritKind, "tracker" | "lantern" | "ledger" | "forge"> = {
  sentinel: "tracker",
  oracle: "lantern",
  witness: "ledger",
  specter: "forge",
};

export function ObservatoryTab() {
  const [mode, setMode] = useState<"atlas" | "flow">("atlas");
  const [characterControllerEnabled, setCharacterControllerEnabled] = useState(false);
  const [cameraResetToken, setCameraResetToken] = useState(0);

  const stations = useObservatoryStore.use.stations();
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();

  // Build HuntStationState[] — map workbench stations to huntronomer station IDs by index.
  // Workbench station[0] → signal, [1] → targets, [2] → run, [3] → receipts, [4] → case-notes, [5] → watch.
  // If workbench has no stations or fewer than 6, pad remaining with artifactCount 0.
  const stationStates: HuntStationState[] = WORKBENCH_STATION_IDS.map((huntId, index) => {
    const workbenchStation = stations[index] ?? null;
    return {
      id: huntId,
      label: HUNT_STATION_LABELS[huntId],
      status: "idle",
      affinity: 0,
      emphasis: 0,
      artifactCount: workbenchStation?.artifactCount ?? 0,
      hasUnread: (workbenchStation?.artifactCount ?? 0) > 0,
    };
  });

  const sceneState: HuntObservatorySceneState = {
    huntId: "workbench",
    mode,
    stations: stationStates,
    activeSelection: { type: "none" },
    likelyStationId: null,
    roomReceiveState: "idle",
    spiritFieldBias: kind ? 0.5 : 0,
    confidence: 0.5,
    cameraPreset: "overview",
    openedDetailSurface: "none",
  };

  const spirit =
    kind && accentColor
      ? { kind: SPIRIT_KIND_MAP[kind], accentColor }
      : null;

  const handleSelectStation = useCallback(
    (stationId: HuntStationId) => {
      // Station selection — resets camera to focus on selected station.
      // Full routing deferred to later plan.
      setCameraResetToken((prev) => prev + 1);
      // noop for now; onSelectStation prop for future routing
      void stationId;
    },
    [],
  );

  const handleDoubleClick = useCallback(() => {
    if (mode === "flow") {
      setCharacterControllerEnabled((prev) => {
        // Easter-egg toast (console log for now; toast integration in 03-02)
        if (!prev) {
          // WASD controls activated
          console.debug("[Observatory] WASD character controller activated");
        }
        return !prev;
      });
    }
  }, [mode]);

  return (
    <div className="relative flex-1 overflow-hidden" onDoubleClick={handleDoubleClick}>
      <div className="absolute inset-0">
        <ObservatoryWorldCanvas
          mode={mode}
          sceneState={sceneState}
          activeStationId={null}
          spirit={spirit}
          characterControllerEnabled={characterControllerEnabled}
          frameloop="demand"
          cameraResetToken={cameraResetToken}
          onSelectStation={handleSelectStation}
        />
      </div>
      {/* Mode toggle (exposed for Plan 03-02 flow mode toggle button) */}
      <div
        className="absolute bottom-4 right-4 z-10"
        data-observatory-mode={mode}
        data-observatory-character-controller={characterControllerEnabled ? "on" : "off"}
      >
        {/* Placeholder for flow mode toggle button — added in Plan 03-02 */}
      </div>
    </div>
  );
}
