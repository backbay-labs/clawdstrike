// NexusTab — store bridge that reads workbench stores and renders the 3D Observatory
// in atlas mode. Mirrors the ObservatoryTab pattern exactly.
//
// Plan 04-02: NXS-01 — user can open cyber nexus as "Hunt Deck" pane tab.
// hunt.openNexus already calls usePaneStore.getState().openApp("/nexus", "Nexus");
// this component makes that route render real content.

import { useState, useCallback, useMemo } from "react";
import type { HuntObservatorySceneState, HuntStationId, HuntStationState } from "@/features/observatory/world/types";
import { HUNT_STATION_LABELS, HUNT_STATION_PLACEMENTS } from "@/features/observatory/world/stations";
import { useNexusStore } from "../stores/nexus-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { ObservatoryWorldCanvas } from "@/features/observatory/components/ObservatoryWorldCanvas";
import type { SpiritKind } from "@/features/spirit/types";
import { STRIKECELL_BY_STATION, STRIKECELL_ROUTE_MAP } from "../types";
import type { StrikecellDomainId } from "../types";

// Fixed station IDs that huntronomer recognizes — same 6 stations as ObservatoryTab.
const WORKBENCH_STATION_IDS: HuntStationId[] = HUNT_STATION_PLACEMENTS.map((p) => p.id);

// Maps workbench SpiritKind to ObservatorySpiritVisual.kind (same as ObservatoryTab)
const SPIRIT_KIND_MAP: Record<SpiritKind, "tracker" | "lantern" | "ledger" | "forge"> = {
  sentinel: "tracker",
  oracle: "lantern",
  witness: "ledger",
  specter: "forge",
};

/**
 * resolveNexusObservatoryStationId — ported inline from huntronomer observatory.ts.
 * Maps a strikecell domain ID to the matching observatory station ID, or null if unmapped.
 */
function resolveNexusObservatoryStationId(
  strikecellId: StrikecellDomainId | null,
): HuntStationId | null {
  switch (strikecellId) {
    case "security-overview":
    case "events":
      return "signal";
    case "attack-graph":
      return "targets";
    case "network-map":
    case "workflows":
      return "run";
    case "forensics-river":
      return "receipts";
    case "policies":
      return "case-notes";
    case "threat-radar":
    case "marketplace":
      return "watch";
    default:
      return null;
  }
}

export function NexusTab() {
  const [activeStrikecellId, setActiveStrikecellId] = useState<StrikecellDomainId | null>(null);
  const [cameraResetToken, setCameraResetToken] = useState(0);

  const strikecells = useNexusStore.use.strikecells();
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();

  // Derive activeStationId from the currently selected strikecell
  const activeStationId = useMemo(
    () => resolveNexusObservatoryStationId(activeStrikecellId),
    [activeStrikecellId],
  );

  // Build HuntStationState[] — map strikecells to observatory station IDs by position.
  // Station order: signal, targets, run, receipts, case-notes, watch.
  // Strikecells are matched by STRIKECELL_BY_STATION reverse lookup.
  const stationStates: HuntStationState[] = WORKBENCH_STATION_IDS.map((huntId) => {
    const strikecellId = STRIKECELL_BY_STATION[huntId];
    const strikecell = strikecells.find((sc) => sc.id === strikecellId) ?? null;
    return {
      id: huntId,
      label: HUNT_STATION_LABELS[huntId],
      status: "idle",
      affinity: 0,
      emphasis: 0,
      artifactCount: strikecell?.activityCount ?? 0,
      hasUnread: (strikecell?.status ?? "offline") !== "offline",
    };
  });

  const sceneState: HuntObservatorySceneState = {
    huntId: "nexus",
    mode: "atlas",
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
      const strikecellId = STRIKECELL_BY_STATION[stationId];
      if (!strikecellId) return;
      setActiveStrikecellId(strikecellId);
      setCameraResetToken((prev) => prev + 1);
      const route = STRIKECELL_ROUTE_MAP[strikecellId] ?? "/home";
      usePaneStore.getState().openApp(route);
    },
    [],
  );

  return (
    <div className="relative flex-1 overflow-hidden" data-testid="nexus-tab">
      <div className="absolute inset-0">
        <ObservatoryWorldCanvas
          mode="atlas"
          sceneState={sceneState}
          activeStationId={activeStationId}
          spirit={spirit}
          frameloop="demand"
          cameraResetToken={cameraResetToken}
          onSelectStation={handleSelectStation}
        />
      </div>

      {/* Test assertion target — reports active strikecell for automation */}
      <div
        className="sr-only"
        data-active-strikecell={activeStrikecellId ?? "none"}
      />
    </div>
  );
}
