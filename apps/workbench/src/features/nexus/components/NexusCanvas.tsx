import { useMemo } from "react";
import type {
  HuntObservatorySceneState,
  HuntStationId,
} from "@/features/observatory/world/types";
import { ObservatoryWorldCanvas } from "@/features/observatory/components/ObservatoryWorldCanvas";
import type { NexusSpiritSceneActor } from "../scene/spirits/runtime";
import type {
  NexusLayoutMode,
  NexusViewMode,
  Strikecell,
  StrikecellConnection,
  StrikecellDomainId,
} from "../types";
import { resolveNexusObservatoryStationId } from "../observatory";

interface NexusCanvasProps {
  strikecells: Strikecell[];
  connections: StrikecellConnection[];
  activeStrikecellId: StrikecellDomainId | null;
  expandedStrikecellIds: StrikecellDomainId[];
  selectedNodeIds: string[];
  focusedNodeId: string | null;
  layoutMode: NexusLayoutMode;
  viewMode: NexusViewMode;
  fieldVisible: boolean;
  cameraResetToken: number;
  activeSpiritActor: NexusSpiritSceneActor | null;
  observatorySceneState: HuntObservatorySceneState | null;
  onSelectStrikecell: (id: StrikecellDomainId) => void;
  onToggleExpandedStrikecell: (id: StrikecellDomainId) => void;
  onToggleNodeSelection: (nodeId: string) => void;
  onFocusNode: (nodeId: string | null) => void;
  onBackgroundClick: () => void;
  onContextMenu: (
    targetId: string,
    targetType: "strikecell" | "node",
    event: MouseEvent,
    strikecellId?: StrikecellDomainId,
  ) => void;
}

const STRIKECELL_BY_STATION: Record<HuntStationId, StrikecellDomainId> = {
  signal: "security-overview",
  targets: "attack-graph",
  run: "network-map",
  receipts: "forensics-river",
  "case-notes": "policies",
  watch: "threat-radar",
};

export function NexusCanvas({
  activeStrikecellId,
  cameraResetToken,
  activeSpiritActor,
  observatorySceneState,
  onSelectStrikecell,
}: NexusCanvasProps) {
  const activeStationId = useMemo(
    () => resolveNexusObservatoryStationId(activeStrikecellId),
    [activeStrikecellId],
  );

  return (
    <div className="relative h-full w-full">
      <ObservatoryWorldCanvas
        className="absolute inset-0"
        mode="atlas"
        sceneState={observatorySceneState}
        activeStationId={activeStationId}
        cameraResetToken={cameraResetToken}
        spirit={
          activeSpiritActor
            ? {
                kind: activeSpiritActor.kind,
                accentColor: activeSpiritActor.accentColor,
                likelyStationId: activeSpiritActor.observatoryLikelyStationId ?? null,
                cueKind: activeSpiritActor.observatoryActor?.cueKind ?? null,
              }
            : null
        }
        onSelectStation={(stationId) => {
          onSelectStrikecell(STRIKECELL_BY_STATION[stationId]);
        }}
      />
    </div>
  );
}
