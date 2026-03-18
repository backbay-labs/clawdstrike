import { useCallback, useMemo, useState } from "react";
import { useHuntStore, useLens, useShell, useWorkbenchDispatch } from "../WorkbenchStateProvider";
import { SpiritBindSheet } from "../spirit-bind";
import type { SpiritBindCandidate, SpiritBindCommit } from "../spirit-bind/types";
import { createHuntSpiritState, getHuntSpiritMeta, readSpiritChamberHuntId } from "../spirit";
import type { TabContentProps } from "../tabRegistry";
import { buildSpiritManifestationModel, type SpiritManifestationModel } from "./canvas";
import { SpiritReleaseChoreography } from "./release";

type SpiritReleaseTransit = {
  model: SpiritManifestationModel;
};

function formatSpiritSurfaceLabel(value: string): string {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function buildReleaseCandidate(commit: SpiritBindCommit): SpiritBindCandidate {
  const meta = getHuntSpiritMeta(commit.kind);
  const focusSurfaces = (meta?.defaultBiases ?? [])
    .filter(Boolean)
    .slice(0, 3)
    .map(formatSpiritSurfaceLabel);

  return {
    kind: commit.kind,
    label: meta?.label ?? formatSpiritSurfaceLabel(commit.kind),
    confidenceScore: commit.confidenceScore,
    rationale: commit.bindReason,
    biasLine:
      focusSurfaces.length > 0
        ? `Pulls toward ${focusSurfaces.join(", ")}.`
        : "Pulls toward the live hunt field.",
    predictedFocusSurfaces: focusSurfaces.length > 0 ? focusSurfaces : ["Hunt"],
    alternates: [],
    liveMood: commit.liveMood,
    bindSource: commit.bindSource,
    thesis: commit.thesis,
    anchorArtifactIds: commit.anchorArtifactIds,
  };
}

export function SpiritChamberTab({ tab, groupId }: TabContentProps) {
  const dispatch = useWorkbenchDispatch();
  const huntStore = useHuntStore();
  const { lens } = useLens();
  const shell = useShell();
  const [releaseTransit, setReleaseTransit] = useState<SpiritReleaseTransit | null>(null);

  const huntId = readSpiritChamberHuntId(tab);
  const hunt = huntId ? huntStore.hunts[huntId] ?? null : null;
  const chamberKey = hunt
    ? `${hunt.id}:${hunt.spirit?.reboundAt ?? hunt.spirit?.boundAt ?? 0}`
    : "missing-hunt";

  const handleClose = useCallback(() => {
    dispatch({ type: "CLOSE_TAB", payload: { groupId, tabId: tab.id } });
  }, [dispatch, groupId, tab.id]);

  const context = useMemo(() => {
    if (!hunt) return null;
    return {
      hunt,
      artifacts: huntStore.artifacts,
      runs: huntStore.runs,
      currentLens: lens,
      currentShell: shell,
      activeStationId: shell ?? "hunt",
    };
  }, [hunt, huntStore.artifacts, huntStore.runs, lens, shell]);

  if (!hunt || !context) {
    return (
      <div className="flex h-full items-center justify-center bg-[rgba(3,5,10,0.78)] p-6">
        <div className="max-w-md rounded-2xl border border-[rgba(213,173,87,0.12)] bg-[rgba(8,10,16,0.84)] p-5 text-center">
          <div className="font-mono text-[11px] uppercase tracking-[0.18em] text-[rgba(213,173,87,0.72)]">
            Spirit unavailable
          </div>
          <div className="mt-3 text-[14px] text-[rgba(236,233,225,0.82)]">
            This hunt is no longer available.
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="mt-4 rounded-full border border-[rgba(213,173,87,0.18)] px-4 py-2 text-[12px] text-[rgba(236,233,225,0.82)]"
          >
            Close tab
          </button>
        </div>
      </div>
    );
  }

  const accentColor = getHuntSpiritMeta(hunt.spirit?.kind)?.accentColor ?? hunt.color;

  return (
    <div
      data-testid="spirit-chamber-tab"
      className="relative flex h-full flex-col overflow-auto px-8 py-7"
      style={{
        background: `radial-gradient(circle at 50% 12%, ${accentColor}18, rgba(5,7,12,0.94) 40%), rgba(3,5,9,0.96)`,
      }}
    >
      <div className="relative mx-auto flex w-full max-w-[1480px] justify-center pb-8">
        <SpiritBindSheet
          key={chamberKey}
          context={context}
          isOpen
          surface="page"
          onBind={(commit) => {
            const releaseModel = buildSpiritManifestationModel(
              context,
              buildReleaseCandidate(commit),
            );
            dispatch({
              type: "HUNT_RECONFIGURE_SPIRIT",
              payload: {
                huntId: hunt.id,
                spirit: createHuntSpiritState(commit),
              },
            });
            setReleaseTransit({ model: releaseModel });
          }}
          onDismiss={handleClose}
          onSkip={handleClose}
        />

        {releaseTransit ? (
          <SpiritReleaseChoreography
            className="absolute inset-0 z-10"
            model={releaseTransit.model}
            phase="releasing"
            restMs={320}
            onRest={() => {
              setReleaseTransit(null);
              handleClose();
            }}
          />
        ) : null}
      </div>
    </div>
  );
}
