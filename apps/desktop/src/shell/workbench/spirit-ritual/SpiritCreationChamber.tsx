import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { Artifact } from "../huntTypes";
import { HUNT_SPIRIT_KINDS, getHuntSpiritMeta } from "../spirit";
import {
  buildSpiritBindCommit,
  canBindSpiritDraft,
  deriveSpiritBindCandidate,
} from "../spirit-bind/suggestions";
import type {
  SpiritBindCommit,
  SpiritBindContext,
  SpiritBindMode,
} from "../spirit-bind/types";
import {
  MAX_ANCHORS,
  createInitialSpiritBindDraft,
  useSpiritBindDraft,
} from "../spirit-bind/useSpiritBindDraft";
import { IntentionSuggestions } from "./IntentionSuggestions";
import { SpiritAtmosphereLayer } from "./atmosphere";
import { buildSpiritManifestationModel, SpiritManifestationCanvas } from "./canvas";
import { SpiritModeRail, SpiritOrbSelector } from "./controls";
import type { SpiritRitualSuggestion } from "./state/types";

const MODE_OPTIONS: Array<{
  id: SpiritBindMode;
  label: string;
  caption: string;
  glyph: string;
}> = [
  { id: "quick-configure", label: "Quick", caption: "Settle the field.", glyph: "◎" },
  { id: "thesis", label: "Thesis", caption: "Thread one line.", glyph: "✦" },
  { id: "anchor-artifacts", label: "Anchors", caption: "Pull from evidence.", glyph: "◈" },
  { id: "manual", label: "Manual", caption: "Hold alternate readings.", glyph: "◌" },
];

function renderArtifactLabel(artifact: Artifact): string {
  return `${artifact.title} · ${artifact.kind}`;
}

function buildSurfaceStyle(borderColor: string, surface: "page" | "dialog"): CSSProperties {
  if (surface === "page") {
    return {
      background: "transparent",
    };
  }
  return {
    border: `1px solid ${borderColor}`,
    background:
      "linear-gradient(180deg, rgba(5,7,12,0.985), rgba(6,9,15,0.985) 34%, rgba(4,6,12,0.992))",
    boxShadow: "0 34px 96px rgba(0,0,0,0.54)",
    backdropFilter: "blur(24px)",
  };
}

function toTitleCase(value: string): string {
  return value
    .split(/[\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getThresholdState(context: SpiritBindContext): string {
  const bindSource = context.hunt.spirit?.bindSource;
  return !bindSource || bindSource === "default-create" ? "Initial read" : "Retuning";
}

function getReadReason(mode: SpiritBindMode, rationale: string): string {
  if (mode === "manual") {
    return "Manual station gathers alternate readings and holds the vessel until one feels truer.";
  }

  const [firstSentence] = rationale.split(". ");
  const cleaned = (firstSentence || rationale)
    .trim()
    .replace(/^Suggested because\s+/i, "")
    .replace(/\.$/, "");
  return cleaned ? `${cleaned.charAt(0).toUpperCase()}${cleaned.slice(1)}.` : rationale;
}

function formatFocusSummary(focusSurfaces: string[]): string {
  const focus = focusSurfaces.slice(0, 3);
  if (focus.length === 0) {
    return "Applies across the active hunt.";
  }
  if (focus.length === 1) {
    return `Biases ${focus[0]}.`;
  }
  if (focus.length === 2) {
    return `Biases ${focus[0]} and ${focus[1]}.`;
  }
  return `Biases ${focus[0]}, ${focus[1]}, and ${focus[2]}.`;
}

function buildThesisSuggestions(
  context: SpiritBindContext,
  artifacts: Artifact[],
  label: string,
  focusSurfaces: string[],
): SpiritRitualSuggestion[] {
  const stationLabel = context.activeStationId
    ? context.activeStationId
      .split("-")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")
    : "the active field";

  const focusLine = focusSurfaces.slice(0, 3);
  const suggestions: SpiritRitualSuggestion[] = [
    {
      id: `read-${label.toLowerCase()}`,
      label: `Follow ${label}`,
      detail: `Bias the line toward ${focusLine.join(" and ")}.`,
      promptFragment: `Follow ${label.toLowerCase()} pressure through ${focusLine.join(" and ").toLowerCase()}.`,
      focusSurfaces: focusLine,
      keywords: [label.toLowerCase(), ...focusLine.map((surface) => surface.toLowerCase())],
      sourceMode: "context",
      spiritKindHints: {},
    },
    {
      id: "station-read",
      label: `Name ${stationLabel}`,
      detail: "Aim the line at the active station.",
      promptFragment: `Carry the read through ${stationLabel.toLowerCase()}.`,
      focusSurfaces: [stationLabel],
      keywords: [stationLabel.toLowerCase()],
      sourceMode: "context",
      spiritKindHints: {},
    },
  ];

  const firstArtifact = artifacts[0];
  if (firstArtifact) {
    suggestions.push({
      id: `artifact-${firstArtifact.id}`,
      label: `Pull ${toTitleCase(firstArtifact.kind)}`,
      detail: `Let ${firstArtifact.title} bend the line.`,
      promptFragment: `Trace ${firstArtifact.title} through the hunt.`,
      focusSurfaces: [toTitleCase(firstArtifact.kind)],
      keywords: [firstArtifact.kind, firstArtifact.title.toLowerCase()],
      sourceMode: "context",
      spiritKindHints: {},
    });
  }

  return suggestions;
}

export interface SpiritCreationChamberProps {
  context: SpiritBindContext;
  isOpen: boolean;
  onBind: (commit: SpiritBindCommit) => void;
  onDismiss: () => void;
  onSkip: () => void;
  surface?: "page" | "dialog";
}

export function SpiritCreationChamber({
  context,
  isOpen,
  onBind,
  onDismiss,
  onSkip,
  surface = "page",
}: SpiritCreationChamberProps) {
  const draftState = useSpiritBindDraft(
    createInitialSpiritBindDraft({
      thesis: context.hunt.spirit?.thesis,
      isPinned: context.hunt.spirit?.isPinned,
    }),
  );
  const { draft } = draftState;
  const draftRef = useRef(draft);
  const [selectedSuggestionIds, setSelectedSuggestionIds] = useState<string[]>([]);

  useEffect(() => {
    draftRef.current = draft;
  }, [draft]);

  useEffect(() => {
    setSelectedSuggestionIds([]);
  }, [context.hunt.id]);

  const candidate = useMemo(() => deriveSpiritBindCandidate(context, draft), [context, draft]);
  const manifestationModel = useMemo(
    () => buildSpiritManifestationModel(context, candidate),
    [candidate, context],
  );
  const canBind = canBindSpiritDraft(draft);
  const bindAccent = manifestationModel.accentColor;
  const thresholdState = getThresholdState(context);
  const artifacts = context.hunt.artifactIds
    .map((id) => context.artifacts[id])
    .filter((artifact): artifact is Artifact => Boolean(artifact));
  const readReason = getReadReason(draft.mode, candidate.rationale);
  const footerLine = formatFocusSummary(candidate.predictedFocusSurfaces);
  const stageShift = draft.mode === "quick-configure"
    ? "translate3d(0, 10px, 0) scale(0.985)"
    : draft.mode === "thesis"
      ? "translate3d(-22px, -8px, 0) scale(1.02)"
      : draft.mode === "anchor-artifacts"
        ? "translate3d(-12px, 14px, 0) scale(1.025)"
        : "translate3d(14px, -10px, 0) scale(1.015)";
  const stageCaption = draft.mode === "quick-configure"
    ? "Quick configure"
    : draft.mode === "thesis"
      ? "Thesis line"
      : draft.mode === "anchor-artifacts"
        ? "Anchored by evidence"
        : "Manual read";

  const thesisSuggestions = useMemo(
    () => buildThesisSuggestions(context, artifacts, candidate.label, candidate.predictedFocusSurfaces),
    [artifacts, candidate.label, candidate.predictedFocusSurfaces, context],
  );

  const manualOptions = useMemo(() => {
    const alternateKinds = new Set(candidate.alternates.map((alternate) => alternate.kind));
    const orderedKinds = Array.from(new Set([
      candidate.kind,
      ...candidate.alternates.map((alternate) => alternate.kind),
      ...HUNT_SPIRIT_KINDS,
    ]));

    return orderedKinds.map((kind) => {
      const spiritMeta = getHuntSpiritMeta(kind);
      const biasTokens = (spiritMeta?.defaultBiases ?? [])
        .slice(0, 2)
        .map((entry) => entry.replace(/-/g, " "));
      const caption = kind === candidate.kind
        ? "Current read held steady."
        : alternateKinds.has(kind)
          ? "Alternate reading gathered into Manual."
          : biasTokens.join(" · ");

      return {
        value: kind,
        label: spiritMeta?.label ?? kind,
        caption,
        accentColor: spiritMeta?.accentColor ?? bindAccent,
        testId: `spirit-bind-manual-${kind}`,
      };
    });
  }, [bindAccent, candidate.alternates, candidate.kind]);

  const setMode = useCallback((mode: SpiritBindMode) => {
    if (mode === "manual" && draftRef.current.manualKind === null) {
      const nextManualKind = candidate.kind;
      draftRef.current = {
        ...draftRef.current,
        mode: "manual",
        manualKind: nextManualKind,
      };
      draftState.setManualKind(nextManualKind);
      return;
    }

    draftRef.current = { ...draftRef.current, mode };
    draftState.setMode(mode);
  }, [candidate.kind, draftState]);

  const setThesis = useCallback((thesis: string) => {
    draftRef.current = { ...draftRef.current, thesis };
    draftState.setThesis(thesis);
  }, [draftState]);

  const toggleAnchor = useCallback((artifactId: string) => {
    const exists = draftRef.current.selectedAnchorArtifactIds.includes(artifactId);
    const nextAnchorArtifactIds = exists
      ? draftRef.current.selectedAnchorArtifactIds.filter((id) => id !== artifactId)
      : draftRef.current.selectedAnchorArtifactIds.length >= MAX_ANCHORS
        ? draftRef.current.selectedAnchorArtifactIds
        : [...draftRef.current.selectedAnchorArtifactIds, artifactId];

    draftRef.current = {
      ...draftRef.current,
      selectedAnchorArtifactIds: nextAnchorArtifactIds,
    };
    draftState.toggleAnchor(artifactId);
  }, [draftState]);

  const setManualKind = useCallback((kind: (typeof HUNT_SPIRIT_KINDS)[number]) => {
    draftRef.current = { ...draftRef.current, manualKind: kind, mode: "manual" };
    draftState.setManualKind(kind);
  }, [draftState]);

  const setPinned = useCallback((isPinned: boolean) => {
    draftRef.current = { ...draftRef.current, isPinned };
    draftState.setPinned(isPinned);
  }, [draftState]);

  const toggleSuggestion = useCallback((suggestionId: string) => {
    setSelectedSuggestionIds((current) =>
      current.includes(suggestionId)
        ? current.filter((id) => id !== suggestionId)
        : [...current, suggestionId],
    );
  }, []);

  const applySuggestion = useCallback((suggestion: SpiritRitualSuggestion) => {
    toggleSuggestion(suggestion.id);
    const current = draftRef.current.thesis.trim();
    const fragment = suggestion.promptFragment.trim();
    const nextThesis = !current
      ? fragment
      : current.includes(fragment)
        ? current
        : `${current.replace(/\s+$/, "").replace(/[.?!]?$/, ".")} ${fragment}`;
    setThesis(nextThesis);
  }, [setThesis, toggleSuggestion]);

  const renderPinToggle = (compact = false) => (
    <button
      type="button"
      role="switch"
      aria-checked={draft.isPinned}
      aria-pressed={draft.isPinned}
      data-testid="spirit-bind-pin-toggle"
      onClick={() => setPinned(!draft.isPinned)}
      className="flex items-center justify-between gap-3 rounded-full border px-3 py-2 text-left transition-all"
      style={{
        borderColor: draft.isPinned ? `${bindAccent}42` : "rgba(171,177,191,0.16)",
        background: draft.isPinned ? `${bindAccent}0d` : "rgba(255,255,255,0.02)",
        color: "rgba(236,233,225,0.82)",
        width: compact ? "100%" : "auto",
      }}
    >
      <span className="flex items-center gap-2">
        <span
          aria-hidden="true"
          className="inline-flex h-2 w-2 rounded-full"
          style={{
            background: draft.isPinned ? bindAccent : "rgba(171,177,191,0.4)",
            boxShadow: draft.isPinned ? `0 0 10px ${bindAccent}44` : "none",
          }}
        />
        <span className="font-mono text-[10px] uppercase tracking-[0.16em]">
          Pin to hunt
        </span>
      </span>
      <span
        className="inline-flex h-5 w-9 items-center rounded-full border px-1"
        style={{
          borderColor: `${bindAccent}46`,
          justifyContent: draft.isPinned ? "flex-end" : "flex-start",
        }}
      >
        <span
          className="h-3.5 w-3.5 rounded-full"
          style={{
            background: draft.isPinned ? bindAccent : "rgba(171,177,191,0.36)",
            boxShadow: draft.isPinned ? `0 0 10px ${bindAccent}44` : "none",
          }}
        />
      </span>
    </button>
  );

  const activeControl = (() => {
    switch (draft.mode) {
      case "quick-configure":
        return (
          <div data-testid="spirit-bind-active-control-quick-configure">
            <div className="text-[12px]" style={{ color: "rgba(182,183,193,0.68)", lineHeight: 1.45 }}>
              Stay with the current read unless the hunt needs a stronger contour.
            </div>
          </div>
        );
      case "thesis":
        return (
          <div data-testid="spirit-bind-active-control-thesis">
            <textarea
              value={draft.thesis}
              onChange={(event) => setThesis(event.target.value)}
              rows={4}
              placeholder="Trace lateral movement through the sandbox execution chain"
              data-testid="spirit-bind-thesis-input"
              className="w-full rounded-[18px] border bg-transparent px-3 py-3 text-[13px] outline-none"
              style={{
                borderColor: `${bindAccent}22`,
                background: "rgba(255,255,255,0.02)",
                color: "rgba(236,233,225,0.9)",
                resize: "none",
              }}
            />
            <div className="mt-4">
              <IntentionSuggestions
                suggestions={thesisSuggestions}
                selectedSuggestionIds={selectedSuggestionIds}
                onToggleSuggestion={toggleSuggestion}
                onApplySuggestion={applySuggestion}
                title=""
              />
            </div>
          </div>
        );
      case "anchor-artifacts":
        return (
          <div data-testid="spirit-bind-active-control-anchor-artifacts">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="text-[12px]" style={{ color: "rgba(182,183,193,0.68)" }}>
                Select up to three live anchors.
              </div>
              <div className="text-[12px]" style={{ color: "rgba(236,233,225,0.8)" }}>
                {draft.selectedAnchorArtifactIds.length}/{MAX_ANCHORS}
              </div>
            </div>
            <div className="grid max-h-[276px] gap-2 overflow-auto pr-1">
              {artifacts.map((artifact) => {
                const selected = draft.selectedAnchorArtifactIds.includes(artifact.id);
                const disabled =
                  !selected && draft.selectedAnchorArtifactIds.length >= MAX_ANCHORS;
                return (
                  <button
                    key={artifact.id}
                    type="button"
                    onClick={() => toggleAnchor(artifact.id)}
                    disabled={disabled}
                    data-testid={`spirit-bind-anchor-${artifact.id}`}
                    className="rounded-[16px] px-3 py-2.5 text-left transition-all"
                    style={{
                      border: `1px solid ${selected ? `${bindAccent}4a` : "rgba(171,177,191,0.14)"}`,
                      background: selected ? `${bindAccent}10` : "rgba(255,255,255,0.02)",
                      opacity: disabled ? 0.45 : 1,
                    }}
                  >
                    <div className="text-[12px]" style={{ color: "rgba(236,233,225,0.88)" }}>
                      {renderArtifactLabel(artifact)}
                    </div>
                    <div
                      className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em]"
                      style={{ color: selected ? bindAccent : "rgba(182,183,193,0.56)" }}
                    >
                      {selected ? "Anchored" : "Pull"}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        );
      case "manual":
        return (
          <div data-testid="spirit-bind-active-control-manual">
            <div className="mb-3 text-[12px]" style={{ color: "rgba(182,183,193,0.68)", lineHeight: 1.45 }}>
              Choose a different spirit directly.
            </div>
            <SpiritOrbSelector
              ariaLabel="Manual spirit selection"
              options={manualOptions}
              value={draft.manualKind}
              onChange={setManualKind}
            />
          </div>
        );
      default:
        return null;
    }
  })();

  if (!isOpen) {
    return null;
  }

  return (
    <section
      aria-label="Configure Spirit"
      data-testid="spirit-bind-sheet"
      className={surface === "page"
        ? "relative flex w-full flex-col"
        : "relative flex w-[1180px] flex-col overflow-hidden rounded-[30px]"}
      style={buildSurfaceStyle("rgba(212,168,75,0.16)", surface)}
    >
      <header
        className={surface === "page"
          ? "flex items-center justify-between gap-4 px-0 pb-5 pt-1"
          : "flex items-center justify-between gap-4 px-6 py-4"}
        style={{
          borderBottom: "1px solid rgba(212,168,75,0.1)",
        }}
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <div
              className="font-mono text-[11px] uppercase tracking-[0.18em]"
              style={{ color: "rgba(212,168,75,0.82)" }}
            >
              Spirit
            </div>
            <div
              className="rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em]"
              style={{
                borderColor: `${bindAccent}36`,
                background: `${bindAccent}12`,
                color: "rgba(241,239,234,0.86)",
              }}
            >
              {thresholdState}
            </div>
            <div className="text-[14px]" style={{ color: "rgba(241,239,234,0.92)" }}>
              {context.hunt.title}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onSkip}
            data-testid="spirit-bind-skip"
            className="rounded-full px-3 py-1.5 text-[12px]"
            style={{
              color: "rgba(207,211,220,0.76)",
              background: "rgba(255,255,255,0.03)",
            }}
          >
            Keep current
          </button>
          <button
            type="button"
            onClick={onDismiss}
            data-testid="spirit-bind-dismiss"
            className="rounded-full px-3 py-1.5 text-[12px]"
            style={{
              color: "rgba(241,239,234,0.84)",
              background: "rgba(255,255,255,0.03)",
            }}
          >
            Close
          </button>
        </div>
      </header>

      <div
        className={surface === "page"
          ? "grid min-h-[760px] grid-cols-[minmax(0,1fr)_228px] gap-7 pt-6"
          : "grid min-h-[760px] grid-cols-[minmax(0,1fr)_220px]"}
      >
        <main className={surface === "page" ? "relative overflow-hidden px-0 py-0" : "relative overflow-hidden px-6 py-5"}>
          <div className="relative h-full min-h-[700px]">
            <div
              className="relative transition-transform duration-300 ease-out"
              style={{ transform: stageShift, transformOrigin: "50% 48%" }}
            >
              <SpiritManifestationCanvas
                model={manifestationModel}
                className="relative z-[1] h-[648px] w-full"
                showLegend={draft.mode !== "quick-configure"}
              />
              <SpiritAtmosphereLayer
                model={manifestationModel}
                className="absolute inset-0 z-[2]"
              />

              <div className="pointer-events-none absolute inset-0 z-[3]">
                <SpiritModeRail
                  ariaLabel="Spirit modes"
                  options={MODE_OPTIONS.map((mode) => ({
                    ...mode,
                    testId: `spirit-bind-mode-${mode.id}`,
                  }))}
                  value={draft.mode}
                  accentColor={bindAccent}
                  onChange={setMode}
                  className="pointer-events-auto absolute left-3 top-[84px] h-[500px] w-[214px]"
                />
              </div>

              <div
                className="pointer-events-none absolute left-[54px] top-[56px] z-[4]"
                style={{ color: "rgba(236,233,225,0.64)" }}
              >
                <div className="font-mono text-[9px] uppercase tracking-[0.18em]">
                  {stageCaption}
                </div>
              </div>
            </div>

            <div
              className="mt-6 flex items-center justify-between gap-6 border-t px-1 pt-5"
              style={{ borderColor: "rgba(212,168,75,0.08)" }}
            >
              <div className="min-w-0">
                <div
                  className="font-mono text-[9px] uppercase tracking-[0.16em]"
                  style={{ color: "rgba(212,168,75,0.62)" }}
                >
                  Apply to hunt
                </div>
                <div
                  className="mt-1 text-[12px]"
                  style={{ color: "rgba(182,183,193,0.66)", lineHeight: 1.45 }}
                >
                  {footerLine}
                </div>
              </div>

              <button
                type="button"
                data-testid="spirit-bind-submit"
                disabled={!canBind}
                onClick={() => {
                  if (!canBind) return;
                  onBind(buildSpiritBindCommit(context, draftRef.current));
                }}
                className="rounded-full px-4 py-2.5 text-[12px] font-medium transition-all"
                style={{
                  border: `1px solid ${canBind ? `${bindAccent}46` : "rgba(171,177,191,0.18)"}`,
                  background: "linear-gradient(180deg, rgba(16,20,30,0.94), rgba(8,11,19,0.98))",
                  color: canBind ? "rgba(244,225,177,0.92)" : "rgba(182,183,193,0.44)",
                  cursor: canBind ? "pointer" : "not-allowed",
                  boxShadow: canBind ? `0 10px 24px ${bindAccent}18` : "none",
                }}
              >
                Apply spirit
              </button>
            </div>
          </div>
        </main>

        <aside
          className={surface === "page" ? "flex flex-col px-0 py-2 pr-2" : "flex flex-col px-5 py-5"}
          style={{
            borderLeft: "1px solid rgba(212,168,75,0.08)",
            background: surface === "page"
              ? "transparent"
              : "linear-gradient(180deg, rgba(5,7,12,0.38), rgba(3,5,9,0.18))",
          }}
        >
          <div data-testid="spirit-bind-read-panel">
            <div
              className="font-mono text-[9px] uppercase tracking-[0.16em]"
              style={{ color: "rgba(212,168,75,0.62)" }}
            >
              Spirit
            </div>
            <div className="mt-2 text-[22px]" style={{ color: "rgba(241,239,234,0.92)", lineHeight: 1.2 }}>
              {candidate.label}
            </div>
            <div className="mt-3 text-[12px]" style={{ color: "rgba(236,233,225,0.72)", lineHeight: 1.55 }}>
              {readReason}
            </div>
            <div className="mt-4">{renderPinToggle(true)}</div>
          </div>

          <div
            className="mt-5 border-t pt-4"
            style={{ borderColor: "rgba(212,168,75,0.08)" }}
          >
            {activeControl}
          </div>
        </aside>
      </div>
    </section>
  );
}
