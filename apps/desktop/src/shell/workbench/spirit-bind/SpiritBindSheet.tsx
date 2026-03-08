import { useMemo, type CSSProperties } from "react";
import type { Artifact } from "../huntTypes";
import { HUNT_SPIRIT_KINDS, getHuntSpiritMeta } from "../spirit";
import { buildSpiritBindPreviewModel } from "./preview";
import { buildSpiritBindCommit, canBindSpiritDraft, deriveSpiritBindCandidate } from "./suggestions";
import type { SpiritBindCommit, SpiritBindContext, SpiritBindMode } from "./types";
import { MAX_ANCHORS, useSpiritBindDraft } from "./useSpiritBindDraft";

const MODE_LABELS: Array<{ id: SpiritBindMode; label: string; caption: string }> = [
  { id: "quick-bind", label: "Quick Bind", caption: "Infer from the current hunt and move in one click." },
  { id: "thesis", label: "Thesis", caption: "Author one sentence to fix the hunt posture." },
  { id: "anchor-artifacts", label: "Anchor Artifacts", caption: "Choose up to three artifacts that define the center." },
  { id: "manual", label: "Manual Spirit", caption: "Override the suggestion with a direct spirit choice." },
];

function panelStyle(borderColor: string) {
  return {
    border: `1px solid ${borderColor}`,
    background: "linear-gradient(180deg, rgba(13,16,24,0.98), rgba(8,10,16,0.96))",
    boxShadow: "0 20px 48px rgba(0,0,0,0.34)",
  } satisfies CSSProperties;
}

function renderArtifactLabel(artifact: Artifact): string {
  return `${artifact.title} · ${artifact.kind}`;
}

export function SpiritBindSheet({
  context,
  isOpen,
  onBind,
  onDismiss,
  onSkip,
}: {
  context: SpiritBindContext;
  isOpen: boolean;
  onBind: (commit: SpiritBindCommit) => void;
  onDismiss: () => void;
  onSkip: () => void;
}) {
  const { draft, setMode, setThesis, toggleAnchor, setManualKind, setPinned } = useSpiritBindDraft();

  const candidate = useMemo(() => deriveSpiritBindCandidate(context, draft), [context, draft]);
  const preview = useMemo(() => buildSpiritBindPreviewModel(context, candidate), [candidate, context]);
  const canBind = canBindSpiritDraft(draft);

  if (!isOpen) {
    return null;
  }

  const bindAccent = preview.dock.accentColor;
  const artifacts = context.hunt.artifactIds
    .map((id) => context.artifacts[id])
    .filter((artifact): artifact is Artifact => Boolean(artifact));

  return (
    <section
      aria-label="Bind Spirit"
      className="flex w-[760px] flex-col overflow-hidden rounded-2xl"
      style={panelStyle("rgba(213,173,87,0.18)")}
      data-testid="spirit-bind-sheet"
    >
      <header
        className="flex items-start justify-between gap-4 border-b px-5 py-4"
        style={{ borderColor: "rgba(213,173,87,0.12)" }}
      >
        <div>
          <div
            className="font-mono text-[11px] uppercase tracking-[0.14em]"
            style={{ color: "rgba(213,173,87,0.78)" }}
          >
            Bind Spirit
          </div>
          <div className="mt-2 text-[22px]" style={{ color: "rgba(236,233,225,0.94)" }}>
            {context.hunt.title}
          </div>
          <div className="mt-1 text-[12px]" style={{ color: "rgba(182,183,193,0.64)" }}>
            Draft the hunt now, release it into the dock, wake, and workspace when ready.
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            className="rounded-full border px-3 py-1.5 text-[12px]"
            style={{ borderColor: "rgba(182,183,193,0.18)", color: "rgba(182,183,193,0.7)" }}
            onClick={onSkip}
            data-testid="spirit-bind-skip"
          >
            Skip for now
          </button>
          <button
            type="button"
            className="rounded-full border px-3 py-1.5 text-[12px]"
            style={{ borderColor: "rgba(182,183,193,0.18)", color: "rgba(236,233,225,0.82)" }}
            onClick={onDismiss}
            data-testid="spirit-bind-dismiss"
          >
            Dismiss
          </button>
        </div>
      </header>

      <div className="grid grid-cols-[1.15fr_0.85fr] gap-0">
        <div className="border-r px-5 py-4" style={{ borderColor: "rgba(213,173,87,0.08)" }}>
          <div className="grid grid-cols-2 gap-2" role="tablist" aria-label="Bind Spirit modes">
            {MODE_LABELS.map((mode) => {
              const active = draft.mode === mode.id;
              return (
                <button
                  key={mode.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  className="rounded-xl border px-3 py-3 text-left transition-colors"
                  style={{
                    borderColor: active ? `${bindAccent}66` : "rgba(182,183,193,0.12)",
                    background: active ? `${bindAccent}14` : "rgba(232,230,222,0.02)",
                  }}
                  onClick={() => setMode(mode.id)}
                  data-testid={`spirit-bind-mode-${mode.id}`}
                >
                  <div className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: active ? bindAccent : "rgba(236,233,225,0.86)" }}>
                    {mode.label}
                  </div>
                  <div className="mt-1 text-[11px]" style={{ color: "rgba(182,183,193,0.62)", lineHeight: 1.35 }}>
                    {mode.caption}
                  </div>
                </button>
              );
            })}
          </div>

          <div className="mt-4 rounded-2xl border p-4" style={{ borderColor: "rgba(213,173,87,0.12)", background: "rgba(232,230,222,0.02)" }}>
            {draft.mode === "quick-bind" && (
              <div data-testid="spirit-bind-quick-panel">
                <div className="font-mono text-[11px] uppercase tracking-[0.1em]" style={{ color: "rgba(213,173,87,0.76)" }}>
                  Suggested posture
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <div className="rounded-full border px-3 py-1 text-[13px]" style={{ borderColor: `${bindAccent}50`, color: bindAccent }}>
                    {candidate.label}
                  </div>
                  <div className="text-[12px]" style={{ color: "rgba(182,183,193,0.68)" }}>
                    Confidence {candidate.confidenceScore}%
                  </div>
                </div>
                <p className="mt-3 text-[13px]" style={{ color: "rgba(236,233,225,0.82)", lineHeight: 1.5 }}>
                  {candidate.rationale}
                </p>
              </div>
            )}

            {draft.mode === "thesis" && (
              <label className="block" data-testid="spirit-bind-thesis-panel">
                <div className="font-mono text-[11px] uppercase tracking-[0.1em]" style={{ color: "rgba(213,173,87,0.76)" }}>
                  What are you chasing?
                </div>
                <textarea
                  value={draft.thesis}
                  onChange={(event) => setThesis(event.target.value)}
                  rows={4}
                  placeholder="Trace lateral movement through the sandbox execution chain"
                  className="mt-3 w-full rounded-xl border bg-transparent px-3 py-2 text-[13px] outline-none"
                  style={{ borderColor: "rgba(182,183,193,0.18)", color: "rgba(236,233,225,0.88)", resize: "none" }}
                  data-testid="spirit-bind-thesis-input"
                />
              </label>
            )}

            {draft.mode === "anchor-artifacts" && (
              <div data-testid="spirit-bind-anchor-panel">
                <div className="flex items-center justify-between">
                  <div className="font-mono text-[11px] uppercase tracking-[0.1em]" style={{ color: "rgba(213,173,87,0.76)" }}>
                    Choose anchors
                  </div>
                  <div className="text-[11px]" style={{ color: "rgba(182,183,193,0.58)" }}>
                    {draft.selectedAnchorArtifactIds.length}/{MAX_ANCHORS}
                  </div>
                </div>
                <div className="mt-3 grid gap-2">
                  {artifacts.map((artifact) => {
                    const selected = draft.selectedAnchorArtifactIds.includes(artifact.id);
                    const disabled =
                      !selected && draft.selectedAnchorArtifactIds.length >= MAX_ANCHORS;

                    return (
                      <button
                        key={artifact.id}
                        type="button"
                        className="flex items-center justify-between rounded-xl border px-3 py-2 text-left"
                        style={{
                          borderColor: selected ? `${bindAccent}5a` : "rgba(182,183,193,0.14)",
                          background: selected ? `${bindAccent}12` : "transparent",
                          opacity: disabled ? 0.45 : 1,
                        }}
                        onClick={() => toggleAnchor(artifact.id)}
                        disabled={disabled}
                        data-testid={`spirit-bind-anchor-${artifact.id}`}
                      >
                        <span className="text-[13px]" style={{ color: "rgba(236,233,225,0.86)" }}>
                          {renderArtifactLabel(artifact)}
                        </span>
                        <span className="text-[11px]" style={{ color: selected ? bindAccent : "rgba(182,183,193,0.5)" }}>
                          {selected ? "Anchored" : "Select"}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {draft.mode === "manual" && (
              <div data-testid="spirit-bind-manual-panel">
                <div className="font-mono text-[11px] uppercase tracking-[0.1em]" style={{ color: "rgba(213,173,87,0.76)" }}>
                  Choose spirit
                </div>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  {HUNT_SPIRIT_KINDS.map((kind) => {
                    const meta = getHuntSpiritMeta(kind);
                    const active = draft.manualKind === kind;
                    return (
                      <button
                        key={kind}
                        type="button"
                        className="rounded-xl border px-3 py-3 text-left"
                        style={{
                          borderColor: active ? `${meta?.accentColor ?? bindAccent}66` : "rgba(182,183,193,0.14)",
                          background: active ? `${meta?.accentColor ?? bindAccent}14` : "transparent",
                        }}
                        onClick={() => setManualKind(kind)}
                        data-testid={`spirit-bind-manual-${kind}`}
                      >
                        <div className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: meta?.accentColor ?? bindAccent }}>
                          {meta?.label ?? kind}
                        </div>
                        <div className="mt-1 text-[11px]" style={{ color: "rgba(182,183,193,0.62)" }}>
                          {(meta?.defaultBiases ?? []).map((entry) => entry.replace("-", " ")).join(", ")}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 rounded-2xl border p-4" style={{ borderColor: "rgba(213,173,87,0.12)", background: "rgba(232,230,222,0.02)" }}>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="font-mono text-[11px] uppercase tracking-[0.1em]" style={{ color: "rgba(213,173,87,0.76)" }}>
                  Candidate
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <div className="rounded-full border px-3 py-1 text-[13px]" style={{ borderColor: `${bindAccent}50`, color: bindAccent }}>
                    {candidate.label}
                  </div>
                  <div className="text-[12px]" style={{ color: "rgba(182,183,193,0.68)" }}>
                    {candidate.liveMood}
                  </div>
                </div>
              </div>
              <label className="flex items-center gap-2 text-[12px]" style={{ color: "rgba(236,233,225,0.82)" }}>
                <input
                  type="checkbox"
                  checked={draft.isPinned}
                  onChange={(event) => setPinned(event.target.checked)}
                  data-testid="spirit-bind-pin-toggle"
                />
                Pin spirit
              </label>
            </div>

            <p className="mt-3 text-[13px]" style={{ color: "rgba(236,233,225,0.82)", lineHeight: 1.5 }}>
              {candidate.rationale}
            </p>
            <p className="mt-2 text-[12px]" style={{ color: "rgba(182,183,193,0.66)", lineHeight: 1.5 }}>
              {candidate.biasLine}
            </p>

            <div className="mt-3 flex flex-wrap gap-2">
              {candidate.alternates.map((alternate) => (
                <button
                  key={alternate.kind}
                  type="button"
                  className="rounded-full border px-2.5 py-1 text-[11px]"
                  style={{ borderColor: "rgba(182,183,193,0.18)", color: "rgba(182,183,193,0.72)" }}
                  onClick={() => setManualKind(alternate.kind)}
                  data-testid={`spirit-bind-alternate-${alternate.kind}`}
                >
                  Try {alternate.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="px-5 py-4">
          <div className="font-mono text-[11px] uppercase tracking-[0.14em]" style={{ color: "rgba(213,173,87,0.78)" }}>
            Preview
          </div>
          <div className="mt-3 grid gap-3">
            <div className="rounded-2xl border p-4" style={{ borderColor: `${bindAccent}38`, background: `${bindAccent}12` }}>
              <div className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: bindAccent }}>
                Dock pill
              </div>
              <div className="mt-3 flex items-center gap-3">
                <div
                  className="flex h-10 w-10 items-center justify-center rounded-xl border"
                  style={{ borderColor: `${bindAccent}66`, color: bindAccent }}
                >
                  {preview.dock.label.charAt(0)}
                </div>
                <div>
                  <div className="text-[14px]" style={{ color: "rgba(236,233,225,0.9)" }}>
                    {preview.dock.label}
                  </div>
                  <div className="text-[11px]" style={{ color: "rgba(182,183,193,0.64)" }}>
                    {preview.dock.detail}
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border p-4" style={{ borderColor: "rgba(213,173,87,0.12)", background: "rgba(232,230,222,0.02)" }}>
              <div className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: "rgba(213,173,87,0.72)" }}>
                Sidebar wake
              </div>
              <div className="mt-2 text-[14px]" style={{ color: "rgba(236,233,225,0.88)" }}>
                {preview.sidebar.wakeTitle}
              </div>
              <div className="mt-2 text-[12px]" style={{ color: "rgba(182,183,193,0.68)", lineHeight: 1.5 }}>
                {preview.sidebar.wakeReason}
              </div>
              <div className="mt-2 text-[12px]" style={{ color: bindAccent }}>
                {preview.sidebar.biasLine}
              </div>
            </div>

            <div className="rounded-2xl border p-4" style={{ borderColor: "rgba(213,173,87,0.12)", background: "rgba(232,230,222,0.02)" }}>
              <div className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: "rgba(213,173,87,0.72)" }}>
                Workspace release
              </div>
              <div className="mt-2 text-[14px]" style={{ color: "rgba(236,233,225,0.88)" }}>
                {preview.workspace.title}
              </div>
              <div className="mt-2 flex items-center gap-2 text-[12px]" style={{ color: "rgba(182,183,193,0.66)" }}>
                <span className="rounded-full border px-2 py-0.5" style={{ borderColor: "rgba(182,183,193,0.18)" }}>
                  stance {preview.workspace.stance}
                </span>
                <span>{preview.workspace.motionLabel}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="button"
              className="rounded-full border px-4 py-2 text-[12px]"
              style={{ borderColor: "rgba(182,183,193,0.18)", color: "rgba(182,183,193,0.72)" }}
              onClick={onSkip}
            >
              Keep hunt unbound
            </button>
            <button
              type="button"
              className="rounded-full px-4 py-2 text-[12px] font-medium transition-opacity"
              style={{
                background: bindAccent,
                color: "#071019",
                opacity: canBind ? 1 : 0.45,
                cursor: canBind ? "pointer" : "not-allowed",
              }}
              onClick={() => {
                if (!canBind) return;
                onBind(buildSpiritBindCommit(context, draft));
              }}
              data-testid="spirit-bind-submit"
            >
              Bind Spirit
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
