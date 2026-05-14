// apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx
// Plan 04-03: Full spirit creation chamber replacing Phase 2 plain form.
// SpiritAtmosphereLayer + SpiritManifestationCanvas + kind pill selector + bind/unbind.
import { useMemo, useState } from "react";
import type { SpiritKind } from "../types";
import { useSpiritStore } from "../stores/spirit-store";
import { buildSpiritManifestationModel } from "./spirit-ritual/canvas/model";
import type { SpiritBindCandidate, SpiritBindContext } from "./spirit-ritual/canvas/model";
import { SpiritManifestationCanvas } from "./spirit-ritual/canvas/SpiritManifestationCanvas";
import { SpiritAtmosphereLayer } from "./spirit-ritual/atmosphere/SpiritAtmosphereLayer";

// Maps workbench SpiritKind to huntronomer HuntSpiritKind
const SPIRIT_KIND_TO_HUNT_KIND: Record<SpiritKind, "tracker" | "lantern" | "ledger" | "forge"> = {
  sentinel: "tracker",
  oracle: "lantern",
  witness: "ledger",
  specter: "forge",
};

// Accent color map (same as spirit-store SPIRIT_ACCENT_MAP — kept local to avoid import coupling)
const SPIRIT_ACCENT_MAP: Record<SpiritKind, string> = {
  sentinel: "#3dbf84",
  oracle: "#7b68ee",
  witness: "#d4a84b",
  specter: "#c45c5c",
};

const SPIRIT_KIND_OPTIONS: { value: SpiritKind; label: string }[] = [
  { value: "sentinel", label: "Sentinel" },
  { value: "oracle", label: "Oracle" },
  { value: "witness", label: "Witness" },
  { value: "specter", label: "Specter" },
];

export function SpiritChamberTab() {
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();

  // Default selected kind to bound kind if a spirit is already bound
  const [selectedKind, setSelectedKind] = useState<SpiritKind>(kind ?? "sentinel");

  const model = useMemo(() => {
    const huntKind = SPIRIT_KIND_TO_HUNT_KIND[selectedKind];
    const selectedAccent = SPIRIT_ACCENT_MAP[selectedKind];

    const syntheticContext: SpiritBindContext = {
      hunt: {
        id: "workbench-spirit",
        title: "Workbench",
        spirit: null,
        artifactIds: [],
        color: accentColor ?? selectedAccent,
      },
      artifacts: {},
      runs: {},
      currentLens: null,
      currentShell: null,
      activeStationId: null,
    };

    const candidate: SpiritBindCandidate = {
      kind: huntKind,
      label: SPIRIT_KIND_OPTIONS.find((o) => o.value === selectedKind)?.label ?? selectedKind,
      confidenceScore: 0.75,
      rationale: "Manual selection.",
      biasLine: "Pulls toward the active workspace.",
      predictedFocusSurfaces: [],
      alternates: [],
      liveMood: "attuned",
      bindSource: "manual",
      thesis: null,
      anchorArtifactIds: [],
    };

    return buildSpiritManifestationModel(syntheticContext, candidate);
  }, [selectedKind, accentColor]);

  function handleBind() {
    useSpiritStore.getState().actions.bindSpirit(selectedKind);
  }

  function handleUnbind() {
    useSpiritStore.getState().actions.unbindSpirit();
  }

  return (
    <div className="relative flex-1 overflow-hidden" style={{ minHeight: 0 }}>
      {/* Atmosphere layer — absolute inset, z-[2] */}
      <SpiritAtmosphereLayer
        model={model}
        reducedMotion={false}
        className="absolute inset-0 z-[2]"
      />

      {/* Manifestation canvas — absolute inset, z-[3], centered */}
      <div className="absolute inset-0 z-[3] flex items-center justify-center p-6">
        <SpiritManifestationCanvas
          model={model}
          className="w-full max-w-[560px]"
          showLegend
        />
      </div>

      {/* Controls overlay — bottom bar, z-[10] */}
      <div className="absolute inset-x-0 bottom-8 z-[10] flex flex-col items-center gap-3">
        {/* Kind pill row */}
        <div className="flex gap-2">
          {SPIRIT_KIND_OPTIONS.map((opt) => {
            const isSelected = selectedKind === opt.value;
            const pillAccent = SPIRIT_ACCENT_MAP[opt.value];
            return (
              <button
                key={opt.value}
                type="button"
                aria-pressed={isSelected}
                onClick={() => setSelectedKind(opt.value)}
                className="rounded-full px-4 py-1.5 text-[12px] font-medium transition-all"
                style={{
                  border: `1px solid ${isSelected ? `${pillAccent}60` : "rgba(171,177,191,0.18)"}`,
                  background: isSelected
                    ? `linear-gradient(180deg, ${pillAccent}18, rgba(8,11,18,0.82))`
                    : "rgba(255,255,255,0.03)",
                  color: isSelected ? "rgba(241,239,234,0.92)" : "rgba(182,183,193,0.64)",
                  boxShadow: isSelected ? `0 0 16px ${pillAccent}22` : "none",
                }}
              >
                {opt.label}
              </button>
            );
          })}
        </div>

        {/* Bind / Unbind buttons */}
        <div className="flex gap-2">
          {kind === null ? (
            <button
              type="button"
              onClick={handleBind}
              className="rounded-full px-5 py-2 text-[13px] font-medium transition-all"
              style={{
                border: `1px solid ${SPIRIT_ACCENT_MAP[selectedKind]}46`,
                background: "linear-gradient(180deg, rgba(16,20,30,0.94), rgba(8,11,19,0.98))",
                color: "rgba(244,225,177,0.92)",
                boxShadow: `0 10px 24px ${SPIRIT_ACCENT_MAP[selectedKind]}18`,
              }}
            >
              Bind
            </button>
          ) : (
            <button
              type="button"
              onClick={handleUnbind}
              className="rounded-full px-5 py-2 text-[13px] font-medium transition-all"
              style={{
                border: "1px solid rgba(196,92,92,0.36)",
                background: "linear-gradient(180deg, rgba(16,20,30,0.94), rgba(8,11,19,0.98))",
                color: "rgba(220,180,180,0.82)",
              }}
            >
              Unbind
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
