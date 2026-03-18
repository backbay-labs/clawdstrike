// apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx
import { useState } from "react";
import { useSpiritStore } from "../stores/spirit-store";
import type { SpiritKind } from "../types";

const SPIRIT_KIND_OPTIONS: { value: SpiritKind; label: string }[] = [
  { value: "sentinel", label: "Sentinel" },
  { value: "oracle", label: "Oracle" },
  { value: "witness", label: "Witness" },
  { value: "specter", label: "Specter" },
];

export function SpiritChamberTab() {
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();
  const mood = useSpiritStore.use.mood();

  const [selectedKind, setSelectedKind] = useState<SpiritKind>("sentinel");

  function handleBind() {
    useSpiritStore.getState().actions.bindSpirit(selectedKind);
  }

  function handleUnbind() {
    useSpiritStore.getState().actions.unbindSpirit();
  }

  return (
    <div className="flex flex-1 flex-col items-center justify-center p-6">
      <div className="w-full max-w-xs rounded-lg border border-[#2d3240] bg-[#0b0d13] p-5 flex flex-col gap-4">
        {/* Header */}
        <div className="flex items-center gap-2">
          <span className="font-display font-semibold text-[14px] text-[#ece7dc]">
            Spirit Chamber
          </span>
        </div>

        {/* Current spirit status */}
        <div className="flex items-center gap-2 text-[12px]">
          {kind !== null && accentColor !== null ? (
            <>
              <span
                aria-label="Spirit accent color"
                style={{
                  display: "inline-block",
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  backgroundColor: accentColor,
                  boxShadow: `0 0 6px ${accentColor}66`,
                  flexShrink: 0,
                }}
              />
              <span className="text-[#ece7dc] capitalize">
                {kind} bound — {mood}
              </span>
            </>
          ) : (
            <span className="text-[#6f7f9a]">No spirit bound</span>
          )}
        </div>

        {/* Kind selector — shown only when no spirit is bound */}
        {kind === null && (
          <div className="flex flex-col gap-1">
            <label
              htmlFor="spirit-kind-select"
              className="text-[11px] font-medium text-[#6f7f9a] uppercase tracking-wider"
            >
              Kind
            </label>
            <select
              id="spirit-kind-select"
              value={selectedKind}
              onChange={(e) => setSelectedKind(e.target.value as SpiritKind)}
              className="w-full rounded border border-[#2d3240] bg-[#131721] px-2 py-1.5 text-[13px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/50"
            >
              {SPIRIT_KIND_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Action buttons */}
        <div className="flex gap-2">
          {kind === null ? (
            <button
              type="button"
              onClick={handleBind}
              className="flex-1 rounded border border-[#2d3240] bg-[#131721] px-3 py-1.5 text-[13px] font-medium text-[#ece7dc] transition-colors hover:border-[#d4a84b]/40 hover:text-[#d4a84b]"
            >
              Bind
            </button>
          ) : (
            <button
              type="button"
              onClick={handleUnbind}
              className="flex-1 rounded border border-[#2d3240] bg-[#131721] px-3 py-1.5 text-[13px] font-medium text-[#6f7f9a] transition-colors hover:border-[#c45c5c]/40 hover:text-[#c45c5c]"
            >
              Unbind
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
