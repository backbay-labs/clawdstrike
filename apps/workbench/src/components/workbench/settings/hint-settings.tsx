import {
  useHintSettings,
  HINT_LABELS,
  DEFAULT_HINTS,
  type HintId,
} from "@/lib/workbench/use-hint-settings";
import { IconBrain, IconRefresh, IconCheck } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useState, useCallback } from "react";


const HINT_GROUPS: { label: string; ids: HintId[] }[] = [
  {
    label: "Dashboard & Editor",
    ids: ["home.audit", "editor.validate"],
  },
  {
    label: "Simulator & Analysis",
    ids: ["simulator.scenarios", "compliance.check", "observe.synth", "risk.assess"],
  },
  {
    label: "Library Prompts",
    ids: ["library.audit", "library.testSuite", "library.harden", "library.compare"],
  },
];

// Dot colors per group (matching the design language)
const GROUP_COLORS = ["#d4a84b", "#3dbf84", "#8b5cf6"];


export function HintSettings() {
  const {
    showHints,
    setShowHints,
    getHint,
    updateHint,
    resetHint,
    resetAll,
    isCustomized,
  } = useHintSettings();

  const [resetConfirm, setResetConfirm] = useState(false);

  const handleResetAll = useCallback(() => {
    if (!resetConfirm) {
      setResetConfirm(true);
      setTimeout(() => setResetConfirm(false), 3000);
      return;
    }
    resetAll();
    setResetConfirm(false);
  }, [resetConfirm, resetAll]);

  const hasAnyCustomized = HINT_GROUPS.some((g) => g.ids.some((id) => isCustomized(id)));

  return (
    <div className="flex flex-col gap-6">
      {/* Master toggle + reset all */}
      <div className="flex items-center justify-between gap-4 p-4 rounded-lg border border-[#2d3240] bg-[#131721]/50">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 flex items-center justify-center shrink-0">
            <IconBrain size={16} stroke={1.5} className="text-[#8b5cf6]" />
          </div>
          <div className="min-w-0">
            <p className="text-xs font-medium text-[#ece7dc]">Show Claude Code Hints</p>
            <p className="text-[10px] text-[#6f7f9a] mt-0.5">
              Display contextual AI prompts throughout the workbench
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {hasAnyCustomized && (
            <button
              onClick={handleResetAll}
              className={cn(
                "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-medium border transition-colors",
                resetConfirm
                  ? "text-[#c45c5c] border-[#c45c5c]/30 bg-[#c45c5c]/10"
                  : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:text-[#ece7dc] hover:border-[#2d3240]",
              )}
            >
              <IconRefresh size={11} stroke={1.5} />
              {resetConfirm ? "Confirm reset?" : "Reset All"}
            </button>
          )}
          <button
            onClick={() => setShowHints(!showHints)}
            role="switch"
            aria-checked={showHints}
            aria-label="Show Claude Code Hints"
            className="flex items-center gap-2.5 group"
          >
            <span
              className={cn(
                "relative inline-flex h-[18px] w-[32px] shrink-0 items-center rounded-full border transition-colors",
                showHints
                  ? "bg-[#8b5cf6] border-[#8b5cf6]"
                  : "bg-[#2d3240] border-[#2d3240]",
              )}
            >
              <span
                className={cn(
                  "block h-3.5 w-3.5 rounded-full bg-[#0b0d13] transition-transform",
                  showHints ? "translate-x-[14px]" : "translate-x-[1px]",
                )}
              />
            </span>
          </button>
        </div>
      </div>

      {/* Hint groups */}
      {HINT_GROUPS.map((group, gi) => (
        <div key={group.label}>
          <h3 className="text-[10px] font-mono font-semibold uppercase tracking-[0.12em] text-[#6f7f9a] mb-3 flex items-center gap-2">
            <span
              className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{ backgroundColor: GROUP_COLORS[gi] }}
            />
            {group.label}
          </h3>
          <div className="flex flex-col gap-3">
            {group.ids.map((id) => (
              <HintCard
                key={id}
                id={id}
                dotColor={GROUP_COLORS[gi]}
                hint={getHint(id)}
                customized={isCustomized(id)}
                onUpdate={(patch) => updateHint(id, patch)}
                onReset={() => resetHint(id)}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}


function HintCard({
  id,
  dotColor,
  hint,
  customized,
  onUpdate,
  onReset,
}: {
  id: HintId;
  dotColor: string;
  hint: { hint: string; prompt: string };
  customized: boolean;
  onUpdate: (patch: { hint?: string; prompt?: string }) => void;
  onReset: () => void;
}) {
  const defaults = DEFAULT_HINTS[id];
  const [resetDone, setResetDone] = useState(false);

  const handleReset = useCallback(() => {
    onReset();
    setResetDone(true);
    setTimeout(() => setResetDone(false), 1500);
  }, [onReset]);

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/50 p-4">
      {/* Header row */}
      <div className="flex items-center gap-2 mb-3">
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ backgroundColor: dotColor }}
        />
        <span className="text-[11px] font-medium text-[#ece7dc] truncate">
          {HINT_LABELS[id]}
        </span>
        {customized && (
          <span className="ml-1 px-1.5 py-0 text-[8px] font-mono uppercase tracking-wider border rounded text-[#d4a84b] border-[#d4a84b]/20 bg-[#d4a84b]/10">
            customized
          </span>
        )}
        {customized && (
          <button
            onClick={handleReset}
            className="ml-auto flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            {resetDone ? (
              <>
                <IconCheck size={9} stroke={2} className="text-[#3dbf84]" />
                <span className="text-[#3dbf84]">Reset</span>
              </>
            ) : (
              <>
                <IconRefresh size={9} stroke={1.5} />
                Reset
              </>
            )}
          </button>
        )}
      </div>

      {/* Description field */}
      <div className="mb-2.5">
        <label className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-1 block">
          Description
        </label>
        <input
          type="text"
          value={hint.hint}
          onChange={(e) => onUpdate({ hint: e.target.value })}
          placeholder={defaults.hint}
          className="w-full h-8 px-2.5 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/30 focus:border-[#8b5cf6]/50 focus:outline-none focus:ring-1 focus:ring-[#8b5cf6]/20 transition-colors"
        />
      </div>

      {/* Prompt field */}
      <div>
        <label className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-1 block">
          Prompt
        </label>
        <textarea
          value={hint.prompt}
          onChange={(e) => onUpdate({ prompt: e.target.value })}
          placeholder={defaults.prompt}
          rows={3}
          className="w-full px-2.5 py-2 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/30 focus:border-[#8b5cf6]/50 focus:outline-none focus:ring-1 focus:ring-[#8b5cf6]/20 transition-colors resize-none leading-relaxed font-mono"
        />
      </div>
    </div>
  );
}
