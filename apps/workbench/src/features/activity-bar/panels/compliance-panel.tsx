import { useMemo, useState } from "react";
import { IconCheckbox } from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  COMPLIANCE_FRAMEWORKS,
  scoreFramework,
} from "@/lib/workbench/compliance-requirements";
import { MiniScoreRing } from "@/components/workbench/compliance/framework-selector";
import { usePaneStore } from "@/features/panes/pane-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

// ---------------------------------------------------------------------------
// CompliancePanel -- framework selector with score rings and score bars.
//
// Shows compliance frameworks with MiniScoreRing indicators, a summary
// section for the selected framework with per-requirement score bars,
// and an overall score in the footer.
// ---------------------------------------------------------------------------

function getScoreColor(score: number): string {
  if (score > 80) return "#3dbf84";
  if (score >= 50) return "#d4a84b";
  return "#c45c5c";
}

// ---------------------------------------------------------------------------
// CompliancePanel
// ---------------------------------------------------------------------------

export function CompliancePanel() {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const guards = (editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }).guards;
  const settings = (editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }).settings;

  const [selectedFrameworkId, setSelectedFrameworkId] = useState<string>(
    COMPLIANCE_FRAMEWORKS[0]?.id ?? "",
  );

  // Score each framework
  const frameworkScores = useMemo(() => {
    return COMPLIANCE_FRAMEWORKS.map((fw) => {
      const result = scoreFramework(fw.id, guards, settings);
      return {
        id: fw.id,
        name: fw.name,
        shortName: fw.shortName,
        score: result.score,
        met: result.met,
        gaps: result.gaps,
        requirements: fw.requirements,
      };
    });
  }, [guards, settings]);

  const selectedFramework = useMemo(
    () => frameworkScores.find((fw) => fw.id === selectedFrameworkId),
    [frameworkScores, selectedFrameworkId],
  );

  const handleOpenCompliance = () => {
    usePaneStore.getState().openApp("/compliance", "Compliance");
  };

  // Empty state
  if (COMPLIANCE_FRAMEWORKS.length === 0) {
    return (
      <div className="flex flex-col h-full">
        {/* Panel header */}
        <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
          <span className="font-display font-semibold text-sm text-[#ece7dc]">
            Compliance
          </span>
        </div>

        <div className="flex-1 flex flex-col items-center justify-center py-8 text-center gap-1">
          <IconCheckbox size={28} stroke={1} className="text-[#6f7f9a]/30" />
          <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
            No Frameworks
          </span>
          <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
            Configure compliance frameworks in the full compliance dashboard.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <button
        type="button"
        onClick={handleOpenCompliance}
        className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40 w-full text-left hover:bg-[#131721]/20 transition-colors"
      >
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          Compliance
        </span>
      </button>

      <ScrollArea className="flex-1">
        {/* Frameworks section */}
        <div className="px-3 py-1">
          <div className="flex items-center gap-1 w-full px-0 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider">
            FRAMEWORKS
          </div>

          <div className="flex flex-col gap-1">
            {frameworkScores.map((fw) => {
              const isSelected = fw.id === selectedFrameworkId;

              return (
                <button
                  key={fw.id}
                  type="button"
                  onClick={() => setSelectedFrameworkId(fw.id)}
                  className={`flex items-center gap-2 w-full h-11 px-2 rounded-lg border transition-all duration-150 text-left ${
                    isSelected
                      ? "border-[#d4a84b]/40 bg-[#d4a84b]/5"
                      : "border-transparent hover:bg-[#131721]/40"
                  }`}
                >
                  <MiniScoreRing score={fw.score} size={32} />
                  <span
                    className={`text-[11px] font-mono truncate ${
                      isSelected ? "text-[#ece7dc]" : "text-[#6f7f9a]"
                    }`}
                  >
                    {fw.name}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Selected framework summary */}
        {selectedFramework && (
          <div className="px-3 py-1 border-t border-[#2d3240]/40">
            <div className="flex items-center gap-1 w-full px-0 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider">
              {selectedFramework.shortName} SUMMARY
            </div>

            <div className="flex flex-col gap-2 py-1">
              {selectedFramework.requirements.map((req) => {
                const isMet = selectedFramework.met.some(
                  (m) => m.id === req.id,
                );
                const score = isMet ? 100 : 0;
                const color = getScoreColor(score);

                return (
                  <div key={req.id}>
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1 mr-2">
                        {req.title}
                      </span>
                      <span
                        className="text-[9px] font-mono shrink-0"
                        style={{ color }}
                      >
                        {score}%
                      </span>
                    </div>
                    {/* Progress bar */}
                    <div className="w-full h-1 bg-[#2d3240] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${score}%`,
                          backgroundColor: color,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </ScrollArea>

      {/* Footer */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          Overall: {selectedFramework?.score ?? 0}%
        </span>
      </div>
    </div>
  );
}
