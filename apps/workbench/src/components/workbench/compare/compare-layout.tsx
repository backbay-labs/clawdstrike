import { useState, useCallback, useEffect, useRef } from "react";
import type { WorkbenchPolicy } from "@/lib/workbench/types";
import { PolicySelector } from "./policy-selector";
import { YamlDiffView } from "./yaml-diff-view";
import { SemanticDiffView } from "./semantic-diff-view";
import { cn } from "@/lib/utils";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

type DiffTab = "yaml" | "semantic";

export function CompareLayout() {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  // activeTab not needed in this component
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));

  const [activeTab, setActiveTab] = useState<DiffTab>("yaml");

  const [policyA, setPolicyA] = useState<WorkbenchPolicy>((editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }));
  const [yamlA, setYamlA] = useState<string>((editState?.yaml ?? ""));
  /** Tracks whether the user has manually selected a different Policy A. */
  const userSelectedARef = useRef(false);

  const [policyB, setPolicyB] = useState<WorkbenchPolicy | null>(null);
  const [yamlB, setYamlB] = useState<string>("");

  // Keep Policy A in sync with the active store policy unless the user
  // has explicitly chosen a different policy via the selector.
  useEffect(() => {
    if (!userSelectedARef.current) {
      setPolicyA((editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }));
      setYamlA((editState?.yaml ?? ""));
    }
  }, [(editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }), (editState?.yaml ?? "")]);

  const handleSelectA = useCallback(
    (policy: WorkbenchPolicy, yaml: string) => {
      userSelectedARef.current = true;
      setPolicyA(policy);
      setYamlA(yaml);
    },
    []
  );

  const handleSelectB = useCallback(
    (policy: WorkbenchPolicy, yaml: string) => {
      setPolicyB(policy);
      setYamlB(yaml);
    },
    []
  );

  const tabs: { id: DiffTab; label: string }[] = [
    { id: "yaml", label: "YAML Diff" },
    { id: "semantic", label: "Semantic Diff" },
  ];

  return (
    <div className="flex flex-col h-full">
      {/* Top bar: policy selectors side by side */}
      <div className="shrink-0 border-b border-[#2d3240] bg-[#0b0d13] p-4">
        <div className="grid grid-cols-2 gap-4">
          <PolicySelector label="Policy A" onSelect={handleSelectA} />
          <PolicySelector label="Policy B" onSelect={handleSelectB} />
        </div>
      </div>

      {/* Tab bar */}
      <div className="shrink-0 flex items-center gap-0 border-b border-[#2d3240] bg-[#0b0d13] px-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "relative px-4 py-2.5 text-xs font-mono uppercase tracking-wider transition-colors",
              activeTab === tab.id
                ? "text-[#ece7dc]"
                : "text-[#6f7f9a] hover:text-[#ece7dc]"
            )}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-2 right-2 h-[2px] bg-[#d4a84b] rounded-t-sm" />
            )}
          </button>
        ))}
      </div>

      {/* Diff content */}
      <div className="flex-1 min-h-0 overflow-hidden p-4">
        {activeTab === "yaml" ? (
          <YamlDiffView yamlA={yamlA} yamlB={yamlB} />
        ) : policyB ? (
          <SemanticDiffView policyA={policyA} policyB={policyB} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
            <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-4">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="empty-state-icon text-[#6f7f9a]">
                <rect x="3" y="3" width="8" height="18" rx="1.5" stroke="currentColor" strokeWidth="1.5"/>
                <rect x="13" y="3" width="8" height="18" rx="1.5" stroke="currentColor" strokeWidth="1.5"/>
              </svg>
            </div>
            <span className="text-[13px] font-medium text-[#6f7f9a] mb-1">Select Policy B</span>
            <span className="text-[11px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[260px]">
              Choose a second policy above to see semantic differences between both configurations
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
