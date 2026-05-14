import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

const RULESETS = [
  { value: "__none__", label: "None (from scratch)" },
  { value: "default", label: "default" },
  { value: "strict", label: "strict" },
  { value: "permissive", label: "permissive" },
  { value: "ai-agent", label: "ai-agent" },
  { value: "ai-agent-posture", label: "ai-agent-posture" },
  { value: "cicd", label: "cicd" },
  { value: "remote-desktop", label: "remote-desktop" },
  { value: "remote-desktop-strict", label: "remote-desktop-strict" },
  { value: "remote-desktop-permissive", label: "remote-desktop-permissive" },
  { value: "spider-sense", label: "spider-sense" },
] as const;

export function BaseRulesetSelector() {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const currentExtends = (editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }).extends ?? "__none__";

  return (
    <div className="flex flex-col gap-2 p-4 border-b border-[#2d3240]">
      <label className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
        Base Ruleset
      </label>
      <Select
        value={currentExtends}
        onValueChange={(val) => {
          usePolicyEditStore.getState().updateMeta(activeTabId, {
            extends: val === "__none__" ? "" : (val as string),
          }, activeTab?.fileType ?? "clawdstrike_policy");
          usePolicyTabsStore.getState().setDirty(activeTabId, true);
        }}
      >
        <SelectTrigger className="w-full bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
          <SelectValue placeholder="Select base ruleset" />
        </SelectTrigger>
        <SelectContent className="bg-[#131721] border-[#2d3240]">
          {RULESETS.map((r) => (
            <SelectItem
              key={r.value}
              value={r.value}
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              {r.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
