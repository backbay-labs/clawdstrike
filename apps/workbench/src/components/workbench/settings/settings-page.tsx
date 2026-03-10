// ---------------------------------------------------------------------------
// Settings Page — tabbed layout for app-level configuration
// ---------------------------------------------------------------------------
import { useState } from "react";
import { IconPlugConnected, IconSettings, IconBrain } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ConnectionSettings } from "./connection-settings";
import { GeneralSettings } from "./general-settings";
import { HintSettings } from "./hint-settings";

const TABS = [
  { id: "connection" as const, label: "Connection", icon: IconPlugConnected },
  { id: "general" as const, label: "General", icon: IconSettings },
  { id: "hints" as const, label: "Claude Code", icon: IconBrain },
] as const;

type TabId = (typeof TABS)[number]["id"];

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>("connection");

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* ---- Header ---- */}
      <div className="shrink-0 px-6 pt-6 pb-0">
        <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">Settings</h1>
        <p className="text-[11px] text-[#6f7f9a] mt-1">
          Configure connections, preferences, and integrations
        </p>

        {/* Tabs */}
        <div className="flex items-center gap-0 mt-4 border-b border-[#2d3240]/60">
          {TABS.map((tab) => {
            const active = activeTab === tab.id;
            const Icon = tab.icon;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors",
                  active
                    ? "text-[#d4a84b] border-[#d4a84b]"
                    : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
                )}
              >
                <Icon size={14} stroke={1.5} />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className={activeTab === "hints" ? "max-w-2xl" : "max-w-lg"}>
          {activeTab === "connection" && <ConnectionSettings />}
          {activeTab === "general" && <GeneralSettings />}
          {activeTab === "hints" && <HintSettings />}
        </div>
      </div>
    </div>
  );
}
