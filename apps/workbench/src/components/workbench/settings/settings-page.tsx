import { useState } from "react";
import { IconPlugConnected, IconSettings, IconBrain, IconFingerprint, IconKey } from "@tabler/icons-react";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { ConnectionSettings } from "./connection-settings";
import { GeneralSettings } from "./general-settings";
import { HintSettings } from "./hint-settings";
import { IdentitySettings } from "./identity-settings";
import { PluginSecretsSettings } from "./plugin-secrets-settings";

const TABS: SubTab[] = [
  { id: "connection", label: "Connection", icon: IconPlugConnected },
  { id: "general", label: "General", icon: IconSettings },
  { id: "identity", label: "Identity", icon: IconFingerprint },
  { id: "hints", label: "Claude Code", icon: IconBrain },
  { id: "plugins", label: "Plugins", icon: IconKey },
];

type TabId = "connection" | "general" | "identity" | "hints" | "plugins";

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
        <div className="mt-4">
          <SubTabBar tabs={TABS} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as TabId)} />
        </div>
      </div>

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className={activeTab === "hints" || activeTab === "plugins" ? "max-w-2xl" : "max-w-lg"}>
          {activeTab === "connection" && <ConnectionSettings />}
          {activeTab === "general" && <GeneralSettings />}
          {activeTab === "identity" && <IdentitySettings />}
          {activeTab === "hints" && <HintSettings />}
          {activeTab === "plugins" && <PluginSecretsSettings />}
        </div>
      </div>
    </div>
  );
}
