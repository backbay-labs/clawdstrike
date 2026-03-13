// ---------------------------------------------------------------------------
// Settings Page — tabbed layout for app-level configuration
// ---------------------------------------------------------------------------
import { useState } from "react";
import { IconPlugConnected, IconSettings, IconFingerprint, IconBrain } from "@tabler/icons-react";
import { PageHeader } from "../shared/page-header";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { ConnectionSettings } from "./connection-settings";
import { GeneralSettings } from "./general-settings";
import { HintSettings } from "./hint-settings";
import { IdentitySettings } from "./identity-settings";

const TABS: SubTab[] = [
  { id: "connection", label: "Connection", icon: IconPlugConnected },
  { id: "general", label: "General", icon: IconSettings },
  { id: "identity", label: "Identity", icon: IconFingerprint },
  { id: "hints", label: "Claude Code", icon: IconBrain },
];

type TabId = "connection" | "general" | "identity" | "hints";

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>("connection");

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <PageHeader
        title="Settings"
        subtitle="Configure connections, preferences, and integrations"
        icon={IconSettings}
        iconColor="#6f7f9a"
        sectionAccent="#7b6b8b"
      />

      <SubTabBar
        tabs={TABS}
        activeTab={activeTab}
        onTabChange={(id) => setActiveTab(id as TabId)}
      />

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className={activeTab === "hints" ? "max-w-2xl" : "max-w-lg"}>
          {activeTab === "connection" && <ConnectionSettings />}
          {activeTab === "general" && <GeneralSettings />}
          {activeTab === "identity" && <IdentitySettings />}
          {activeTab === "hints" && <HintSettings />}
        </div>
      </div>
    </div>
  );
}
