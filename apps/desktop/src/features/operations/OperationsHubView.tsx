import { GlassHeader, GlassPanel, GlowButton } from "@backbay/glia/primitives";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { OpenClawFleetView } from "@/features/openclaw/OpenClawFleetView";
import { SettingsView } from "@/features/settings/SettingsView";

type OperationsTab = "fleet" | "connection" | "preferences";

const TAB_ORDER: OperationsTab[] = ["fleet", "connection", "preferences"];

const TAB_LABELS: Record<OperationsTab, string> = {
  fleet: "Fleet",
  connection: "Connection",
  preferences: "Preferences",
};

function normalizeTab(value: string | null): OperationsTab {
  if (value === "connection" || value === "preferences") return value;
  return "fleet";
}

export function OperationsHubView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = useMemo(() => normalizeTab(searchParams.get("tab")), [searchParams]);

  const setTab = (tab: OperationsTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next, { replace: true });
  };

  return (
    <GlassPanel className="h-full overflow-hidden">
      <div className="h-full max-w-[1400px] mx-auto px-5 py-4 flex flex-col gap-4">
        <GlassHeader>
          <h1 className="text-2xl font-semibold text-sdr-text-primary">Operations</h1>
          <p className="text-sdr-text-muted mt-1">
            Manage OpenClaw fleet connectivity and desktop runtime preferences.
          </p>
        </GlassHeader>

        <div className="flex items-center gap-2">
          {TAB_ORDER.map((tab) => (
            <GlowButton
              key={tab}
              type="button"
              variant={activeTab === tab ? "default" : "secondary"}
              onClick={() => setTab(tab)}
            >
              {TAB_LABELS[tab]}
            </GlowButton>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-sdr-border bg-sdr-bg-primary/50">
          {activeTab === "fleet" ? (
            <OpenClawFleetView />
          ) : activeTab === "connection" ? (
            <SettingsView scope="connection" />
          ) : (
            <SettingsView scope="preferences" />
          )}
        </div>
      </div>
    </GlassPanel>
  );
}
