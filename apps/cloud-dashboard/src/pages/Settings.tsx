import { useCallback, useEffect, useState } from "react";
import { useTheme } from "../hooks/useTheme";
import { useAlertRules } from "../hooks/useAlertRules";
import { useMultiInstance } from "../hooks/useMultiInstance";
import { useSharedSSE } from "../context/SSEContext";
import { NoiseGrain } from "../components/ui";
import {
  ConnectionSettings,
  SiemSettings,
  WebhookSettings,
  WallpaperPicker,
  SoundSettings,
  AlertRules,
  MultiInstance,
  ThemeToggle,
} from "../components/settings";
import packageJson from "../../package.json";

type SettingsSection = "connection" | "siem" | "webhooks" | "wallpaper" | "sound" | "alerts" | "instances" | "theme";

type SettingsProps = {
  initialSection?: SettingsSection;
  windowId?: string;
};

const SECTION_ORDER: Array<{ id: SettingsSection; label: string; description: string }> = [
  { id: "connection", label: "Connection", description: "Configure dashboard access to hushd and SSE streams." },
  { id: "siem", label: "SIEM Export", description: "Choose a SIEM target and endpoint for event export wiring." },
  { id: "webhooks", label: "Webhooks", description: "Set webhook delivery targets for incident forwarding." },
  { id: "wallpaper", label: "Wallpaper", description: "Choose a desktop wallpaper." },
  { id: "sound", label: "Sound", description: "Toggle sound effects for events." },
  { id: "alerts", label: "Alerts", description: "Configure violation alert rules." },
  { id: "instances", label: "Instances", description: "Manage multiple hushd connections." },
  { id: "theme", label: "Theme", description: "Switch between dark and light mode." },
];

const PATH_TO_SECTION: Record<string, SettingsSection> = {
  "/settings/siem": "siem",
  "/settings/webhooks": "webhooks",
};

function getAppPath(): string {
  const base = (import.meta.env.BASE_URL || "/").replace(/\/+$/, "");
  const raw = window.location.pathname.replace(/\/+$/, "") || "/";
  return base && raw.startsWith(base) ? raw.slice(base.length) || "/" : raw;
}

function SectionPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="glass-panel max-w-3xl space-y-5 p-6">
      <NoiseGrain />
      <h2 className="font-display relative z-10 text-lg tracking-wide" style={{ color: "#fff" }}>
        {title}
      </h2>
      {children}
    </section>
  );
}

export function Settings({ initialSection }: SettingsProps) {
  const derivedSection = initialSection ?? PATH_TO_SECTION[getAppPath()] ?? "connection";
  const [activeSection, setActiveSection] = useState<SettingsSection>(derivedSection);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const { theme, toggle: toggleTheme } = useTheme();
  const { events } = useSharedSSE();

  const { rules, addRule, removeRule, updateRule, triggered } = useAlertRules(events, { evaluate: false });
  const { instances, activeId, addInstance, removeInstance, switchTo } = useMultiInstance();

  useEffect(() => {
    if (initialSection) setActiveSection(initialSection);
  }, [initialSection]);

  const handleStatus = useCallback((message: string | null, error: string | null) => {
    setStatusMessage(message);
    setStatusError(error);
  }, []);

  return (
    <div className="space-y-6" style={{ padding: 20, color: "rgba(229,231,235,0.92)", overflow: "auto", height: "100%" }}>
      {/* Tab selector */}
      <section className="glass-panel max-w-4xl p-4">
        <NoiseGrain />
        <div className="relative z-10 grid gap-2 sm:grid-cols-4">
          {SECTION_ORDER.map((section) => {
            const active = section.id === activeSection;
            return (
              <button
                key={section.id}
                type="button"
                onClick={() => setActiveSection(section.id)}
                className="rounded-md px-3 py-3 text-left transition-all duration-200"
                style={{
                  background: active ? "rgba(214,177,90,0.06)" : "rgba(7,8,10,0.6)",
                  border: active ? "1px solid rgba(214,177,90,0.35)" : "1px solid rgba(27,34,48,0.5)",
                  boxShadow: active
                    ? "inset 0 1px 0 rgba(255,255,255,0.03), 0 0 8px rgba(214,177,90,0.06)"
                    : "inset 0 1px 0 rgba(255,255,255,0.02)",
                  cursor: "pointer",
                }}
              >
                <p className="font-mono text-sm font-medium" style={{ letterSpacing: "0.05em", color: active ? "#d6b15a" : "rgba(229,231,235,0.7)" }}>
                  {section.label}
                </p>
                <p className="font-body mt-1 text-xs" style={{ color: "rgba(229,231,235,0.35)" }}>
                  {section.description}
                </p>
              </button>
            );
          })}
        </div>
      </section>

      {/* Status messages */}
      {statusMessage && (
        <section className="glass-panel max-w-3xl p-3 text-sm" style={{ borderColor: "rgba(45,170,106,0.3)", color: "#2daa6a" }}>
          <NoiseGrain />
          <span className="relative z-10">{statusMessage}</span>
        </section>
      )}
      {statusError && (
        <section className="glass-panel max-w-3xl p-3 text-sm" style={{ borderColor: "rgba(194,59,59,0.3)", color: "#c23b3b" }}>
          <NoiseGrain />
          <span className="relative z-10">{statusError}</span>
        </section>
      )}

      {/* Section content */}
      {activeSection === "connection" && <ConnectionSettings />}
      {activeSection === "siem" && <SiemSettings onStatus={handleStatus} />}
      {activeSection === "webhooks" && <WebhookSettings onStatus={handleStatus} />}
      {activeSection === "wallpaper" && <SectionPanel title="Wallpaper"><WallpaperPicker /></SectionPanel>}
      {activeSection === "sound" && <SectionPanel title="Sound Effects"><SoundSettings /></SectionPanel>}
      {activeSection === "alerts" && (
        <SectionPanel title="Alert Rules">
          <AlertRules rules={rules} onAdd={addRule} onRemove={removeRule} onUpdate={updateRule} triggered={triggered} />
        </SectionPanel>
      )}
      {activeSection === "instances" && (
        <SectionPanel title="Multi-Instance">
          <MultiInstance instances={instances} activeId={activeId} onAdd={addInstance} onRemove={removeInstance} onSwitch={switchTo} />
        </SectionPanel>
      )}
      {activeSection === "theme" && <SectionPanel title="Theme"><ThemeToggle theme={theme} onToggle={toggleTheme} /></SectionPanel>}

      {/* About */}
      <section className="glass-panel max-w-3xl p-6">
        <NoiseGrain />
        <h2 className="font-display relative z-10 mb-2 text-lg tracking-wide" style={{ color: "#fff" }}>About</h2>
        <p className="font-body relative z-10 text-sm" style={{ color: "rgba(229,231,235,0.5)" }}>
          ClawdStrike Dashboard v{packageJson.version} &mdash; Local-first security monitoring for hushd.
        </p>
      </section>
    </div>
  );
}
