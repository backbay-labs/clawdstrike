import { useEffect, useState } from "react";
import { fetchIntegrationSettings, saveIntegrationSettings } from "../../api/client";
import { GlassButton, NoiseGrain } from "../ui";

const INPUT_FOCUS_CSS =
  "glass-input font-body rounded-md px-3 py-2 text-sm outline-none transition-colors duration-150 focus:ring-1 placeholder:text-[rgba(100,116,139,0.5)]";

const focusRingStyle = {
  "--tw-ring-color": "rgba(214,177,90,0.4)",
} as React.CSSProperties;

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="font-mono text-[10px]"
      style={{
        color: "rgba(214,177,90,0.55)",
        textTransform: "uppercase",
        letterSpacing: "0.1em",
      }}
    >
      {children}
    </span>
  );
}

export interface SiemSettingsProps {
  onStatus?: (message: string | null, error: string | null) => void;
}

export function SiemSettings({ onStatus }: SiemSettingsProps) {
  const [siemProvider, setSiemProvider] = useState(
    () => localStorage.getItem("siem_provider") || "datadog",
  );
  const [siemEndpoint, setSiemEndpoint] = useState(
    () => localStorage.getItem("siem_endpoint") || "",
  );
  const [siemApiKey, setSiemApiKey] = useState(() => localStorage.getItem("siem_api_key") || "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let mounted = true;
    fetchIntegrationSettings()
      .then((settings) => {
        if (!mounted) return;
        setSiemProvider(settings.siem.provider || "datadog");
        setSiemEndpoint(settings.siem.endpoint || "");
        setSiemApiKey(settings.siem.api_key || "");
      })
      .catch(() => {
        // Keep localStorage fallback values in dev/proxy mode when agent endpoint is unavailable.
      });
    return () => {
      mounted = false;
    };
  }, []);

  async function handleSave() {
    setSaving(true);
    onStatus?.(null, null);

    localStorage.setItem("siem_provider", siemProvider);
    if (siemEndpoint) {
      localStorage.setItem("siem_endpoint", siemEndpoint);
    } else {
      localStorage.removeItem("siem_endpoint");
    }
    if (siemApiKey) {
      localStorage.setItem("siem_api_key", siemApiKey);
    } else {
      localStorage.removeItem("siem_api_key");
    }

    try {
      const response = await saveIntegrationSettings({
        siem: {
          provider: siemProvider,
          endpoint: siemEndpoint.trim(),
          api_key: siemApiKey.trim(),
          enabled: siemEndpoint.trim().length > 0,
        },
        apply: true,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      const exportersEnabled = response.exporter_status?.enabled;
      if (response.warning) {
        onStatus?.(`Saved, but warning: ${response.warning}`, null);
      } else if (exportersEnabled === false) {
        onStatus?.("Saved, but hushd still reports SIEM disabled.", null);
      } else {
        onStatus?.("SIEM config saved and hushd restarted.", null);
      }
    } catch (err) {
      onStatus?.(null, err instanceof Error ? err.message : "Failed to apply SIEM settings");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="glass-panel max-w-3xl space-y-5 p-6">
      <NoiseGrain />
      <h2 className="font-display relative z-10 text-lg tracking-wide" style={{ color: "#fff" }}>
        SIEM Export
      </h2>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>Provider</FieldLabel>
        <select
          value={siemProvider}
          onChange={(e) => setSiemProvider(e.target.value)}
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        >
          <option value="datadog">Datadog</option>
          <option value="splunk">Splunk</option>
          <option value="elastic">Elastic</option>
          <option value="sumo_logic">Sumo Logic</option>
          <option value="custom">Custom</option>
        </select>
      </label>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>Collector / Ingress Endpoint</FieldLabel>
        <input
          type="url"
          value={siemEndpoint}
          onChange={(e) => setSiemEndpoint(e.target.value)}
          placeholder="https://example-collector.company.net"
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>Token / API Key</FieldLabel>
        <input
          type="password"
          value={siemApiKey}
          onChange={(e) => setSiemApiKey(e.target.value)}
          placeholder="Optional auth token"
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <div className="relative z-10 flex items-center gap-3">
        <GlassButton onClick={handleSave} disabled={saving}>
          {saving ? "Applying..." : "Save SIEM Config"}
        </GlassButton>
        {saved && (
          <span className="text-sm" style={{ color: "#2daa6a" }}>
            Saved!
          </span>
        )}
      </div>
    </section>
  );
}
