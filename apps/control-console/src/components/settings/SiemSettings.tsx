import { useEffect, useState } from "react";
import {
  fetchIntegrationSettings,
  saveIntegrationSettings,
  testIntegrationDelivery,
  type IntegrationTestResult,
} from "../../api/client";
import { GlassButton, NoiseGrain } from "../ui";

const INPUT_FOCUS_CSS =
  "glass-input font-body rounded-md px-3 py-2 text-sm outline-none transition-colors duration-150 focus:ring-1 placeholder:text-[rgba(100,116,139,0.5)]";

const focusRingStyle = {
  "--tw-ring-color": "rgba(214,177,90,0.4)",
} as React.CSSProperties;
const SIEM_TEST_HISTORY_KEY = "cs.settings.siem.test-history.v1";
const MAX_TEST_HISTORY = 12;

function readTestHistory(): IntegrationTestResult[] {
  try {
    const raw = localStorage.getItem(SIEM_TEST_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as IntegrationTestResult[]) : [];
  } catch {
    return [];
  }
}

function writeTestHistory(history: IntegrationTestResult[]) {
  localStorage.setItem(SIEM_TEST_HISTORY_KEY, JSON.stringify(history.slice(0, MAX_TEST_HISTORY)));
}

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
  const [testing, setTesting] = useState(false);
  const [testHistory, setTestHistory] = useState<IntegrationTestResult[]>(() => readTestHistory());

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

  async function handleTestDelivery() {
    setTesting(true);
    onStatus?.(null, null);
    try {
      const result = await testIntegrationDelivery("siem", 2);
      setTestHistory((current) => {
        const next = [result, ...current].slice(0, MAX_TEST_HISTORY);
        writeTestHistory(next);
        return next;
      });

      if (result.delivered) {
        onStatus?.(
          `SIEM test delivered (${result.status_code ?? 200}) in ${result.latency_ms}ms after ${result.retry_count} retries.`,
          null,
        );
      } else {
        const errorMessage = result.last_error ?? `HTTP ${result.status_code ?? "unknown"}`;
        onStatus?.(
          null,
          `SIEM test failed after ${result.attempts} attempts: ${errorMessage}`,
        );
      }
    } catch (err) {
      onStatus?.(null, err instanceof Error ? err.message : "SIEM test delivery failed");
    } finally {
      setTesting(false);
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
        <GlassButton onClick={handleTestDelivery} disabled={saving || testing}>
          {testing ? "Testing..." : "Test Delivery"}
        </GlassButton>
        {saved && (
          <span className="text-sm" style={{ color: "#2daa6a" }}>
            Saved!
          </span>
        )}
      </div>

      <div className="relative z-10">
        <FieldLabel>Recent Test Delivery Status</FieldLabel>
        <div
          style={{
            marginTop: 8,
            border: "1px solid rgba(27,34,48,0.75)",
            borderRadius: 8,
            overflow: "hidden",
          }}
        >
          {testHistory.length === 0 ? (
            <div className="font-mono" style={{ fontSize: 11, color: "rgba(154,167,181,0.45)", padding: 10 }}>
              No SIEM delivery tests run yet.
            </div>
          ) : (
            testHistory.map((entry) => (
              <div
                key={`${entry.tested_at}-${entry.endpoint}`}
                style={{
                  display: "grid",
                  gridTemplateColumns: "110px 80px 70px 70px 1fr",
                  gap: 8,
                  padding: "8px 10px",
                  borderTop: "1px solid rgba(27,34,48,0.6)",
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: 10,
                  color: "rgba(229,231,235,0.8)",
                }}
              >
                <span style={{ color: "rgba(154,167,181,0.75)" }}>
                  {new Date(entry.tested_at).toLocaleTimeString()}
                </span>
                <span style={{ color: entry.delivered ? "#2daa6a" : "#c23b3b" }}>
                  {entry.delivered ? "delivered" : "failed"}
                </span>
                <span>{entry.latency_ms} ms</span>
                <span>r{entry.retry_count}</span>
                <span
                  style={{
                    color: "rgba(154,167,181,0.7)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={entry.last_error ?? entry.endpoint}
                >
                  {entry.last_error ?? entry.endpoint}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}
