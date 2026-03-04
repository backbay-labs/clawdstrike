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
const WEBHOOK_TEST_HISTORY_KEY = "cs.settings.webhook.test-history.v1";
const MAX_TEST_HISTORY = 12;

function readTestHistory(): IntegrationTestResult[] {
  try {
    const raw = localStorage.getItem(WEBHOOK_TEST_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as IntegrationTestResult[]) : [];
  } catch {
    return [];
  }
}

function writeTestHistory(history: IntegrationTestResult[]) {
  localStorage.setItem(
    WEBHOOK_TEST_HISTORY_KEY,
    JSON.stringify(history.slice(0, MAX_TEST_HISTORY)),
  );
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

export interface WebhookSettingsProps {
  onStatus?: (message: string | null, error: string | null) => void;
}

export function WebhookSettings({ onStatus }: WebhookSettingsProps) {
  const [webhookUrl, setWebhookUrl] = useState(() => localStorage.getItem("webhook_url") || "");
  const [webhookSecret, setWebhookSecret] = useState(
    () => localStorage.getItem("webhook_secret") || "",
  );
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testHistory, setTestHistory] = useState<IntegrationTestResult[]>(() => readTestHistory());

  useEffect(() => {
    let mounted = true;
    fetchIntegrationSettings()
      .then((settings) => {
        if (!mounted) return;
        setWebhookUrl(settings.webhooks.url || "");
        setWebhookSecret(settings.webhooks.secret || "");
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

    if (webhookUrl) {
      localStorage.setItem("webhook_url", webhookUrl);
    } else {
      localStorage.removeItem("webhook_url");
    }
    if (webhookSecret) {
      localStorage.setItem("webhook_secret", webhookSecret);
    } else {
      localStorage.removeItem("webhook_secret");
    }

    try {
      const response = await saveIntegrationSettings({
        webhooks: {
          url: webhookUrl.trim(),
          secret: webhookSecret.trim(),
          enabled: webhookUrl.trim().length > 0,
        },
        apply: true,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      if (response.warning) {
        onStatus?.(`Saved, but warning: ${response.warning}`, null);
      } else {
        onStatus?.("Webhook config saved and hushd restarted.", null);
      }
    } catch (err) {
      onStatus?.(null, err instanceof Error ? err.message : "Failed to apply webhook settings");
    } finally {
      setSaving(false);
    }
  }

  async function handleTestDelivery() {
    setTesting(true);
    onStatus?.(null, null);

    try {
      const result = await testIntegrationDelivery("webhook", 2);
      setTestHistory((current) => {
        const next = [result, ...current].slice(0, MAX_TEST_HISTORY);
        writeTestHistory(next);
        return next;
      });

      if (result.delivered) {
        onStatus?.(
          `Webhook test delivered (${result.status_code ?? 200}) in ${result.latency_ms}ms after ${result.retry_count} retries.`,
          null,
        );
      } else {
        const errorMessage = result.last_error ?? `HTTP ${result.status_code ?? "unknown"}`;
        onStatus?.(
          null,
          `Webhook test failed after ${result.attempts} attempts: ${errorMessage}`,
        );
      }
    } catch (err) {
      onStatus?.(null, err instanceof Error ? err.message : "Webhook test delivery failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <section className="glass-panel max-w-3xl space-y-5 p-6">
      <NoiseGrain />
      <h2 className="font-display relative z-10 text-lg tracking-wide" style={{ color: "#fff" }}>
        Webhooks
      </h2>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>Destination URL</FieldLabel>
        <input
          type="url"
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
          placeholder="https://hooks.slack.com/services/..."
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>Signing Secret (optional)</FieldLabel>
        <input
          type="password"
          value={webhookSecret}
          onChange={(e) => setWebhookSecret(e.target.value)}
          placeholder="Secret for HMAC signing"
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <div className="relative z-10 flex items-center gap-3">
        <GlassButton onClick={handleSave} disabled={saving}>
          {saving ? "Applying..." : "Save Webhook Config"}
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
              No webhook delivery tests run yet.
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
