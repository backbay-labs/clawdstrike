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
        {saved && (
          <span className="text-sm" style={{ color: "#2daa6a" }}>
            Saved!
          </span>
        )}
      </div>
    </section>
  );
}
