import { useEffect, useState } from "react";
import { fetchIntegrationSettings, saveIntegrationSettings } from "../api/client";
import { notifySSEConfigChanged } from "../hooks/useSSE";

type SettingsSection = "connection" | "siem" | "webhooks";

type SettingsProps = {
  initialSection?: SettingsSection;
  windowId?: string;
};

const SECTION_ORDER: Array<{ id: SettingsSection; label: string; description: string }> = [
  {
    id: "connection",
    label: "Connection",
    description: "Configure dashboard access to hushd and SSE streams.",
  },
  {
    id: "siem",
    label: "SIEM Export",
    description: "Choose a SIEM target and endpoint for event export wiring.",
  },
  {
    id: "webhooks",
    label: "Webhooks",
    description: "Set webhook delivery targets for incident forwarding.",
  },
];

const GLASS_PANEL = {
  background: "rgba(4,8,16,0.94)",
  border: "1px solid rgba(34,211,238,0.12)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
} as const;

const INPUT_STYLE = {
  background: "rgba(4,8,16,0.8)",
  border: "1px solid rgba(34,211,238,0.12)",
  color: "rgba(229,231,235,0.92)",
  fontFamily: "var(--glia-font-body), sans-serif",
} as const;

const INPUT_FOCUS_CSS =
  "rounded-md px-3 py-2 text-sm outline-none transition-colors duration-150 focus:ring-1 placeholder:text-[rgba(100,116,139,0.5)]";

function NoiseGrain({ id = "settingsNoise" }: { id?: string }) {
  return (
    <svg
      aria-hidden
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        opacity: 0.04,
        pointerEvents: "none",
        borderRadius: "inherit",
      }}
    >
      <filter id={id}>
        <feTurbulence
          type="fractalNoise"
          baseFrequency="0.8"
          numOctaves="4"
          stitchTiles="stitch"
        />
      </filter>
      <rect width="100%" height="100%" filter={`url(#${id})`} />
    </svg>
  );
}

function GlassButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-md px-5 py-2 text-sm transition-all duration-200 disabled:opacity-50"
      style={{
        ...GLASS_PANEL,
        color: "#22d3ee",
        fontFamily: "var(--glia-font-mono), monospace",
        letterSpacing: "0.05em",
        cursor: disabled ? "default" : "pointer",
      }}
      onMouseEnter={(e) => {
        if (disabled) return;
        e.currentTarget.style.boxShadow =
          "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 14px rgba(34,211,238,0.18)";
        e.currentTarget.style.borderColor = "rgba(34,211,238,0.35)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02)";
        e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)";
      }}
    >
      {children}
    </button>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="text-[10px]"
      style={{
        fontFamily: "var(--glia-font-mono), monospace",
        color: "rgba(34,211,238,0.55)",
        textTransform: "uppercase",
        letterSpacing: "0.1em",
      }}
    >
      {children}
    </span>
  );
}

export function Settings({ initialSection = "connection" }: SettingsProps) {
  const [activeSection, setActiveSection] = useState<SettingsSection>(initialSection);
  const [hushdUrl, setHushdUrl] = useState(() => localStorage.getItem("hushd_url") || "");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("hushd_api_key") || "");
  const [siemProvider, setSiemProvider] = useState(
    () => localStorage.getItem("siem_provider") || "datadog",
  );
  const [siemEndpoint, setSiemEndpoint] = useState(
    () => localStorage.getItem("siem_endpoint") || "",
  );
  const [siemApiKey, setSiemApiKey] = useState(() => localStorage.getItem("siem_api_key") || "");
  const [webhookUrl, setWebhookUrl] = useState(() => localStorage.getItem("webhook_url") || "");
  const [webhookSecret, setWebhookSecret] = useState(
    () => localStorage.getItem("webhook_secret") || "",
  );
  const [savedSection, setSavedSection] = useState<SettingsSection | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [savingSection, setSavingSection] = useState<SettingsSection | null>(null);

  useEffect(() => {
    setActiveSection(initialSection);
  }, [initialSection]);

  useEffect(() => {
    let mounted = true;
    fetchIntegrationSettings()
      .then((settings) => {
        if (!mounted) return;
        setSiemProvider(settings.siem.provider || "datadog");
        setSiemEndpoint(settings.siem.endpoint || "");
        setSiemApiKey(settings.siem.api_key || "");
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

  function markSaved(section: SettingsSection) {
    setSavedSection(section);
    setTimeout(() => {
      setSavedSection((current) => (current === section ? null : current));
    }, 2000);
  }

  function handleConnectionSave() {
    setStatusError(null);
    setStatusMessage(null);
    if (hushdUrl) {
      localStorage.setItem("hushd_url", hushdUrl);
    } else {
      localStorage.removeItem("hushd_url");
    }
    if (apiKey) {
      localStorage.setItem("hushd_api_key", apiKey);
    } else {
      localStorage.removeItem("hushd_api_key");
    }
    notifySSEConfigChanged();
    markSaved("connection");
  }

  async function handleSiemSave() {
    setSavingSection("siem");
    setStatusError(null);
    setStatusMessage(null);

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
      markSaved("siem");
      const exportersEnabled = response.exporter_status?.enabled;
      if (response.warning) {
        setStatusMessage(`Saved, but warning: ${response.warning}`);
      } else if (exportersEnabled === false) {
        setStatusMessage("Saved, but hushd still reports SIEM disabled.");
      } else {
        setStatusMessage("SIEM config saved and hushd restarted.");
      }
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Failed to apply SIEM settings");
    } finally {
      setSavingSection(null);
    }
  }

  async function handleWebhooksSave() {
    setSavingSection("webhooks");
    setStatusError(null);
    setStatusMessage(null);

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
      markSaved("webhooks");
      if (response.warning) {
        setStatusMessage(`Saved, but warning: ${response.warning}`);
      } else {
        setStatusMessage("Webhook config saved and hushd restarted.");
      }
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Failed to apply webhook settings");
    } finally {
      setSavingSection(null);
    }
  }

  const focusRingStyle = {
    "--tw-ring-color": "rgba(34,211,238,0.4)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6" style={{ color: "rgba(229,231,235,0.92)" }}>
      <h1
        className="text-2xl tracking-wide"
        style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
      >
        Settings
      </h1>

      {/* Tab selector */}
      <section
        className="relative max-w-3xl overflow-hidden rounded-lg p-4"
        style={GLASS_PANEL}
      >
        <NoiseGrain id="settingsTabs" />
        <div className="relative z-10 grid gap-2 sm:grid-cols-3">
          {SECTION_ORDER.map((section) => {
            const active = section.id === activeSection;
            return (
              <button
                key={section.id}
                type="button"
                onClick={() => setActiveSection(section.id)}
                className="rounded-md px-3 py-3 text-left transition-all duration-200"
                style={{
                  background: active ? "rgba(34,211,238,0.06)" : "rgba(4,8,16,0.6)",
                  border: active
                    ? "1px solid rgba(34,211,238,0.3)"
                    : "1px solid rgba(34,211,238,0.08)",
                  boxShadow: active
                    ? "inset 0 1px 0 rgba(255,255,255,0.03), 0 0 8px rgba(34,211,238,0.06)"
                    : "inset 0 1px 0 rgba(255,255,255,0.02)",
                  cursor: "pointer",
                }}
              >
                <p
                  className="text-sm font-medium"
                  style={{
                    fontFamily: "var(--glia-font-mono), monospace",
                    letterSpacing: "0.05em",
                    color: active ? "#22d3ee" : "rgba(229,231,235,0.7)",
                  }}
                >
                  {section.label}
                </p>
                <p
                  className="mt-1 text-xs"
                  style={{
                    fontFamily: "var(--glia-font-body), sans-serif",
                    color: "rgba(229,231,235,0.35)",
                  }}
                >
                  {section.description}
                </p>
              </button>
            );
          })}
        </div>
      </section>

      {/* Status messages */}
      {statusMessage && (
        <section
          className="relative max-w-3xl overflow-hidden rounded-lg p-3 text-sm"
          style={{
            ...GLASS_PANEL,
            borderColor: "rgba(16,185,129,0.3)",
            color: "#10b981",
          }}
        >
          <NoiseGrain id="settingsSuccess" />
          <span className="relative z-10">{statusMessage}</span>
        </section>
      )}

      {statusError && (
        <section
          className="relative max-w-3xl overflow-hidden rounded-lg p-3 text-sm"
          style={{
            ...GLASS_PANEL,
            borderColor: "rgba(239,68,68,0.3)",
            color: "#ef4444",
          }}
        >
          <NoiseGrain id="settingsError" />
          <span className="relative z-10">{statusError}</span>
        </section>
      )}

      {/* Connection section */}
      {activeSection === "connection" && (
        <section
          className="relative max-w-3xl space-y-5 overflow-hidden rounded-lg p-6"
          style={GLASS_PANEL}
        >
          <NoiseGrain id="settingsConn" />
          <h2
            className="relative z-10 text-lg tracking-wide"
            style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
          >
            Connection
          </h2>

          <label className="relative z-10 flex flex-col gap-1.5">
            <FieldLabel>hushd URL (leave empty for Vite proxy)</FieldLabel>
            <input
              type="text"
              value={hushdUrl}
              onChange={(e) => setHushdUrl(e.target.value)}
              placeholder="http://localhost:9876"
              className={INPUT_FOCUS_CSS}
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
            />
          </label>

          <label className="relative z-10 flex flex-col gap-1.5">
            <FieldLabel>API Key (optional)</FieldLabel>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Bearer token for hushd"
              className={INPUT_FOCUS_CSS}
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
            />
          </label>

          <div className="relative z-10 flex items-center gap-3">
            <GlassButton onClick={handleConnectionSave}>Save Connection</GlassButton>
            {savedSection === "connection" && (
              <span className="text-sm" style={{ color: "#10b981" }}>
                Saved!
              </span>
            )}
          </div>
        </section>
      )}

      {/* SIEM section */}
      {activeSection === "siem" && (
        <section
          className="relative max-w-3xl space-y-5 overflow-hidden rounded-lg p-6"
          style={GLASS_PANEL}
        >
          <NoiseGrain id="settingsSiem" />
          <h2
            className="relative z-10 text-lg tracking-wide"
            style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
          >
            SIEM Export
          </h2>

          <label className="relative z-10 flex flex-col gap-1.5">
            <FieldLabel>Provider</FieldLabel>
            <select
              value={siemProvider}
              onChange={(e) => setSiemProvider(e.target.value)}
              className={INPUT_FOCUS_CSS}
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
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
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
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
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
            />
          </label>

          <div className="relative z-10 flex items-center gap-3">
            <GlassButton onClick={handleSiemSave} disabled={savingSection === "siem"}>
              {savingSection === "siem" ? "Applying..." : "Save SIEM Config"}
            </GlassButton>
            {savedSection === "siem" && (
              <span className="text-sm" style={{ color: "#10b981" }}>
                Saved!
              </span>
            )}
          </div>
        </section>
      )}

      {/* Webhooks section */}
      {activeSection === "webhooks" && (
        <section
          className="relative max-w-3xl space-y-5 overflow-hidden rounded-lg p-6"
          style={GLASS_PANEL}
        >
          <NoiseGrain id="settingsWebhooks" />
          <h2
            className="relative z-10 text-lg tracking-wide"
            style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
          >
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
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
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
              style={{ ...INPUT_STYLE, ...focusRingStyle }}
            />
          </label>

          <div className="relative z-10 flex items-center gap-3">
            <GlassButton onClick={handleWebhooksSave} disabled={savingSection === "webhooks"}>
              {savingSection === "webhooks" ? "Applying..." : "Save Webhook Config"}
            </GlassButton>
            {savedSection === "webhooks" && (
              <span className="text-sm" style={{ color: "#10b981" }}>
                Saved!
              </span>
            )}
          </div>
        </section>
      )}

      {/* About section */}
      <section
        className="relative max-w-3xl overflow-hidden rounded-lg p-6"
        style={GLASS_PANEL}
      >
        <NoiseGrain id="settingsAbout" />
        <h2
          className="relative z-10 mb-2 text-lg tracking-wide"
          style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
        >
          About
        </h2>
        <p
          className="relative z-10 text-sm"
          style={{
            fontFamily: "var(--glia-font-body), sans-serif",
            color: "rgba(229,231,235,0.5)",
          }}
        >
          ClawdStrike Dashboard v0.1.0 &mdash; Local-first security monitoring for hushd.
        </p>
      </section>
    </div>
  );
}
