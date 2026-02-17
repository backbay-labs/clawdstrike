import { useEffect, useState } from "react";
import { fetchIntegrationSettings, saveIntegrationSettings } from "../api/client";
import { notifySSEConfigChanged } from "../hooks/useSSE";

type SettingsSection = "connection" | "siem" | "webhooks";

type SettingsProps = {
  initialSection?: SettingsSection;
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

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <section className="max-w-3xl rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="grid gap-2 sm:grid-cols-3">
          {SECTION_ORDER.map((section) => {
            const active = section.id === activeSection;
            return (
              <button
                key={section.id}
                type="button"
                onClick={() => setActiveSection(section.id)}
                className={`rounded-md border px-3 py-3 text-left transition-colors ${
                  active
                    ? "border-blue-500 bg-blue-950/30 text-blue-200"
                    : "border-gray-700 bg-gray-800/70 text-gray-300 hover:border-gray-600"
                }`}
              >
                <p className="text-sm font-semibold">{section.label}</p>
                <p className="mt-1 text-xs text-gray-400">{section.description}</p>
              </button>
            );
          })}
        </div>
      </section>

      {statusMessage && (
        <section className="max-w-3xl rounded-lg border border-green-900/60 bg-green-950/30 p-3 text-sm text-green-300">
          {statusMessage}
        </section>
      )}

      {statusError && (
        <section className="max-w-3xl rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">
          {statusError}
        </section>
      )}

      {activeSection === "connection" && (
        <section className="max-w-3xl space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h2 className="text-lg font-semibold">Connection</h2>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            hushd URL (leave empty for Vite proxy)
            <input
              type="text"
              value={hushdUrl}
              onChange={(e) => setHushdUrl(e.target.value)}
              placeholder="http://localhost:9876"
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            API Key (optional)
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Bearer token for hushd"
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <div className="flex items-center gap-3">
            <button
              onClick={handleConnectionSave}
              className="rounded bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500"
            >
              Save Connection
            </button>
            {savedSection === "connection" && <span className="text-sm text-green-400">Saved!</span>}
          </div>
        </section>
      )}

      {activeSection === "siem" && (
        <section className="max-w-3xl space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h2 className="text-lg font-semibold">SIEM Export</h2>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            Provider
            <select
              value={siemProvider}
              onChange={(e) => setSiemProvider(e.target.value)}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200"
            >
              <option value="datadog">Datadog</option>
              <option value="splunk">Splunk</option>
              <option value="elastic">Elastic</option>
              <option value="sumo_logic">Sumo Logic</option>
              <option value="custom">Custom</option>
            </select>
          </label>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            Collector/Ingress Endpoint
            <input
              type="url"
              value={siemEndpoint}
              onChange={(e) => setSiemEndpoint(e.target.value)}
              placeholder="https://example-collector.company.net"
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            Token / API Key
            <input
              type="password"
              value={siemApiKey}
              onChange={(e) => setSiemApiKey(e.target.value)}
              placeholder="Optional auth token"
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <div className="flex items-center gap-3">
            <button
              onClick={handleSiemSave}
              disabled={savingSection === "siem"}
              className="rounded bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500"
            >
              {savingSection === "siem" ? "Applying..." : "Save SIEM Config"}
            </button>
            {savedSection === "siem" && <span className="text-sm text-green-400">Saved!</span>}
          </div>
        </section>
      )}

      {activeSection === "webhooks" && (
        <section className="max-w-3xl space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
          <h2 className="text-lg font-semibold">Webhooks</h2>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            Destination URL
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-gray-400">
            Signing Secret (optional)
            <input
              type="password"
              value={webhookSecret}
              onChange={(e) => setWebhookSecret(e.target.value)}
              placeholder="Secret for HMAC signing"
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
            />
          </label>

          <div className="flex items-center gap-3">
            <button
              onClick={handleWebhooksSave}
              disabled={savingSection === "webhooks"}
              className="rounded bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500"
            >
              {savingSection === "webhooks" ? "Applying..." : "Save Webhook Config"}
            </button>
            {savedSection === "webhooks" && <span className="text-sm text-green-400">Saved!</span>}
          </div>
        </section>
      )}

      <section className="max-w-3xl rounded-lg border border-gray-800 bg-gray-900 p-6">
        <h2 className="mb-2 text-lg font-semibold">About</h2>
        <p className="text-sm text-gray-400">
          ClawdStrike Dashboard v0.1.0 &mdash; Local-first security monitoring for hushd.
        </p>
      </section>
    </div>
  );
}
