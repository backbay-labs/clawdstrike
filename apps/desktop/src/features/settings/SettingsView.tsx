/**
 * SettingsView - Daemon connection and preferences
 */
import { useEffect, useState, type ReactNode } from "react";
import { clsx } from "clsx";
import { useConnection, type ConnectionMode } from "@/context/ConnectionContext";
import {
  DEFAULT_MARKETPLACE_FEED_SOURCES,
  formatMarketplaceFeedSourcesInput,
  loadMarketplaceFeedSources,
  parseMarketplaceFeedSourcesInput,
  saveMarketplaceFeedSources,
} from "@/services/marketplaceSettings";
import {
  DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS,
  formatMarketplaceDiscoveryBootstrapInput,
  loadMarketplaceDiscoverySettings,
  parseMarketplaceDiscoveryBootstrapInput,
  saveMarketplaceDiscoverySettings,
} from "@/services/marketplaceDiscoverySettings";
import {
  DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS,
  formatMarketplaceTrustedAttestersInput,
  loadMarketplaceProvenanceSettings,
  parseMarketplaceTrustedAttestersInput,
  saveMarketplaceProvenanceSettings,
} from "@/services/marketplaceProvenanceSettings";
import {
  announceMarketplaceDiscovery,
  getMarketplaceDiscoveryStatus,
  isTauri,
  startMarketplaceDiscovery,
  stopMarketplaceDiscovery,
  type MarketplaceDiscoveryStatus,
} from "@/services/tauri";

export function SettingsView() {
  const {
    mode,
    daemonUrl,
    status,
    info,
    error,
    setDaemonUrl,
    setMode,
    connect,
    disconnect,
    testConnection,
  } = useConnection();

  const [urlInput, setUrlInput] = useState(daemonUrl);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [marketplaceSourcesInput, setMarketplaceSourcesInput] = useState<string>(() =>
    formatMarketplaceFeedSourcesInput(loadMarketplaceFeedSources())
  );
  const [marketplaceSaved, setMarketplaceSaved] = useState<string | null>(null);

  const [initialDiscoverySettings] = useState(() => loadMarketplaceDiscoverySettings());
  const [discoveryEnabled, setDiscoveryEnabled] = useState(initialDiscoverySettings.enabled);
  const [discoveryListenPort, setDiscoveryListenPort] = useState(
    initialDiscoverySettings.listenPort ? String(initialDiscoverySettings.listenPort) : ""
  );
  const [discoveryBootstrapInput, setDiscoveryBootstrapInput] = useState(() =>
    formatMarketplaceDiscoveryBootstrapInput(initialDiscoverySettings.bootstrap)
  );
  const [discoveryTopic, setDiscoveryTopic] = useState(initialDiscoverySettings.topic ?? "");
  const [discoverySaved, setDiscoverySaved] = useState<string | null>(null);
  const [discoveryStatus, setDiscoveryStatus] = useState<MarketplaceDiscoveryStatus | null>(null);
  const [discoveryAnnounceUri, setDiscoveryAnnounceUri] = useState("");

  const [initialProvenanceSettings] = useState(() => loadMarketplaceProvenanceSettings());
  const [notaryUrl, setNotaryUrl] = useState(initialProvenanceSettings.notaryUrl ?? "");
  const [trustedAttestersInput, setTrustedAttestersInput] = useState(() =>
    formatMarketplaceTrustedAttestersInput(initialProvenanceSettings.trustedAttesters)
  );
  const [requireVerifiedAttestation, setRequireVerifiedAttestation] = useState(
    initialProvenanceSettings.requireVerified
  );
  const [provenanceSaved, setProvenanceSaved] = useState<string | null>(null);

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const info = await testConnection(urlInput);
      setTestResult({ success: true, message: `Connected to hushd v${info.version}` });
    } catch (e) {
      setTestResult({ success: false, message: e instanceof Error ? e.message : "Connection failed" });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = () => {
    setDaemonUrl(urlInput);
    connect();
  };

  const handleMarketplaceSave = () => {
    const sources = parseMarketplaceFeedSourcesInput(marketplaceSourcesInput);
    saveMarketplaceFeedSources(sources);
    setMarketplaceSaved("Saved");
    setTimeout(() => setMarketplaceSaved(null), 2000);
  };

  const handleMarketplaceReset = () => {
    setMarketplaceSourcesInput(formatMarketplaceFeedSourcesInput(DEFAULT_MARKETPLACE_FEED_SOURCES));
    saveMarketplaceFeedSources(DEFAULT_MARKETPLACE_FEED_SOURCES);
    setMarketplaceSaved("Reset to default");
    setTimeout(() => setMarketplaceSaved(null), 2000);
  };

  useEffect(() => {
    if (!isTauri()) return;
    getMarketplaceDiscoveryStatus().then(setDiscoveryStatus).catch(() => {
      // ignore
    });
  }, []);

  const parseListenPort = (value: string): number | null => {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const n = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(n)) return null;
    if (n <= 0 || n > 65535) return null;
    return n;
  };

  const handleDiscoverySave = async () => {
    const listenPort = parseListenPort(discoveryListenPort);
    const bootstrap = parseMarketplaceDiscoveryBootstrapInput(discoveryBootstrapInput);
    const topic = discoveryTopic.trim() ? discoveryTopic.trim() : null;

    saveMarketplaceDiscoverySettings({
      enabled: discoveryEnabled,
      listenPort,
      bootstrap,
      topic,
    });

    if (isTauri()) {
      try {
        if (discoveryEnabled) {
          const status = await startMarketplaceDiscovery({
            listen_port: listenPort,
            bootstrap,
            topic,
          });
          setDiscoveryStatus(status);
          setDiscoverySaved("Discovery running");
        } else {
          await stopMarketplaceDiscovery();
          const status = await getMarketplaceDiscoveryStatus();
          setDiscoveryStatus(status);
          setDiscoverySaved("Discovery stopped");
        }
      } catch (e) {
        setDiscoverySaved(e instanceof Error ? e.message : "Failed to update discovery");
      }
    } else {
      setDiscoverySaved("Saved");
    }

    setTimeout(() => setDiscoverySaved(null), 2000);
  };

  const handleDiscoveryReset = async () => {
    const d = DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS;
    setDiscoveryEnabled(d.enabled);
    setDiscoveryListenPort(d.listenPort ? String(d.listenPort) : "");
    setDiscoveryBootstrapInput(formatMarketplaceDiscoveryBootstrapInput(d.bootstrap));
    setDiscoveryTopic(d.topic ?? "");
    saveMarketplaceDiscoverySettings(d);

    if (isTauri()) {
      await stopMarketplaceDiscovery().catch(() => {
        // ignore
      });
      getMarketplaceDiscoveryStatus().then(setDiscoveryStatus).catch(() => {
        // ignore
      });
    }

    setDiscoverySaved("Reset to default");
    setTimeout(() => setDiscoverySaved(null), 2000);
  };

  const handleDiscoveryAnnounce = async () => {
    const feedUri = discoveryAnnounceUri.trim();
    if (!feedUri) return;
    try {
      await announceMarketplaceDiscovery({ feed_uri: feedUri });
      setDiscoveryAnnounceUri("");
      setDiscoverySaved("Announced");
    } catch (e) {
      setDiscoverySaved(e instanceof Error ? e.message : "Announce failed");
    }
    setTimeout(() => setDiscoverySaved(null), 2000);
  };

  const handleProvenanceSave = () => {
    const trustedAttesters = parseMarketplaceTrustedAttestersInput(trustedAttestersInput);
    const url = notaryUrl.trim() ? notaryUrl.trim() : null;

    saveMarketplaceProvenanceSettings({
      notaryUrl: url,
      trustedAttesters,
      requireVerified: requireVerifiedAttestation,
    });

    setProvenanceSaved("Saved");
    setTimeout(() => setProvenanceSaved(null), 2000);
  };

  const handleProvenanceReset = () => {
    const p = DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS;
    setNotaryUrl(p.notaryUrl ?? "");
    setTrustedAttestersInput(formatMarketplaceTrustedAttestersInput(p.trustedAttesters));
    setRequireVerifiedAttestation(p.requireVerified);
    saveMarketplaceProvenanceSettings(p);
    setProvenanceSaved("Reset to default");
    setTimeout(() => setProvenanceSaved(null), 2000);
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-2xl mx-auto p-6 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-semibold text-sdr-text-primary">Settings</h1>
          <p className="text-sdr-text-muted mt-1">Configure your SDR Desktop connection</p>
        </div>

        {/* Connection Status */}
        <Section title="Connection Status">
          <div className="flex items-center gap-4 p-4 bg-sdr-bg-secondary rounded-lg border border-sdr-border">
            <StatusIndicator status={status} />
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="font-medium text-sdr-text-primary capitalize">{status}</span>
                {info?.version && (
                  <span className="text-sm text-sdr-text-muted">v{info.version}</span>
                )}
              </div>
              {error && <p className="text-sm text-sdr-accent-red mt-1">{error}</p>}
              {info && (
                <p className="text-sm text-sdr-text-muted mt-1">
                  Policy: {info.policy_name ?? "default"}
                  {info.policy_hash && ` (${info.policy_hash.slice(0, 8)}...)`}
                </p>
              )}
            </div>
            {status === "connected" ? (
              <button
                onClick={disconnect}
                className="px-3 py-1.5 text-sm text-sdr-text-secondary hover:text-sdr-text-primary bg-sdr-bg-tertiary rounded-md transition-colors"
              >
                Disconnect
              </button>
            ) : (
              <button
                onClick={connect}
                disabled={status === "connecting"}
                className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white rounded-md hover:bg-sdr-accent-blue/90 disabled:opacity-50 transition-colors"
              >
                {status === "connecting" ? "Connecting..." : "Connect"}
              </button>
            )}
          </div>
        </Section>

        {/* Connection Mode */}
        <Section title="Connection Mode">
          <div className="space-y-2">
            {CONNECTION_MODES.map((m) => (
              <ModeOption
                key={m.id}
                mode={m}
                selected={mode === m.id}
                onSelect={() => setMode(m.id)}
              />
            ))}
          </div>
        </Section>

        {/* Daemon URL */}
        <Section title="Daemon URL">
          <div className="space-y-3">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="http://localhost:9876"
              className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono"
            />

            <div className="flex items-center gap-2">
              <button
                onClick={handleTest}
                disabled={isTesting || !urlInput}
                className="px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors disabled:opacity-50"
              >
                {isTesting ? "Testing..." : "Test Connection"}
              </button>
              <button
                onClick={handleSave}
                disabled={urlInput === daemonUrl}
                className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white rounded-md hover:bg-sdr-accent-blue/90 disabled:opacity-50 transition-colors"
              >
                Save & Connect
              </button>
            </div>

            {testResult && (
              <div
                className={clsx(
                  "p-3 rounded-md text-sm",
                  testResult.success
                    ? "bg-sdr-accent-green/10 text-sdr-accent-green"
                    : "bg-sdr-accent-red/10 text-sdr-accent-red"
                )}
              >
                {testResult.message}
              </div>
            )}
          </div>
        </Section>

        {/* Marketplace */}
        <Section title="Marketplace">
          <div className="space-y-3">
            <p className="text-sm text-sdr-text-muted">
              Configure signed marketplace feed sources (one per line). Use <code>builtin</code> for the
              bundled feed, or add <code>https://…</code> / <code>ipfs://…</code>.
            </p>
            <textarea
              value={marketplaceSourcesInput}
              onChange={(e) => setMarketplaceSourcesInput(e.target.value)}
              rows={4}
              className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
              placeholder="builtin"
            />

            <div className="flex items-center gap-2">
              <button
                onClick={handleMarketplaceSave}
                className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white rounded-md hover:bg-sdr-accent-blue/90 transition-colors"
              >
                Save
              </button>
              <button
                onClick={handleMarketplaceReset}
                className="px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
              >
                Reset
              </button>
              {marketplaceSaved && (
                <span className="text-sm text-sdr-text-muted">{marketplaceSaved}</span>
              )}
            </div>
          </div>
        </Section>

        {/* Marketplace Discovery */}
        <Section title="Marketplace Discovery (P2P)">
          <div className="space-y-3">
            <p className="text-sm text-sdr-text-muted">
              Optional P2P gossip for new marketplace feed URIs (e.g. <code>ipfs://…</code>). Discovery is
              untrusted: the Marketplace still verifies feed and bundle signatures.
            </p>

            <div className="flex items-start gap-3">
              <button
                onClick={() => setDiscoveryEnabled(!discoveryEnabled)}
                className={clsx(
                  "w-10 h-6 rounded-full transition-colors relative shrink-0 mt-0.5",
                  discoveryEnabled ? "bg-sdr-accent-blue" : "bg-sdr-bg-tertiary"
                )}
              >
                <span
                  className={clsx(
                    "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
                    discoveryEnabled ? "left-5" : "left-1"
                  )}
                />
              </button>
              <div>
                <div className="text-sm font-medium text-sdr-text-primary">Enable discovery</div>
                <div className="text-sm text-sdr-text-muted">
                  Uses libp2p gossipsub + mDNS (local network) and optional bootstrap peers.
                </div>
              </div>
            </div>

            {discoveryStatus && (
              <div className="p-3 rounded-md border border-sdr-border bg-sdr-bg-secondary text-xs text-sdr-text-muted space-y-1">
                <div>Status: {discoveryStatus.running ? "running" : "stopped"}</div>
                {discoveryStatus.peer_id && <div>Peer ID: {discoveryStatus.peer_id}</div>}
                {discoveryStatus.listen_addrs?.length ? (
                  <div>Listen: {discoveryStatus.listen_addrs[0]}</div>
                ) : null}
                {discoveryStatus.last_error && <div>Error: {discoveryStatus.last_error}</div>}
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                  Listen port (optional)
                </label>
                <input
                  type="text"
                  value={discoveryListenPort}
                  onChange={(e) => setDiscoveryListenPort(e.target.value)}
                  placeholder="auto"
                  className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                  Topic (optional)
                </label>
                <input
                  type="text"
                  value={discoveryTopic}
                  onChange={(e) => setDiscoveryTopic(e.target.value)}
                  placeholder="clawdstrike/marketplace/v1/discovery"
                  className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Bootstrap peers (optional)
              </label>
              <textarea
                value={discoveryBootstrapInput}
                onChange={(e) => setDiscoveryBootstrapInput(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
                placeholder="/ip4/1.2.3.4/tcp/12345/p2p/12D3KooW…"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleDiscoverySave}
                className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white rounded-md hover:bg-sdr-accent-blue/90 transition-colors"
              >
                Save
              </button>
              <button
                onClick={handleDiscoveryReset}
                className="px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
              >
                Reset
              </button>
              {discoverySaved && (
                <span className="text-sm text-sdr-text-muted">{discoverySaved}</span>
              )}
            </div>

            <div className="pt-2 border-t border-sdr-border/50">
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Announce feed URI (testing)
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={discoveryAnnounceUri}
                  onChange={(e) => setDiscoveryAnnounceUri(e.target.value)}
                  placeholder="ipfs://<CID>"
                  className="flex-1 px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
                />
                <button
                  onClick={handleDiscoveryAnnounce}
                  disabled={!discoveryAnnounceUri.trim()}
                  className="px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors disabled:opacity-50"
                >
                  Announce
                </button>
              </div>
            </div>
          </div>
        </Section>

        {/* Marketplace Provenance */}
        <Section title="Marketplace Provenance (Notary)">
          <div className="space-y-3">
            <p className="text-sm text-sdr-text-muted">
              Optional provenance verification via a notary service (e.g. for EAS attestations). Policies
              can include an <code>attestation_uid</code> pointer in the marketplace feed.
            </p>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-sdr-text-primary">
                Default notary URL (optional)
              </label>
              <input
                type="text"
                value={notaryUrl}
                onChange={(e) => setNotaryUrl(e.target.value)}
                placeholder="https://notary.example.com"
                className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Trusted attesters (optional)
              </label>
              <textarea
                value={trustedAttestersInput}
                onChange={(e) => setTrustedAttestersInput(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
                placeholder="0x…"
              />
              <p className="text-xs text-sdr-text-muted mt-1">
                If set, the Marketplace can filter to only attestations issued by these attesters.
              </p>
            </div>

            <div className="flex items-start gap-3">
              <button
                onClick={() => setRequireVerifiedAttestation(!requireVerifiedAttestation)}
                className={clsx(
                  "w-10 h-6 rounded-full transition-colors relative shrink-0 mt-0.5",
                  requireVerifiedAttestation ? "bg-sdr-accent-blue" : "bg-sdr-bg-tertiary"
                )}
              >
                <span
                  className={clsx(
                    "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
                    requireVerifiedAttestation ? "left-5" : "left-1"
                  )}
                />
              </button>
              <div>
                <div className="text-sm font-medium text-sdr-text-primary">
                  Require verified attestations by default
                </div>
                <div className="text-sm text-sdr-text-muted">
                  When enabled, Marketplace shows only policies with a valid attestation.
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleProvenanceSave}
                className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white rounded-md hover:bg-sdr-accent-blue/90 transition-colors"
              >
                Save
              </button>
              <button
                onClick={handleProvenanceReset}
                className="px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
              >
                Reset
              </button>
              {provenanceSaved && (
                <span className="text-sm text-sdr-text-muted">{provenanceSaved}</span>
              )}
            </div>
          </div>
        </Section>

        {/* Notifications */}
        <Section title="Notifications">
          <div className="space-y-3">
            <ToggleSetting
              label="Desktop notifications for blocked events"
              description="Show system notifications when an action is blocked"
              defaultChecked={true}
            />
            <ToggleSetting
              label="Sound alerts"
              description="Play a sound for critical events"
              defaultChecked={false}
            />
          </div>
        </Section>

        {/* Theme */}
        <Section title="Appearance">
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Theme
              </label>
              <select className="px-3 py-2 bg-sdr-bg-secondary text-sdr-text-primary rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue">
                <option value="dark">Dark</option>
                <option value="light" disabled>
                  Light (coming soon)
                </option>
                <option value="system" disabled>
                  System (coming soon)
                </option>
              </select>
            </div>
          </div>
        </Section>

        {/* About */}
        <Section title="About">
          <div className="p-4 bg-sdr-bg-secondary rounded-lg border border-sdr-border">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-sdr-accent-blue/20 flex items-center justify-center">
                <ShieldIcon className="w-6 h-6 text-sdr-accent-blue" />
              </div>
              <div>
                <h3 className="font-medium text-sdr-text-primary">SDR Desktop</h3>
                <p className="text-sm text-sdr-text-muted">Swarm Detection Response</p>
                <p className="text-xs text-sdr-text-muted mt-1">Version 0.1.0</p>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-sdr-border text-sm text-sdr-text-muted">
              <p>A companion app for the clawdstrike-sdr security framework.</p>
              <p className="mt-2">
                <a href="https://github.com/clawdstrike/sdr" className="text-sdr-accent-blue hover:underline">
                  GitHub
                </a>
                {" · "}
                <a href="https://docs.clawdstrike.dev" className="text-sdr-accent-blue hover:underline">
                  Documentation
                </a>
              </p>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
}

const CONNECTION_MODES: { id: ConnectionMode; label: string; description: string }[] = [
  {
    id: "local",
    label: "Local Daemon",
    description: "Connect to hushd running on this machine",
  },
  {
    id: "remote",
    label: "Remote Daemon",
    description: "Connect to hushd on a remote server",
  },
  {
    id: "embedded",
    label: "Embedded (Coming Soon)",
    description: "Run policy engine directly in the app",
  },
];

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2 className="text-sm font-medium text-sdr-text-muted uppercase tracking-wide mb-3">
        {title}
      </h2>
      {children}
    </section>
  );
}

function StatusIndicator({ status }: { status: string }) {
  const colors: Record<string, string> = {
    connected: "bg-sdr-accent-green",
    connecting: "bg-sdr-accent-amber animate-pulse",
    disconnected: "bg-sdr-text-muted",
    error: "bg-sdr-accent-red",
  };

  return (
    <div className="relative">
      <div className={clsx("w-3 h-3 rounded-full", colors[status] ?? colors.disconnected)} />
      {status === "connected" && (
        <div className="absolute inset-0 w-3 h-3 rounded-full bg-sdr-accent-green/50 animate-ping" />
      )}
    </div>
  );
}

interface ModeOptionProps {
  mode: { id: ConnectionMode; label: string; description: string };
  selected: boolean;
  onSelect: () => void;
}

function ModeOption({ mode, selected, onSelect }: ModeOptionProps) {
  const isDisabled = mode.id === "embedded";

  return (
    <button
      onClick={onSelect}
      disabled={isDisabled}
      className={clsx(
        "w-full text-left p-3 rounded-lg border transition-colors",
        selected
          ? "bg-sdr-accent-blue/10 border-sdr-accent-blue"
          : "bg-sdr-bg-secondary border-sdr-border hover:border-sdr-text-muted",
        isDisabled && "opacity-50 cursor-not-allowed"
      )}
    >
      <div className="flex items-center gap-3">
        <div
          className={clsx(
            "w-4 h-4 rounded-full border-2",
            selected ? "border-sdr-accent-blue bg-sdr-accent-blue" : "border-sdr-text-muted"
          )}
        >
          {selected && <div className="w-2 h-2 bg-white rounded-full m-0.5" />}
        </div>
        <div>
          <div className="font-medium text-sdr-text-primary">{mode.label}</div>
          <div className="text-sm text-sdr-text-muted">{mode.description}</div>
        </div>
      </div>
    </button>
  );
}

interface ToggleSettingProps {
  label: string;
  description: string;
  defaultChecked?: boolean;
}

function ToggleSetting({ label, description, defaultChecked }: ToggleSettingProps) {
  const [checked, setChecked] = useState(defaultChecked ?? false);

  return (
    <div className="flex items-start gap-3">
      <button
        onClick={() => setChecked(!checked)}
        className={clsx(
          "w-10 h-6 rounded-full transition-colors relative shrink-0 mt-0.5",
          checked ? "bg-sdr-accent-blue" : "bg-sdr-bg-tertiary"
        )}
      >
        <span
          className={clsx(
            "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
            checked ? "left-5" : "left-1"
          )}
        />
      </button>
      <div>
        <div className="text-sm font-medium text-sdr-text-primary">{label}</div>
        <div className="text-sm text-sdr-text-muted">{description}</div>
      </div>
    </div>
  );
}

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
