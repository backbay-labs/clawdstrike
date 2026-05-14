import { useState, useCallback } from "react";
import {
  IconPlugConnected,
  IconPlugConnectedX,
  IconCheck,
  IconX,
  IconEye,
  IconEyeOff,
  IconRefresh,
  IconLoader2,
  IconCircleDot,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import type { HealthResponse } from "@/features/fleet/fleet-client";
import { emitAuditEvent } from "@/lib/workbench/local-audit";

/** Ensure a URL has an http(s):// prefix — normalizes bare "localhost:PORT" inputs. */
function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return trimmed;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `http://${trimmed}`;
}

// Finding M5: Only include dev credentials in development mode.
// In production, only pre-fill URLs (no secrets).
const LOCAL_STACK_PRESET = import.meta.env.DEV
  ? ({
      hushdUrl: "http://localhost:9876",
      controlApiUrl: "http://localhost:8090",
      apiKey: "clawdstrike-local-admin",
      controlApiToken: "cs_local_dev_key",
    } as const)
  : ({
      hushdUrl: "http://localhost:9876",
      controlApiUrl: "http://localhost:8090",
      apiKey: "",
      controlApiToken: "",
    } as const);

export function ConnectionSettings() {
  const {
    connection,
    isConnecting,
    error,
    agents,
    remotePolicyInfo,
    connect,
    disconnect,
    testConnection,
    refreshAgents,
    getCredentials,
  } = useFleetConnection();

  const credentials = getCredentials();
  const [hushdUrl, setHushdUrl] = useState(connection.hushdUrl || "http://localhost:9876");
  const [controlApiUrl, setControlApiUrl] = useState(connection.controlApiUrl || "");
  const [apiKey, setApiKey] = useState(credentials.apiKey || "");
  const [showApiKey, setShowApiKey] = useState(false);
  const [controlApiToken, setControlApiToken] = useState(credentials.controlApiToken || "");
  const [showControlToken, setShowControlToken] = useState(false);

  const [testResult, setTestResult] = useState<
    { ok: true; health: HealthResponse & { tlsWarning?: string } } | { ok: false; error: string } | null
  >(null);
  const [isTesting, setIsTesting] = useState(false);

  const handleTest = useCallback(async () => {
    setIsTesting(true);
    setTestResult(null);
    const url = normalizeUrl(hushdUrl);
    setHushdUrl(url);
    try {
      const health = await testConnection(url, apiKey);
      setTestResult({ ok: true, health });
    } catch (err) {
      setTestResult({
        ok: false,
        error: err instanceof Error ? err.message : "Connection failed",
      });
    } finally {
      setIsTesting(false);
    }
  }, [hushdUrl, apiKey, testConnection]);

  const handleConnect = useCallback(async () => {
    const hUrl = normalizeUrl(hushdUrl);
    const cUrl = normalizeUrl(controlApiUrl);
    setHushdUrl(hUrl);
    setControlApiUrl(cUrl);
    const success = await connect(hUrl, cUrl, apiKey, controlApiToken);
    if (success) {
      emitAuditEvent({
        eventType: "fleet.connected",
        source: "settings",
        summary: `Connected to fleet at ${hUrl}`,
        details: { hushdUrl: hUrl, controlApiUrl: cUrl || undefined },
      });
    }
  }, [hushdUrl, controlApiUrl, apiKey, controlApiToken, connect]);

  const handleApplyLocalStack = useCallback(() => {
    setHushdUrl(LOCAL_STACK_PRESET.hushdUrl);
    setControlApiUrl(LOCAL_STACK_PRESET.controlApiUrl);
    setApiKey(LOCAL_STACK_PRESET.apiKey);
    setControlApiToken(LOCAL_STACK_PRESET.controlApiToken);
    setTestResult(null);
  }, []);

  const handleDisconnect = useCallback(() => {
    emitAuditEvent({
      eventType: "fleet.disconnected",
      source: "settings",
      summary: "Disconnected from fleet",
    });
    disconnect();
    setTestResult(null);
  }, [disconnect]);

  const onlineAgents = agents.filter((a) => a.online).length;
  const staleAgents = agents.filter((a) => a.drift.stale).length;

  return (
    <div className="flex flex-col gap-6">
      <div
        className={cn(
          "flex items-center gap-3 px-4 py-3 rounded-lg border",
          connection.connected
            ? "bg-[#3dbf84]/5 border-[#3dbf84]/20"
            : error
              ? "bg-[#c45c5c]/5 border-[#c45c5c]/20"
              : "bg-[#131721] border-[#2d3240]",
        )}
      >
        <IconCircleDot
          size={16}
          stroke={2}
          className={cn(
            connection.connected
              ? "text-[#3dbf84]"
              : error
                ? "text-[#c45c5c]"
                : "text-[#6f7f9a]",
          )}
        />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-[#ece7dc]">
            {connection.connected
              ? "Connected"
              : error
                ? "Connection Error"
                : "Disconnected"}
          </p>
          {connection.connected && connection.hushdHealth && (
            <p className="text-[10px] text-[#6f7f9a] mt-0.5">
              hushd {connection.hushdHealth.version ?? "unknown"} &middot;{" "}
              {connection.hushdUrl}
            </p>
          )}
          {error && !connection.connected && (
            <p className="text-[10px] text-[#c45c5c] mt-0.5">{error}</p>
          )}
          {!connection.connected && !error && (
            <p className="text-[10px] text-[#6f7f9a] mt-0.5">
              Configure your hushd daemon URL to connect
            </p>
          )}
        </div>
        {connection.connected && (
          <button
            onClick={handleDisconnect}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-medium text-[#c45c5c] bg-[#c45c5c]/10 hover:bg-[#c45c5c]/20 border border-[#c45c5c]/20 transition-colors"
          >
            <IconPlugConnectedX size={12} stroke={1.5} />
            Disconnect
          </button>
        )}
      </div>

      {connection.connected && (
        <div className="flex flex-col gap-3 p-4 rounded-lg border border-[#2d3240] bg-[#131721]/50">
          <div className="flex items-center justify-between">
            <h4 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
              Fleet Summary
            </h4>
            <button
              onClick={refreshAgents}
              className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
              title="Refresh agent list"
            >
              <IconRefresh size={12} stroke={1.5} />
            </button>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <span className="text-[#ece7dc]">
              <span className="font-mono text-[#d4a84b]">{agents.length}</span> agents
            </span>
            <span className="w-px h-3 bg-[#2d3240]/60" />
            <span className="text-[#3dbf84]">
              <span className="font-mono">{onlineAgents}</span> online
            </span>
            {staleAgents > 0 && (
              <>
                <span className="w-px h-3 bg-[#2d3240]/60" />
                <span className="text-[#d4a84b]">
                  <span className="font-mono">{staleAgents}</span> stale
                </span>
              </>
            )}
          </div>

          {remotePolicyInfo && (
            <div className="flex flex-col gap-1 pt-2 border-t border-[#2d3240]/40">
              <span className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
                Active Policy
              </span>
              <span className="text-xs text-[#ece7dc]">
                {remotePolicyInfo.name ?? "Unnamed"}{" "}
                {remotePolicyInfo.version && (
                  <span className="text-[#6f7f9a]">v{remotePolicyInfo.version}</span>
                )}
              </span>
              {remotePolicyInfo.policyHash && (
                <span className="text-[10px] font-mono text-[#6f7f9a]">
                  hash: {remotePolicyInfo.policyHash.slice(0, 12)}...
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {!connection.connected && (
        <div className="flex flex-col gap-4">
          {import.meta.env.DEV && (
          <div className="flex items-start justify-between gap-3 p-3 rounded-lg border border-[#2d3240] bg-[#131721]/60">
            <div className="min-w-0">
              <p className="text-xs font-medium text-[#ece7dc]">Local Stack</p>
              <p className="text-[10px] text-[#6f7f9a] mt-1 leading-relaxed">
                Prefill the local Docker Compose defaults for hushd, control-api, and the
                seeded development keys.
              </p>
              <p className="text-[10px] text-[#6f7f9a] mt-1 font-mono">
                hushd :9876 &middot; control-api :8090
              </p>
            </div>
            <button
              type="button"
              onClick={handleApplyLocalStack}
              className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-medium border border-[#2d3240] bg-[#131721] text-[#ece7dc] hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
            >
              Use Local Stack
            </button>
          </div>
          )}

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#ece7dc]">hushd URL</label>
            <div className="flex items-center gap-2">
              <input
                type="url"
                value={hushdUrl}
                onChange={(e) => {
                  setHushdUrl(e.target.value);
                  setTestResult(null);
                }}
                placeholder="http://localhost:9876"
                className="flex-1 h-8 px-2.5 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] font-mono placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/50 focus:outline-none focus:ring-1 focus:ring-[#d4a84b]/20 transition-colors"
              />
              <button
                onClick={handleTest}
                disabled={isTesting || !hushdUrl}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-medium border transition-colors",
                  isTesting
                    ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                    : "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
                  !hushdUrl && "opacity-50 pointer-events-none",
                )}
              >
                {isTesting ? (
                  <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
                ) : (
                  <IconPlugConnected size={12} stroke={1.5} />
                )}
                Test
              </button>
            </div>

            {testResult && (
              <div className="flex flex-col gap-1 mt-0.5">
                <div
                  className={cn(
                    "flex items-center gap-1.5 text-[10px]",
                    testResult.ok ? "text-[#3dbf84]" : "text-[#c45c5c]",
                  )}
                >
                  {testResult.ok ? (
                    <>
                      <IconCheck size={11} stroke={2} />
                      <span>
                        Connected &mdash; hushd {testResult.health.version ?? "unknown"}
                        {testResult.health.policy_hash && (
                          <span className="text-[#6f7f9a]">
                            {" "}(policy: {testResult.health.policy_hash.slice(0, 8)}...)
                          </span>
                        )}
                      </span>
                    </>
                  ) : (
                    <>
                      <IconX size={11} stroke={2} />
                      <span>{testResult.error}</span>
                    </>
                  )}
                </div>
                {testResult.ok && testResult.health.tlsWarning && (
                  <div className="flex items-center gap-1.5 text-[10px] text-[#d4a84b]">
                    <IconAlertTriangle size={11} stroke={2} />
                    <span>{testResult.health.tlsWarning}</span>
                  </div>
                )}
              </div>
            )}

            <span className="text-[10px] text-[#6f7f9a]">
              The hushd daemon URL for policy management and health checks
            </span>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#ece7dc]">
              Control API URL{" "}
              <span className="text-[10px] text-[#6f7f9a] font-normal">(optional)</span>
            </label>
            <input
              type="url"
              value={controlApiUrl}
              onChange={(e) => setControlApiUrl(e.target.value)}
              placeholder={LOCAL_STACK_PRESET.controlApiUrl}
              className="h-8 px-2.5 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] font-mono placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/50 focus:outline-none focus:ring-1 focus:ring-[#d4a84b]/20 transition-colors"
            />
            <span className="text-[10px] text-[#6f7f9a]">
              For fleet agent management and policy distribution
            </span>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#ece7dc]">
              Control API Token{" "}
              <span className="text-[10px] text-[#6f7f9a] font-normal">(JWT or API key)</span>
            </label>
            <div className="relative">
              <input
                type={showControlToken ? "text" : "password"}
                value={controlApiToken}
                onChange={(e) => setControlApiToken(e.target.value)}
                placeholder="eyJhbGci..."
                className="w-full h-8 px-2.5 pr-9 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] font-mono placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/50 focus:outline-none focus:ring-1 focus:ring-[#d4a84b]/20 transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowControlToken(!showControlToken)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
              >
                {showControlToken ? (
                  <IconEyeOff size={14} stroke={1.5} />
                ) : (
                  <IconEye size={14} stroke={1.5} />
                )}
              </button>
            </div>
            <span className="text-[10px] text-[#6f7f9a]">
              JWT or API key for authenticating with control-api (separate from hushd)
            </span>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#ece7dc]">API Key</label>
            <div className="relative">
              <input
                type={showApiKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="hush_..."
                className="w-full h-8 px-2.5 pr-9 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] font-mono placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/50 focus:outline-none focus:ring-1 focus:ring-[#d4a84b]/20 transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowApiKey(!showApiKey)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
              >
                {showApiKey ? (
                  <IconEyeOff size={14} stroke={1.5} />
                ) : (
                  <IconEye size={14} stroke={1.5} />
                )}
              </button>
            </div>
            <span className="text-[10px] text-[#6f7f9a]">
              Bearer token for authenticating with hushd
            </span>
          </div>

          <button
            onClick={handleConnect}
            disabled={isConnecting || !hushdUrl}
            className={cn(
              "flex items-center justify-center gap-2 h-9 rounded-lg text-xs font-medium transition-all",
              isConnecting
                ? "bg-[#d4a84b]/20 text-[#d4a84b] cursor-wait"
                : !hushdUrl
                  ? "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed"
                  : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a] active:scale-[0.98]",
            )}
          >
            {isConnecting ? (
              <>
                <IconLoader2 size={14} stroke={2} className="animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <IconPlugConnected size={14} stroke={2} />
                Connect to Fleet
              </>
            )}
          </button>

          <div className="flex items-start gap-2 p-3 rounded-lg bg-[#d4a84b]/5 border border-[#d4a84b]/10">
            <IconAlertTriangle size={14} stroke={1.5} className="text-[#d4a84b] shrink-0 mt-0.5" />
            <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
              On desktop, credentials are encrypted at rest using Stronghold secure storage.
              On web, credentials are stored in session storage and cleared when the tab
              closes. Do not use the web version on shared or untrusted machines.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
