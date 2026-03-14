import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchFrozenBrokerProviders, type BrokerFrozenProviderStatus } from "../api/client";
import { NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";
import { HintBlock, formatDateTime } from "./broker-utils";

type BrokerStreamEvent = SSEEvent & Record<string, unknown>;

const EVENT_CARD_STYLE = {
  border: "1px solid rgba(27,34,48,0.9)",
  background: "rgba(11,13,16,0.82)",
  padding: 12,
} as const;

const FROZEN_CARD_STYLE = {
  border: "1px solid rgba(210,163,75,0.28)",
  background: "rgba(210,163,75,0.08)",
  padding: 12,
} as const;

function brokerVariant(
  eventType: string,
  outcome: unknown,
): "allowed" | "blocked" | "warn" {
  if (eventType.includes("revoked")) return "blocked";
  if (eventType.includes("frozen")) return "warn";
  if (outcome === "upstream_error" || outcome === "incomplete") return "warn";
  return "allowed";
}

export function BrokerTheater(_props: { windowId?: string }) {
  const { events, connected, paused, setPaused } = useSharedSSE();
  const [frozenProviders, setFrozenProviders] = useState<BrokerFrozenProviderStatus[]>([]);
  const [error, setError] = useState<string | null>(null);
  const latestFreezeEventId = useMemo(
    () =>
      events.find(
        (event) =>
          event.event_type === "broker_provider_frozen" ||
          event.event_type === "broker_provider_unfrozen" ||
          event.event_type === "broker_capabilities_revoked",
      )?._id ?? 0,
    [events],
  );

  const refreshFrozen = useCallback(async () => {
    try {
      const response = await fetchFrozenBrokerProviders();
      setFrozenProviders(response.frozen_providers);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load frozen providers");
    }
  }, []);

  useEffect(() => {
    void refreshFrozen();
    const interval = window.setInterval(() => void refreshFrozen(), 15_000);
    return () => window.clearInterval(interval);
  }, [refreshFrozen]);

  useEffect(() => {
    if (!latestFreezeEventId) return;
    void refreshFrozen();
  }, [latestFreezeEventId, refreshFrozen]);

  const brokerEvents = useMemo(
    () =>
      events.filter((event) => event.event_type.startsWith("broker_")) as BrokerStreamEvent[],
    [events],
  );

  const counts = useMemo(() => {
    let issued = 0;
    let evidence = 0;
    let replayed = 0;
    let revoked = 0;
    for (const event of brokerEvents) {
      if (event.event_type === "broker_capability_issued") issued += 1;
      if (event.event_type === "broker_evidence_recorded") evidence += 1;
      if (event.event_type === "broker_capability_replayed") replayed += 1;
      if (event.event_type === "broker_capability_revoked") revoked += 1;
      if (event.event_type === "broker_capabilities_revoked") {
        revoked +=
          typeof event.revoked_count === "number" && Number.isFinite(event.revoked_count)
            ? event.revoked_count
            : 1;
      }
    }
    return { issued, evidence, replayed, revoked };
  }, [brokerEvents]);

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "#e2e8f0", overflow: "auto", height: "100%" }}
    >
      <div className="flex flex-wrap items-center gap-3">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{
            backgroundColor: connected ? "#2fa7a0" : "#c23b3b",
            animation: "sseBreathingPulse 2s ease-in-out infinite",
          }}
        />
        <span className="font-mono text-xs uppercase" style={{ letterSpacing: "0.1em" }}>
          {connected ? "Broker Event Stream Connected" : "Broker Event Stream Offline"}
        </span>
        <button
          type="button"
          className="glass-panel hover-glass-button font-mono rounded-md px-3 py-1.5 text-[11px] uppercase"
          onClick={() => setPaused(!paused)}
          style={{ color: paused ? "#c23b3b" : "#2fa7a0", letterSpacing: "0.08em" }}
        >
          {paused ? "Resume Stream" : "Pause Stream"}
        </button>
        <button
          type="button"
          className="glass-panel hover-glass-button font-mono rounded-md px-3 py-1.5 text-[11px] uppercase"
          onClick={() => void refreshFrozen()}
          style={{ color: "#d6b15a", letterSpacing: "0.08em" }}
        >
          Refresh Frozen State
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <TheaterCard label="Issued" value={counts.issued} />
        <TheaterCard label="Evidence" value={counts.evidence} />
        <TheaterCard label="Replayed" value={counts.replayed} />
        <TheaterCard label="Revoked" value={counts.revoked} />
      </div>

      {error && (
        <div
          className="glass-panel font-mono text-xs"
          style={{
            padding: 12,
            color: "#c23b3b",
            borderColor: "rgba(194,59,59,0.3)",
          }}
        >
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1.4fr_1fr]">
        <section className="glass-panel rounded-lg p-4">
          <NoiseGrain />
          <div
            className="font-mono mb-3 text-[11px] uppercase"
            style={{ letterSpacing: "0.12em", color: "rgba(214,177,90,0.8)" }}
          >
            Live Timeline
          </div>
          <div className="space-y-3">
            {brokerEvents.length === 0 ? (
              <HintBlock>Waiting for broker events...</HintBlock>
            ) : (
              brokerEvents.slice(0, 60).map((event) => {
                const provider = typeof event.provider === "string" ? event.provider : "unknown";
                const capabilityId =
                  typeof event.capability_id === "string" ? event.capability_id : "-";
                const phase = typeof event.phase === "string" ? event.phase : undefined;
                const outcome = typeof event.outcome === "string" ? event.outcome : undefined;
                const url = typeof event.url === "string" ? event.url : undefined;
                return (
                  <div key={event._id} className="rounded-md" style={EVENT_CARD_STYLE}>
                    <div className="flex flex-wrap items-center gap-2">
                      <Stamp variant={brokerVariant(event.event_type, outcome)}>
                        {event.event_type.replace(/_/g, " ")}
                      </Stamp>
                      <span
                        className="font-mono text-xs"
                        style={{ color: "rgba(154,167,181,0.72)" }}
                      >
                        {provider}
                      </span>
                      {phase && (
                        <span
                          className="font-mono text-xs"
                          style={{ color: "rgba(154,167,181,0.55)" }}
                        >
                          {phase}
                        </span>
                      )}
                      {outcome && (
                        <span
                          className="font-mono text-xs"
                          style={{ color: "rgba(154,167,181,0.55)" }}
                        >
                          {outcome}
                        </span>
                      )}
                    </div>
                    <div className="mt-3 font-mono text-xs" style={{ color: "#e2e8f0" }}>
                      {capabilityId}
                    </div>
                    {url && (
                      <div className="mt-2 text-sm" style={{ color: "rgba(154,167,181,0.75)" }}>
                        {url}
                      </div>
                    )}
                    <div className="mt-2 font-mono text-xs" style={{ color: "rgba(154,167,181,0.5)" }}>
                      {formatDateTime(event.timestamp)}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="glass-panel rounded-lg p-4">
          <NoiseGrain />
          <div
            className="font-mono mb-3 text-[11px] uppercase"
            style={{ letterSpacing: "0.12em", color: "rgba(214,177,90,0.8)" }}
          >
            Provider Freeze Board
          </div>
          {frozenProviders.length === 0 ? (
            <HintBlock>No freezes are active.</HintBlock>
          ) : (
            <div className="space-y-3">
              {frozenProviders.map((provider) => (
                <div key={provider.provider} className="rounded-md" style={FROZEN_CARD_STYLE}>
                  <div className="flex items-center gap-2">
                    <Stamp variant="warn">{provider.provider}</Stamp>
                  </div>
                  <div className="mt-3 text-sm" style={{ color: "#e2e8f0" }}>
                    {provider.reason}
                  </div>
                  <div className="mt-2 font-mono text-xs" style={{ color: "rgba(154,167,181,0.6)" }}>
                    frozen {formatDateTime(provider.frozen_at)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function TheaterCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="glass-panel rounded-lg p-4">
      <NoiseGrain />
      <div className="relative">
        <div
          className="font-mono text-[10px] uppercase"
          style={{ letterSpacing: "0.12em", color: "rgba(154,167,181,0.65)" }}
        >
          {label}
        </div>
        <div className="mt-2 font-mono text-3xl" style={{ color: "#d6b15a" }}>
          {value}
        </div>
      </div>
    </div>
  );
}
