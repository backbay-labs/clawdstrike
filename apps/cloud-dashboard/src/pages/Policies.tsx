import { useCallback, useEffect, useState } from "react";
import { fetchPolicy, type PolicyResponse } from "../api/client";

const GLASS_PANEL = {
  background: "rgba(4,8,16,0.94)",
  border: "1px solid rgba(34,211,238,0.12)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
} as const;

const GLASS_CODE = {
  ...GLASS_PANEL,
  background: "rgba(4,8,16,0.88)",
} as const;

function NoiseGrain({ id = "policyNoise" }: { id?: string }) {
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

export function Policies(_props: { windowId?: string }) {
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPolicy();
      setPolicy(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policy");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-5" style={{ color: "rgba(229,231,235,0.92)" }}>
      <div className="flex items-center justify-between">
        <h1
          className="text-2xl tracking-wide"
          style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
        >
          Active Policy
        </h1>
        <button
          onClick={load}
          className="rounded-md px-4 py-1.5 text-sm transition-all duration-200"
          style={{
            ...GLASS_PANEL,
            color: "#22d3ee",
            cursor: "pointer",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.boxShadow =
              "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 12px rgba(34,211,238,0.15)";
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.3)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02)";
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)";
          }}
        >
          Reload
        </button>
      </div>

      {error && (
        <div
          className="rounded-lg px-4 py-2.5 text-sm relative overflow-hidden"
          style={{
            ...GLASS_PANEL,
            borderColor: "rgba(239,68,68,0.3)",
            color: "#ef4444",
          }}
        >
          <NoiseGrain id="policyError" />
          <span className="relative z-10">{error}</span>
        </div>
      )}

      {loading ? (
        <p
          className="text-sm"
          style={{
            fontFamily: "var(--glia-font-mono), monospace",
            color: "rgba(229,231,235,0.4)",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          Loading...
        </p>
      ) : policy ? (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <InfoCard label="Name" value={policy.name ?? "default"} />
            <InfoCard label="Version" value={policy.version ?? "-"} />
            <InfoCard label="Hash" value={policy.policy_hash ? policy.policy_hash.slice(0, 16) + "..." : "-"} />
            <InfoCard label="Source" value={policy.source ? `${policy.source.kind}${policy.source.path ? `: ${policy.source.path}` : ""}` : "local"} />
          </div>

          {policy.yaml && (
            <div>
              <h2
                className="mb-3 text-base tracking-wide"
                style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
              >
                Policy YAML
              </h2>
              <div className="relative overflow-hidden rounded-lg" style={GLASS_CODE}>
                <NoiseGrain id="policyYaml" />
                <pre
                  className="relative z-10 max-h-[600px] overflow-auto p-4 text-sm"
                  style={{
                    fontFamily: "var(--glia-font-mono), monospace",
                    color: "rgba(229,231,235,0.85)",
                  }}
                >
                  {policy.yaml}
                </pre>
              </div>
            </div>
          )}

          {!!policy.policy && !policy.yaml && (
            <div>
              <h2
                className="mb-3 text-base tracking-wide"
                style={{ fontFamily: "var(--glia-font-display), Cinzel, serif", color: "#fff" }}
              >
                Policy Configuration
              </h2>
              <div className="relative overflow-hidden rounded-lg" style={GLASS_CODE}>
                <NoiseGrain id="policyConfig" />
                <pre
                  className="relative z-10 max-h-[600px] overflow-auto p-4 text-sm"
                  style={{
                    fontFamily: "var(--glia-font-mono), monospace",
                    color: "rgba(229,231,235,0.85)",
                  }}
                >
                  {JSON.stringify(policy.policy, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      ) : (
        <p
          className="text-sm"
          style={{
            fontFamily: "var(--glia-font-mono), monospace",
            color: "rgba(229,231,235,0.4)",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          No policy loaded
        </p>
      )}
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div
      className="relative overflow-hidden rounded-lg p-4"
      style={GLASS_PANEL}
    >
      <NoiseGrain id={`card-${label.toLowerCase()}`} />
      <p
        className="relative z-10 text-[10px]"
        style={{
          fontFamily: "var(--glia-font-mono), monospace",
          color: "rgba(34,211,238,0.6)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        {label}
      </p>
      <p
        className="relative z-10 mt-1 text-sm"
        style={{
          fontFamily: "var(--glia-font-mono), monospace",
          color: "#fff",
        }}
      >
        {value}
      </p>
    </div>
  );
}
