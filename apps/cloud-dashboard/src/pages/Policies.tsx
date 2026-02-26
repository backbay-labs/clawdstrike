import { useCallback, useEffect, useState } from "react";
import { fetchPolicy, type PolicyResponse } from "../api/client";
import { NoiseGrain, GlassButton } from "../components/ui";

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
          className="font-display text-2xl tracking-wide"
          style={{ color: "#fff" }}
        >
          Active Policy
        </h1>
        <GlassButton onClick={load}>Reload</GlassButton>
      </div>

      {error && (
        <div
          className="glass-panel rounded-lg px-4 py-2.5 text-sm"
          style={{ borderColor: "rgba(239,68,68,0.3)", color: "#ef4444" }}
        >
          <NoiseGrain />
          <span className="relative z-10">{error}</span>
        </div>
      )}

      {loading ? (
        <p
          className="font-mono text-sm"
          style={{
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
                className="font-display mb-3 text-base tracking-wide"
                style={{ color: "#fff" }}
              >
                Policy YAML
              </h2>
              <div className="glass-panel rounded-lg" style={{ background: "rgba(4,8,16,0.88)" }}>
                <NoiseGrain />
                <pre
                  className="font-mono relative z-10 max-h-[600px] overflow-auto p-4 text-sm"
                  style={{ color: "rgba(229,231,235,0.85)" }}
                >
                  {policy.yaml}
                </pre>
              </div>
            </div>
          )}

          {!!policy.policy && !policy.yaml && (
            <div>
              <h2
                className="font-display mb-3 text-base tracking-wide"
                style={{ color: "#fff" }}
              >
                Policy Configuration
              </h2>
              <div className="glass-panel rounded-lg" style={{ background: "rgba(4,8,16,0.88)" }}>
                <NoiseGrain />
                <pre
                  className="font-mono relative z-10 max-h-[600px] overflow-auto p-4 text-sm"
                  style={{ color: "rgba(229,231,235,0.85)" }}
                >
                  {JSON.stringify(policy.policy, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      ) : (
        <p
          className="font-mono text-sm"
          style={{
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
    <div className="glass-panel rounded-lg p-4">
      <NoiseGrain />
      <p
        className="font-mono relative z-10 text-[10px]"
        style={{
          color: "rgba(34,211,238,0.6)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        {label}
      </p>
      <p
        className="font-mono relative z-10 mt-1 text-sm"
        style={{ color: "#fff" }}
      >
        {value}
      </p>
    </div>
  );
}
