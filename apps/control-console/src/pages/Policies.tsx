import { useCallback, useEffect, useRef, useState } from "react";
import { fetchPolicy, type PolicyResponse } from "../api/client";
import { PolicyDiffViewer } from "../components/policy/PolicyDiffViewer";
import { GlassButton, NoiseGrain } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import { highlightYaml } from "../utils/yamlHighlight";

export function Policies(_props: { windowId?: string }) {
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [previousYaml, setPreviousYaml] = useState<string>("");
  const lastYamlRef = useRef<string>("");
  const loadingRef = useRef(false);

  const { events } = useSharedSSE();

  const load = useCallback(async () => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const data = await fetchPolicy();
      // Capture previous YAML before updating
      if (lastYamlRef.current && data.yaml && data.yaml !== lastYamlRef.current) {
        setPreviousYaml(lastYamlRef.current);
      }
      if (data.yaml) {
        lastYamlRef.current = data.yaml;
      }
      setPolicy(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policy");
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Re-fetch when we see a policy_updated SSE event
  const lastSeenEventRef = useRef(0);
  useEffect(() => {
    const policyEvent = events.find(
      (e) => e.event_type === "policy_updated" && e._id > lastSeenEventRef.current,
    );
    if (policyEvent) {
      lastSeenEventRef.current = policyEvent._id;
      load();
    }
  }, [events, load]);

  const currentYaml = policy?.yaml ?? "";

  return (
    <div
      className="space-y-5"
      style={{
        padding: 20,
        color: "rgba(229,231,235,0.92)",
        overflow: "auto",
        height: "100%",
        position: "relative",
      }}
    >
      <div className="flex items-center justify-between">
        <div style={{ display: "flex", gap: 8 }}>
          <GlassButton onClick={load}>Reload</GlassButton>
          <GlassButton onClick={() => setShowDiff(true)} disabled={!previousYaml}>
            Diff
          </GlassButton>
        </div>
      </div>

      {showDiff && previousYaml && (
        <PolicyDiffViewer
          oldYaml={previousYaml}
          newYaml={currentYaml}
          onClose={() => setShowDiff(false)}
        />
      )}

      {error && (
        <div
          className="glass-panel rounded-lg px-4 py-2.5 text-sm"
          style={{ borderColor: "rgba(194,59,59,0.3)", color: "#c23b3b" }}
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
            <InfoCard
              label="Hash"
              value={policy.policy_hash ? policy.policy_hash.slice(0, 16) + "..." : "-"}
            />
            <InfoCard
              label="Source"
              value={
                policy.source
                  ? `${policy.source.kind}${policy.source.path ? `: ${policy.source.path}` : ""}`
                  : "local"
              }
            />
          </div>

          {policy.yaml && (
            <div>
              <h2 className="font-display mb-3 text-base tracking-wide" style={{ color: "#fff" }}>
                Policy YAML
              </h2>
              <div className="glass-panel rounded-lg" style={{ background: "rgba(7,8,10,0.88)" }}>
                <NoiseGrain />
                <pre
                  className="font-mono relative z-10 max-h-[600px] overflow-auto p-4 text-sm"
                  style={{ color: "rgba(229,231,235,0.85)" }}
                  dangerouslySetInnerHTML={{ __html: highlightYaml(policy.yaml) }}
                />
              </div>
            </div>
          )}

          {!!policy.policy && !policy.yaml && (
            <div>
              <h2 className="font-display mb-3 text-base tracking-wide" style={{ color: "#fff" }}>
                Policy Configuration
              </h2>
              <div className="glass-panel rounded-lg" style={{ background: "rgba(7,8,10,0.88)" }}>
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
          color: "rgba(214,177,90,0.6)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        {label}
      </p>
      <p className="font-mono relative z-10 mt-1 text-sm" style={{ color: "#fff" }}>
        {value}
      </p>
    </div>
  );
}
