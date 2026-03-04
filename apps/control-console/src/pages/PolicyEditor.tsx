import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchAuditEvents, fetchPolicy } from "../api/client";
import { updatePolicy, type ValidateResult, validatePolicy } from "../api/policyApi";
import { PolicyDiffViewer } from "../components/policy/PolicyDiffViewer";
import { YamlEditor } from "../components/policy/YamlEditor";
import { GlassButton, NoiseGrain, Stamp } from "../components/ui";
import { diffLines } from "../utils/simpleDiff";

interface CanarySnapshot {
  previous_yaml: string;
  previous_policy_hash?: string;
  canary_policy_hash?: string;
  started_at: string;
}

interface SimulationSummary {
  generated_at: string;
  recent_events: number;
  unique_agents: number;
  blocked_events: number;
  high_risk_targets: number;
  changed_lines: number;
  action_hotspots: Array<{ action: string; count: number }>;
}

const CANARY_ROLLOUT_KEY = "cs.policy.canary-rollout.v1";

function readCanarySnapshot(): CanarySnapshot | null {
  try {
    const raw = localStorage.getItem(CANARY_ROLLOUT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if (typeof parsed.previous_yaml !== "string" || typeof parsed.started_at !== "string") {
      return null;
    }
    return parsed as CanarySnapshot;
  } catch {
    return null;
  }
}

function writeCanarySnapshot(snapshot: CanarySnapshot | null) {
  if (!snapshot) {
    localStorage.removeItem(CANARY_ROLLOUT_KEY);
    return;
  }
  localStorage.setItem(CANARY_ROLLOUT_KEY, JSON.stringify(snapshot));
}

function computeActionHotspots(events: Array<{ action_type: string }>): Array<{ action: string; count: number }> {
  const counts = new Map<string, number>();
  for (const event of events) {
    const action = event.action_type || "unknown";
    counts.set(action, (counts.get(action) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}

function isHighRiskTarget(target: string | undefined): boolean {
  if (!target) return false;
  return /(\/etc\/|\/root\/|\.ssh\/|token|secret|credentials|private[-_]?key)/i.test(target);
}

export function PolicyEditor(_props: { windowId?: string }) {
  const [yaml, setYaml] = useState("");
  const [loadedYaml, setLoadedYaml] = useState("");
  const [currentPolicyHash, setCurrentPolicyHash] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [rolloutBusy, setRolloutBusy] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  const [savedHash, setSavedHash] = useState<string | null>(null);
  const [simulation, setSimulation] = useState<SimulationSummary | null>(null);
  const [canarySnapshot, setCanarySnapshot] = useState<CanarySnapshot | null>(() =>
    readCanarySnapshot(),
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicy()
      .then((data) => {
        const nextYaml = data.yaml ?? JSON.stringify(data.policy, null, 2) ?? "";
        setYaml(nextYaml);
        setLoadedYaml(nextYaml);
        setCurrentPolicyHash(data.policy_hash ?? null);
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : "Failed to load policy");
      })
      .finally(() => setLoading(false));
  }, []);

  const hasYamlChanges = useMemo(() => yaml.trim() !== loadedYaml.trim(), [loadedYaml, yaml]);

  const handleValidate = useCallback(async () => {
    setValidating(true);
    setValidation(null);
    setSavedHash(null);
    setError(null);
    try {
      const result = await validatePolicy(yaml);
      setValidation(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Validation failed");
    } finally {
      setValidating(false);
    }
  }, [yaml]);

  const applyPolicy = useCallback(
    async (nextYaml: string): Promise<string> => {
      const result = await updatePolicy(nextYaml);
      if (!result.success) {
        throw new Error("Save returned unsuccessful status");
      }
      return result.policy_hash ?? "saved";
    },
    [],
  );

  const handleSave = useCallback(async () => {
    setSaving(true);
    setError(null);
    setSavedHash(null);
    try {
      const nextHash = await applyPolicy(yaml);
      setSavedHash(nextHash);
      setLoadedYaml(yaml);
      setCurrentPolicyHash(nextHash);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }, [applyPolicy, yaml]);

  const handleCanaryRollout = useCallback(async () => {
    if (!hasYamlChanges) {
      setError("No policy changes to roll out.");
      return;
    }

    setRolloutBusy(true);
    setError(null);
    setSavedHash(null);
    try {
      const previousYaml = loadedYaml;
      const previousHash = currentPolicyHash ?? undefined;
      const nextHash = await applyPolicy(yaml);
      const snapshot: CanarySnapshot = {
        previous_yaml: previousYaml,
        previous_policy_hash: previousHash,
        canary_policy_hash: nextHash,
        started_at: new Date().toISOString(),
      };
      setCanarySnapshot(snapshot);
      writeCanarySnapshot(snapshot);
      setSavedHash(nextHash);
      setLoadedYaml(yaml);
      setCurrentPolicyHash(nextHash);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Canary rollout failed");
    } finally {
      setRolloutBusy(false);
    }
  }, [applyPolicy, currentPolicyHash, hasYamlChanges, loadedYaml, yaml]);

  const handleRollback = useCallback(async () => {
    if (!canarySnapshot) {
      setError("No canary rollout snapshot available.");
      return;
    }
    setRolloutBusy(true);
    setError(null);
    setSavedHash(null);
    try {
      const rollbackHash = await applyPolicy(canarySnapshot.previous_yaml);
      setYaml(canarySnapshot.previous_yaml);
      setLoadedYaml(canarySnapshot.previous_yaml);
      setCurrentPolicyHash(rollbackHash);
      setCanarySnapshot(null);
      writeCanarySnapshot(null);
      setSavedHash(rollbackHash);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rollback failed");
    } finally {
      setRolloutBusy(false);
    }
  }, [applyPolicy, canarySnapshot]);

  const handleDryRun = useCallback(async () => {
    setSimulating(true);
    setError(null);
    setSimulation(null);
    try {
      const result = await validatePolicy(yaml);
      setValidation(result);
      if (!result.valid) {
        throw new Error("Policy validation failed. Fix validation errors before dry-run.");
      }

      const audit = await fetchAuditEvents({ limit: 200 });
      const events = audit.events ?? [];
      const changed = diffLines(loadedYaml, yaml);
      const changedLines =
        changed.left.filter((line) => line.type === "removed").length +
        changed.right.filter((line) => line.type === "added").length;
      const uniqueAgents = new Set(events.map((event) => event.agent_id).filter(Boolean)).size;
      const blockedEvents = events.filter((event) => event.decision === "blocked").length;
      const highRiskTargets = events.filter((event) => isHighRiskTarget(event.target)).length;

      setSimulation({
        generated_at: new Date().toISOString(),
        recent_events: events.length,
        unique_agents: uniqueAgents,
        blocked_events: blockedEvents,
        high_risk_targets: highRiskTargets,
        changed_lines: changedLines,
        action_hotspots: computeActionHotspots(events),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dry-run simulation failed");
    } finally {
      setSimulating(false);
    }
  }, [loadedYaml, yaml]);

  if (loading) {
    return (
      <div style={{ padding: 20, color: "rgba(229,231,235,0.4)" }}>
        <p className="font-mono text-sm" style={{ letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Loading...
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        color: "rgba(229,231,235,0.92)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: "1px solid var(--slate)",
          flexShrink: 0,
          gap: 12,
        }}
      >
        <h2
          className="font-mono"
          style={{
            fontSize: 12,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            color: "var(--gold)",
            margin: 0,
          }}
        >
          Policy Editor
        </h2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
          <GlassButton onClick={() => setShowDiff(true)} disabled={!hasYamlChanges}>
            Diff
          </GlassButton>
          <GlassButton onClick={handleDryRun} disabled={simulating}>
            {simulating ? "Dry-run..." : "Dry-run"}
          </GlassButton>
          <GlassButton onClick={handleValidate} disabled={validating}>
            {validating ? "Validating..." : "Validate"}
          </GlassButton>
          <GlassButton onClick={handleSave} disabled={saving} variant="primary">
            {saving ? "Saving..." : "Save"}
          </GlassButton>
          <GlassButton onClick={handleCanaryRollout} disabled={rolloutBusy || !hasYamlChanges}>
            {rolloutBusy ? "Rolling out..." : "Canary Rollout"}
          </GlassButton>
          <GlassButton onClick={handleRollback} disabled={rolloutBusy || !canarySnapshot}>
            {rolloutBusy ? "Rolling back..." : "Rollback"}
          </GlassButton>
        </div>
      </div>

      {showDiff && (
        <PolicyDiffViewer oldYaml={loadedYaml} newYaml={yaml} onClose={() => setShowDiff(false)} />
      )}

      <div
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 1,
          background: "var(--slate)",
          overflow: "hidden",
        }}
      >
        <div style={{ overflow: "hidden", background: "rgba(7,8,10,0.95)" }}>
          <YamlEditor value={yaml} onChange={setYaml} />
        </div>

        <div
          style={{
            background: "rgba(7,8,10,0.95)",
            overflow: "auto",
            padding: 16,
          }}
        >
          <h3
            className="font-mono"
            style={{
              fontSize: 10,
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              color: "var(--muted)",
              marginTop: 0,
              marginBottom: 16,
            }}
          >
            Guardrails + Validation
          </h3>

          {error && (
            <div
              className="glass-panel rounded-lg px-4 py-2.5 text-sm"
              style={{ borderColor: "rgba(194,59,59,0.3)", color: "#c23b3b", marginBottom: 12 }}
            >
              <NoiseGrain />
              <span className="relative z-10">{error}</span>
            </div>
          )}

          {validation && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ marginBottom: 8 }}>
                <Stamp variant={validation.valid ? "allowed" : "blocked"}>
                  {validation.valid ? "Valid" : "Invalid"}
                </Stamp>
              </div>
              {validation.errors && validation.errors.length > 0 && (
                <div className="glass-panel rounded-lg" style={{ padding: 12, marginTop: 8 }}>
                  <NoiseGrain />
                  <ul
                    className="font-mono relative z-10"
                    style={{
                      margin: 0,
                      padding: "0 0 0 16px",
                      fontSize: 12,
                      lineHeight: "20px",
                      color: "var(--stamp-blocked)",
                    }}
                  >
                    {validation.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {savedHash && (
            <div className="glass-panel rounded-lg" style={{ padding: 12, marginBottom: 12 }}>
              <NoiseGrain />
              <div className="relative z-10">
                <div style={{ marginBottom: 6 }}>
                  <Stamp variant="allowed">Policy Applied</Stamp>
                </div>
                <p className="font-mono" style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>
                  Policy hash: {savedHash}
                </p>
              </div>
            </div>
          )}

          {canarySnapshot && (
            <div className="glass-panel rounded-lg" style={{ padding: 12, marginBottom: 12 }}>
              <NoiseGrain />
              <div className="relative z-10">
                <div style={{ marginBottom: 6 }}>
                  <Stamp variant="warn">Canary Active</Stamp>
                </div>
                <p className="font-mono" style={{ fontSize: 11, color: "var(--muted)", margin: 0 }}>
                  Started: {new Date(canarySnapshot.started_at).toLocaleString()}
                </p>
                <p className="font-mono" style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 0" }}>
                  Baseline hash: {canarySnapshot.previous_policy_hash ?? "unknown"}
                </p>
                <p className="font-mono" style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 0" }}>
                  Canary hash: {canarySnapshot.canary_policy_hash ?? "unknown"}
                </p>
              </div>
            </div>
          )}

          {simulation && (
            <div className="glass-panel rounded-lg" style={{ padding: 12, marginBottom: 12 }}>
              <NoiseGrain />
              <div className="relative z-10">
                <div style={{ marginBottom: 6 }}>
                  <Stamp variant="warn">Dry-run Summary</Stamp>
                </div>
                <div
                  className="font-mono"
                  style={{ fontSize: 11, color: "rgba(229,231,235,0.82)", display: "grid", gap: 4 }}
                >
                  <span>Recent events: {simulation.recent_events}</span>
                  <span>Changed lines: {simulation.changed_lines}</span>
                  <span>Unique agents: {simulation.unique_agents}</span>
                  <span>Blocked events (recent baseline): {simulation.blocked_events}</span>
                  <span>High-risk targets seen: {simulation.high_risk_targets}</span>
                </div>
                <div style={{ marginTop: 8 }}>
                  <p className="font-mono" style={{ fontSize: 10, color: "rgba(214,177,90,0.7)", margin: 0 }}>
                    Action hotspots
                  </p>
                  <div style={{ display: "grid", gap: 4, marginTop: 6 }}>
                    {simulation.action_hotspots.map((hotspot) => (
                      <div
                        key={hotspot.action}
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          color: "rgba(154,167,181,0.75)",
                          display: "flex",
                          justifyContent: "space-between",
                        }}
                      >
                        <span>{hotspot.action}</span>
                        <span>{hotspot.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <p className="font-mono" style={{ fontSize: 10, color: "rgba(154,167,181,0.5)", marginTop: 8 }}>
                  Generated at: {new Date(simulation.generated_at).toLocaleString()}
                </p>
              </div>
            </div>
          )}

          {!validation && !savedHash && !simulation && !error && (
            <p className="font-mono" style={{ fontSize: 12, color: "rgba(154,167,181,0.4)", letterSpacing: "0.06em" }}>
              Validate before rollout. Use Dry-run and Diff to preview change impact, then apply with
              Canary Rollout and keep Rollback ready.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
