import { useCallback, useEffect, useState } from "react";
import { fetchPolicy } from "../api/client";
import { updatePolicy, type ValidateResult, validatePolicy } from "../api/policyApi";
import { YamlEditor } from "../components/policy/YamlEditor";
import { GlassButton, NoiseGrain, Stamp } from "../components/ui";

export function PolicyEditor(_props: { windowId?: string }) {
  const [yaml, setYaml] = useState("");
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  const [savedHash, setSavedHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicy()
      .then((data) => {
        setYaml(data.yaml ?? JSON.stringify(data.policy, null, 2) ?? "");
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : "Failed to load policy");
      })
      .finally(() => setLoading(false));
  }, []);

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

  const handleSave = useCallback(async () => {
    setSaving(true);
    setError(null);
    setSavedHash(null);
    try {
      const result = await updatePolicy(yaml);
      if (result.success) {
        setSavedHash(result.policy_hash ?? "saved");
      } else {
        setError("Save returned unsuccessful status");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }, [yaml]);

  if (loading) {
    return (
      <div style={{ padding: 20, color: "rgba(229,231,235,0.4)" }}>
        <p
          className="font-mono text-sm"
          style={{ letterSpacing: "0.1em", textTransform: "uppercase" }}
        >
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
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: "1px solid var(--slate)",
          flexShrink: 0,
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
        <div style={{ display: "flex", gap: 8 }}>
          <GlassButton onClick={handleValidate} disabled={validating}>
            {validating ? "Validating..." : "Validate"}
          </GlassButton>
          <GlassButton onClick={handleSave} disabled={saving} variant="primary">
            {saving ? "Saving..." : "Save"}
          </GlassButton>
        </div>
      </div>

      {/* Split pane */}
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
        {/* Editor pane */}
        <div style={{ overflow: "hidden", background: "rgba(7,8,10,0.95)" }}>
          <YamlEditor value={yaml} onChange={setYaml} />
        </div>

        {/* Results pane */}
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
            Validation Results
          </h3>

          {error && (
            <div
              className="glass-panel rounded-lg px-4 py-2.5 text-sm"
              style={{
                borderColor: "rgba(194,59,59,0.3)",
                color: "#c23b3b",
                marginBottom: 12,
              }}
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
            <div className="glass-panel rounded-lg" style={{ padding: 12 }}>
              <NoiseGrain />
              <div className="relative z-10">
                <div style={{ marginBottom: 6 }}>
                  <Stamp variant="allowed">Saved</Stamp>
                </div>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 12,
                    color: "var(--muted)",
                    margin: 0,
                  }}
                >
                  Policy hash: {savedHash}
                </p>
              </div>
            </div>
          )}

          {!validation && !savedHash && !error && (
            <p
              className="font-mono"
              style={{
                fontSize: 12,
                color: "rgba(154,167,181,0.4)",
                letterSpacing: "0.06em",
              }}
            >
              Click "Validate" to check the policy YAML, or "Save" to apply changes.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
