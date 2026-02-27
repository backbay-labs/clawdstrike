import { useState } from "react";
import { testGuard, type GuardTestResult } from "../api/guardApi";
import { GuardSelector } from "../components/guards/GuardSelector";
import { GuardInputForm } from "../components/guards/GuardInputForm";
import { NoiseGrain, Stamp } from "../components/ui";

export function GuardPlayground(_props: { windowId?: string }) {
  const [guard, setGuard] = useState("ForbiddenPathGuard");
  const [result, setResult] = useState<GuardTestResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleTest = async (input: Record<string, unknown>) => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await testGuard(guard, input);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Guard test failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="space-y-5"
      style={{
        padding: 20,
        color: "rgba(229,231,235,0.92)",
        overflow: "auto",
        height: "100%",
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
        Guard Playground
      </h2>

      <div
        className="glass-panel rounded-lg"
        style={{ padding: 16 }}
      >
        <NoiseGrain />
        <div className="relative z-10 space-y-4">
          <GuardSelector value={guard} onChange={setGuard} />
          <GuardInputForm guard={guard} onSubmit={handleTest} />
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <p
          className="font-mono text-sm"
          style={{
            color: "rgba(229,231,235,0.4)",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          Testing...
        </p>
      )}

      {/* Error */}
      {error && (
        <div
          className="glass-panel rounded-lg px-4 py-2.5 text-sm"
          style={{ borderColor: "rgba(194,59,59,0.3)", color: "#c23b3b" }}
        >
          <NoiseGrain />
          <span className="relative z-10">{error}</span>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="glass-panel rounded-lg" style={{ padding: 16 }}>
          <NoiseGrain />
          <div className="relative z-10 space-y-3">
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <Stamp variant={result.decision === "allowed" ? "allowed" : "blocked"}>
                {result.decision}
              </Stamp>
              <span
                className="font-mono"
                style={{ fontSize: 12, color: "var(--muted)" }}
              >
                {result.guard}
              </span>
            </div>

            {result.reasoning && (
              <div>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.1em",
                    color: "rgba(214,177,90,0.6)",
                    marginBottom: 4,
                  }}
                >
                  Reasoning
                </p>
                <p
                  className="font-mono"
                  style={{ fontSize: 12, color: "var(--text)", lineHeight: "18px", margin: 0 }}
                >
                  {result.reasoning}
                </p>
              </div>
            )}

            {result.duration_ms != null && (
              <p
                className="font-mono"
                style={{ fontSize: 11, color: "var(--muted)", margin: 0 }}
              >
                Duration: {result.duration_ms}ms
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
