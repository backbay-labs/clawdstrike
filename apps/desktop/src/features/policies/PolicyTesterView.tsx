/**
 * PolicyTesterView - Simulate canonical PolicyEvent evaluations
 */

import { Badge, GlassHeader, GlassPanel, GlowButton, GlowInput } from "@backbay/glia/primitives";
import { clsx } from "clsx";
import type { FormEvent } from "react";
import { useState } from "react";
import { useConnection } from "@/context/ConnectionContext";
import {
  buildPolicyTestEvent,
  getPolicyTestTargetPlaceholder,
  POLICY_TEST_EVENT_TYPES,
  type PolicyTestEventType,
} from "@/features/forensics/policy-workbench/mapping";
import { HushdClient, type PolicyEvalResponse } from "@/services/hushdClient";

interface TestForm {
  eventType: PolicyTestEventType;
  target: string;
  content: string;
  extra: string;
  sessionId: string;
  agentId: string;
}

export function PolicyTesterView() {
  const { status, daemonUrl } = useConnection();

  const [form, setForm] = useState<TestForm>({
    eventType: "file_read",
    target: "",
    content: "",
    extra: "",
    sessionId: "",
    agentId: "",
  });

  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<PolicyEvalResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!form.target.trim()) return;

    setIsRunning(true);
    setResult(null);
    setError(null);

    try {
      const request = buildPolicyTestEvent({
        eventType: form.eventType,
        target: form.target,
        content: form.content || undefined,
        extra: form.extra || undefined,
        sessionId: form.sessionId || undefined,
        agentId: form.agentId || undefined,
      });
      const client = new HushdClient(daemonUrl);
      const response = await client.eval(request);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Eval failed");
    } finally {
      setIsRunning(false);
    }
  };

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full text-sdr-text-secondary">
        Not connected to daemon
      </div>
    );
  }

  return (
    <div className="flex h-full">
      <GlassPanel className="w-1/2 border-r border-sdr-border flex flex-col">
        <GlassHeader className="px-4 py-3">
          <h1 className="text-lg font-semibold text-sdr-text-primary">Policy Tester</h1>
          <p className="text-sm text-sdr-text-muted mt-0.5">
            Simulate canonical <code>PolicyEvent</code> checks via <code>/api/v1/eval</code>
          </p>
        </GlassHeader>

        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-sdr-text-primary mb-2">
              Event Type
            </label>
            <div className="grid grid-cols-2 gap-2">
              {POLICY_TEST_EVENT_TYPES.map((eventType) => (
                <ActionTypeButton
                  key={eventType}
                  value={eventType}
                  selected={form.eventType === eventType}
                  onClick={() => setForm({ ...form, eventType })}
                />
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-sdr-text-primary mb-2">Target</label>
            <GlowInput
              type="text"
              value={form.target}
              onChange={(event) => setForm({ ...form, target: event.target.value })}
              placeholder={getPolicyTestTargetPlaceholder(form.eventType)}
              className="w-full font-mono text-sm"
            />
          </div>

          {(form.eventType === "file_write" || form.eventType === "patch_apply") && (
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Content
              </label>
              <textarea
                value={form.content}
                onChange={(event) => setForm({ ...form, content: event.target.value })}
                placeholder={form.eventType === "patch_apply" ? "--- patch ---" : "content"}
                rows={6}
                className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm resize-none"
              />
            </div>
          )}

          {(form.eventType === "tool_call" || form.eventType === "secret_access") && (
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                {form.eventType === "tool_call" ? "JSON Parameters" : "Scope"}
              </label>
              <textarea
                value={form.extra}
                onChange={(event) => setForm({ ...form, extra: event.target.value })}
                placeholder={form.eventType === "tool_call" ? '{"path":"/tmp"}' : "runtime"}
                rows={4}
                className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm resize-none"
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-2">
            <GlowInput
              type="text"
              value={form.sessionId}
              onChange={(event) => setForm({ ...form, sessionId: event.target.value })}
              placeholder="sessionId (optional)"
              className="w-full font-mono text-sm"
            />
            <GlowInput
              type="text"
              value={form.agentId}
              onChange={(event) => setForm({ ...form, agentId: event.target.value })}
              placeholder="agentId (optional)"
              className="w-full font-mono text-sm"
            />
          </div>

          <GlowButton type="submit" disabled={isRunning || !form.target.trim()} className="w-full">
            {isRunning ? "Running Eval..." : "Run Eval"}
          </GlowButton>
        </form>
      </GlassPanel>

      <GlassPanel className="w-1/2 flex flex-col">
        <GlassHeader className="px-4 py-3">
          <h2 className="font-medium text-sdr-text-primary">Decision</h2>
        </GlassHeader>

        <div className="flex-1 overflow-y-auto p-4">
          {isRunning && (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              <div className="animate-spin w-6 h-6 border-2 border-sdr-accent-blue border-t-transparent rounded-full" />
            </div>
          )}

          {error && (
            <div className="p-4 bg-sdr-accent-red/10 border border-sdr-accent-red/30 rounded-lg">
              <p className="text-sdr-accent-red font-medium">Error</p>
              <p className="text-sm text-sdr-text-secondary mt-1">{error}</p>
            </div>
          )}

          {result && <ResultDisplay result={result} />}

          {!isRunning && !error && !result && (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              Run an eval to see structured results
            </div>
          )}
        </div>
      </GlassPanel>
    </div>
  );
}

function ActionTypeButton({
  value,
  selected,
  onClick,
}: {
  value: PolicyTestEventType;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "px-3 py-2 text-sm font-medium rounded-md border transition-colors",
        selected
          ? "bg-sdr-accent-blue/20 border-sdr-accent-blue text-sdr-accent-blue"
          : "bg-sdr-bg-tertiary border-sdr-border text-sdr-text-secondary hover:text-sdr-text-primary",
      )}
    >
      {value}
    </button>
  );
}

function ResultDisplay({ result }: { result: PolicyEvalResponse }) {
  const decision = result.decision;
  const verdict = decision.denied
    ? "DENY"
    : decision.warn
      ? "WARN"
      : decision.allowed
        ? "ALLOW"
        : "UNKNOWN";

  return (
    <div className="space-y-4">
      <div
        className={clsx(
          "p-4 rounded-lg border",
          verdict === "ALLOW"
            ? "bg-verdict-allowed/10 border-verdict-allowed/30"
            : verdict === "WARN"
              ? "bg-severity-warning/10 border-severity-warning/30"
              : verdict === "DENY"
                ? "bg-verdict-blocked/10 border-verdict-blocked/30"
                : "bg-sdr-bg-tertiary border-sdr-border",
        )}
      >
        <div className="flex items-center gap-2">
          <Badge
            variant={
              verdict === "ALLOW" ? "default" : verdict === "DENY" ? "destructive" : "outline"
            }
            className="text-lg font-semibold"
          >
            {verdict}
          </Badge>
          <span className="text-xs text-sdr-text-muted">guard: {decision.guard ?? "-"}</span>
        </div>
      </div>

      <div className="space-y-3">
        <Field label="Severity" value={decision.severity ?? "-"} />
        <Field label="Reason" value={decision.reason ?? decision.message ?? "-"} />
      </div>

      <div>
        <span className="text-xs text-sdr-text-muted uppercase tracking-wide">JSON</span>
        <pre className="text-xs text-sdr-text-secondary mt-1 bg-sdr-bg-tertiary p-2 rounded overflow-x-auto">
          {JSON.stringify(result, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-xs text-sdr-text-muted uppercase tracking-wide">{label}</span>
      <p className="text-sm text-sdr-text-primary mt-1">{value}</p>
    </div>
  );
}
