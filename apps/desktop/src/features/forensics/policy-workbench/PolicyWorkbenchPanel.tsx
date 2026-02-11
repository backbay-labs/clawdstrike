import * as React from "react";
import { clsx } from "clsx";
import { Badge, GlowButton, GlowInput } from "@backbay/glia/primitives";

import {
  PolicyWorkbenchClient,
  PolicyWorkbenchClientError,
} from "@/services/policyWorkbenchClient";
import {
  buildPolicyTestEvent,
  POLICY_TEST_EVENT_TYPES,
  type PolicyTestEventType,
  type PolicyTestForm,
} from "./mapping";
import {
  initialPolicyWorkbenchState,
  isPolicyDraftDirty,
  policyWorkbenchReducer,
  type ValidationIssue,
} from "./state";
import {
  POLICY_WORKBENCH_DIRTY_EVENT,
  type PolicyWorkbenchDirtyEventDetail,
} from "./events";

type WorkbenchTab = "editor" | "test";

interface PolicyWorkbenchPanelProps {
  daemonUrl: string;
  connected: boolean;
  className?: string;
}

interface PolicyTestHistoryItem {
  id: string;
  at: string;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
  error?: string;
}

const DEFAULT_TEST_FORM: PolicyTestForm = {
  eventType: "file_read",
  target: "",
  content: "",
  extra: "",
  sessionId: "",
  agentId: "",
};

export function PolicyWorkbenchPanel({ daemonUrl, connected, className }: PolicyWorkbenchPanelProps) {
  const client = React.useMemo(() => new PolicyWorkbenchClient(daemonUrl), [daemonUrl]);
  const [tab, setTab] = React.useState<WorkbenchTab>("editor");
  const [state, dispatch] = React.useReducer(policyWorkbenchReducer, initialPolicyWorkbenchState);
  const [testForm, setTestForm] = React.useState<PolicyTestForm>(DEFAULT_TEST_FORM);
  const [isRunningTest, setIsRunningTest] = React.useState(false);
  const [testError, setTestError] = React.useState<string>();
  const [testResult, setTestResult] = React.useState<Record<string, unknown>>();
  const [history, setHistory] = React.useState<PolicyTestHistoryItem[]>([]);
  const [copyStatus, setCopyStatus] = React.useState<string>();
  const validationSeq = React.useRef(0);

  const dirty = isPolicyDraftDirty(state);

  const copyJson = React.useCallback(async (value: unknown, label: string) => {
    const text = JSON.stringify(value, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus(`${label} copied`);
      window.setTimeout(() => setCopyStatus(undefined), 1800);
    } catch {
      setCopyStatus("Copy failed");
      window.setTimeout(() => setCopyStatus(undefined), 1800);
    }
  }, []);

  const readPolicy = React.useCallback(async () => {
    if (!connected) return;
    dispatch({ type: "load_start" });
    try {
      const loaded = await client.loadPolicy();
      dispatch({
        type: "load_success",
        yaml: loaded.yaml,
        hash: loaded.policy_hash,
        version: loaded.version,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load policy";
      const code =
        err instanceof PolicyWorkbenchClientError ? ` (${err.code})` : "";
      dispatch({ type: "load_error", message });
      setCopyStatus(`Load error${code}`);
      window.setTimeout(() => setCopyStatus(undefined), 2200);
    }
  }, [client, connected]);

  const validateYaml = React.useCallback(
    async (yaml: string) => {
      if (!connected) return;
      const seq = ++validationSeq.current;
      dispatch({ type: "validate_start" });
      try {
        const result = await client.validatePolicy(yaml);
        if (seq !== validationSeq.current) return;
        dispatch({
          type: "validate_success",
          valid: result.valid,
          errors: result.errors as ValidationIssue[],
          warnings: result.warnings as ValidationIssue[],
        });
      } catch (err) {
        if (seq !== validationSeq.current) return;
        const message = err instanceof Error ? err.message : "Validation failed";
        dispatch({ type: "validate_error", message });
      }
    },
    [client, connected]
  );

  const handleSave = React.useCallback(async () => {
    dispatch({ type: "save_start" });
    try {
      const validation = await client.validatePolicy(state.draftYaml);
      dispatch({
        type: "validate_success",
        valid: validation.valid,
        errors: validation.errors as ValidationIssue[],
        warnings: validation.warnings as ValidationIssue[],
      });

      if (!validation.valid) {
        dispatch({ type: "save_error", message: "Policy is invalid. Fix validation errors before saving." });
        return;
      }

      const saved = await client.savePolicy(state.draftYaml);
      if (!saved.success) {
        dispatch({ type: "save_error", message: saved.message || "Policy save failed" });
        return;
      }

      dispatch({
        type: "save_success",
        yaml: state.draftYaml,
        hash: saved.policy_hash,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Policy save failed";
      dispatch({ type: "save_error", message });
    }
  }, [client, state.draftYaml]);

  const runPolicyTest = React.useCallback(async () => {
    setIsRunningTest(true);
    setTestError(undefined);

    try {
      const request = buildPolicyTestEvent(testForm);
      const response = await client.evalPolicyEvent(request);
      setTestResult(response as unknown as Record<string, unknown>);
      setHistory((prev) => {
        const next: PolicyTestHistoryItem = {
          id: `test-${Date.now()}`,
          at: new Date().toISOString(),
          request,
          response: response as unknown as Record<string, unknown>,
        };
        return [next, ...prev].slice(0, 100);
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : "Policy eval failed";
      const failClosed = {
        version: 1,
        command: "policy_eval",
        decision: {
          allowed: false,
          denied: true,
          warn: false,
          guard: "policy_eval_error",
          severity: "critical",
          message: "Evaluation failed (fail-closed)",
          reason,
        },
        report: {
          overall: {
            allowed: false,
            guard: "policy_eval_error",
            severity: "critical",
            message: reason,
            details: { error: reason },
          },
          per_guard: [],
        },
      };
      setTestError(reason);
      setTestResult(failClosed);
      setHistory((prev) => {
        const request = (() => {
          try {
            return buildPolicyTestEvent(testForm);
          } catch {
            return {};
          }
        })();
        const next: PolicyTestHistoryItem = {
          id: `test-${Date.now()}`,
          at: new Date().toISOString(),
          request,
          response: failClosed,
          error: reason,
        };
        return [next, ...prev].slice(0, 100);
      });
    } finally {
      setIsRunningTest(false);
    }
  }, [client, testForm]);

  React.useEffect(() => {
    void readPolicy();
  }, [readPolicy]);

  React.useEffect(() => {
    if (!connected || !state.draftYaml) return;
    const handle = window.setTimeout(() => {
      void validateYaml(state.draftYaml);
    }, 500);
    return () => window.clearTimeout(handle);
  }, [connected, state.draftYaml, validateYaml]);

  React.useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [dirty]);

  React.useEffect(() => {
    window.dispatchEvent(
      new CustomEvent<PolicyWorkbenchDirtyEventDetail>(POLICY_WORKBENCH_DIRTY_EVENT, {
        detail: { dirty },
      })
    );
  }, [dirty]);

  return (
    <aside
      data-testid="policy-workbench-panel"
      className={clsx(
        "w-[460px] border-l border-white/10 bg-black/45 backdrop-blur-md",
        className
      )}
    >
      <div className="flex h-full flex-col text-white/90">
        <header className="border-b border-white/10 px-4 py-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold tracking-wide">Policy Workbench</h2>
            <div className="flex items-center gap-2">
              {dirty && (
                <Badge variant="destructive" className="text-[11px]">
                  Dirty
                </Badge>
              )}
              <ValidationBadge status={state.validation.status} />
            </div>
          </div>
          <p className="mt-1 text-xs text-white/50">
            {state.loadedVersion ? `Schema ${state.loadedVersion}` : "Policy schema unknown"}
            {state.loadedHash ? ` · ${state.loadedHash.slice(0, 12)}…` : ""}
          </p>
        </header>

        <div className="flex border-b border-white/10 px-2 py-2">
          <TabButton
            data-testid="policy-workbench-tab-editor"
            active={tab === "editor"}
            onClick={() => setTab("editor")}
          >
            Editor
          </TabButton>
          <TabButton
            data-testid="policy-workbench-tab-test"
            active={tab === "test"}
            onClick={() => setTab("test")}
          >
            Test
          </TabButton>
        </div>

        {tab === "editor" ? (
          <section className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center gap-2 border-b border-white/10 px-3 py-2">
              <GlowButton
                data-testid="policy-editor-reload"
                variant="secondary"
                onClick={() => void readPolicy()}
              >
                Reload
              </GlowButton>
              <GlowButton
                data-testid="policy-editor-revert"
                variant="secondary"
                disabled={!dirty}
                onClick={() => dispatch({ type: "revert" })}
              >
                Revert
              </GlowButton>
              <GlowButton
                data-testid="policy-editor-save"
                disabled={!dirty || state.isSaving}
                onClick={() => void handleSave()}
              >
                {state.isSaving ? "Saving..." : "Save"}
              </GlowButton>
              {copyStatus && <span className="text-xs text-white/60">{copyStatus}</span>}
            </div>

            <YamlEditor
              value={state.draftYaml}
              onChange={(yaml) => dispatch({ type: "edit", yaml })}
            />

            <div className="max-h-44 overflow-y-auto border-t border-white/10 px-3 py-2 text-xs">
              {state.loadError && <p className="text-red-300">{state.loadError}</p>}
              {state.saveError && <p className="text-red-300">{state.saveError}</p>}
              {state.validation.status === "invalid" && (
                <>
                  <p className="mb-1 text-amber-300">Validation errors</p>
                  {state.validation.errors.map((error, index) => (
                    <p key={`${error.code}-${error.path}-${index}`} className="font-mono text-[11px] text-white/75">
                      {error.path} [{error.code}] {error.message}
                    </p>
                  ))}
                </>
              )}
              {state.validation.status === "valid" && (
                <p className="text-emerald-300">Policy is valid.</p>
              )}
              {state.validation.status === "error" && state.validation.message && (
                <p className="text-red-300">{state.validation.message}</p>
              )}
            </div>
          </section>
        ) : (
          <section className="flex min-h-0 flex-1 flex-col">
            <div className="space-y-2 border-b border-white/10 px-3 py-3">
              <div>
                <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">Event Type</label>
                <select
                  data-testid="policy-test-event-type"
                  value={testForm.eventType}
                  onChange={(event) =>
                    setTestForm((prev) => ({
                      ...prev,
                      eventType: event.target.value as PolicyTestEventType,
                    }))
                  }
                  className="w-full rounded border border-white/20 bg-black/35 px-2 py-1 text-xs"
                >
                  {POLICY_TEST_EVENT_TYPES.map((eventType) => (
                    <option key={eventType} value={eventType}>
                      {eventType}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">Target / Resource</label>
                <GlowInput
                  data-testid="policy-test-target"
                  value={testForm.target}
                  onChange={(event) => setTestForm((prev) => ({ ...prev, target: event.target.value }))}
                  placeholder={targetPlaceholder(testForm.eventType)}
                  className="w-full font-mono text-xs"
                />
              </div>

              {(testForm.eventType === "file_write" || testForm.eventType === "patch_apply") && (
                <div>
                  <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">Content</label>
                  <textarea
                    value={testForm.content}
                    onChange={(event) => setTestForm((prev) => ({ ...prev, content: event.target.value }))}
                    className="h-20 w-full resize-none rounded border border-white/20 bg-black/35 px-2 py-1 font-mono text-xs"
                    placeholder={testForm.eventType === "patch_apply" ? "--- patch diff ---" : "file content"}
                  />
                </div>
              )}

              {(testForm.eventType === "tool_call" || testForm.eventType === "secret_access") && (
                <div>
                  <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">
                    {testForm.eventType === "tool_call" ? "Tool Parameters JSON" : "Secret Scope"}
                  </label>
                  <textarea
                    value={testForm.extra}
                    onChange={(event) => setTestForm((prev) => ({ ...prev, extra: event.target.value }))}
                    className="h-16 w-full resize-none rounded border border-white/20 bg-black/35 px-2 py-1 font-mono text-xs"
                    placeholder={testForm.eventType === "tool_call" ? "{\"path\":\"/tmp\"}" : "runtime"}
                  />
                </div>
              )}

              <div className="grid grid-cols-2 gap-2">
                <GlowInput
                  value={testForm.sessionId}
                  onChange={(event) => setTestForm((prev) => ({ ...prev, sessionId: event.target.value }))}
                  placeholder="sessionId (optional)"
                  className="font-mono text-xs"
                />
                <GlowInput
                  value={testForm.agentId}
                  onChange={(event) => setTestForm((prev) => ({ ...prev, agentId: event.target.value }))}
                  placeholder="agentId (optional)"
                  className="font-mono text-xs"
                />
              </div>

              <div className="flex items-center gap-2">
                <GlowButton
                  data-testid="policy-test-run"
                  disabled={isRunningTest || !testForm.target.trim()}
                  onClick={() => void runPolicyTest()}
                >
                  {isRunningTest ? "Running..." : "Run Test"}
                </GlowButton>
                {copyStatus && <span className="text-xs text-white/60">{copyStatus}</span>}
              </div>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
              {testError && (
                <div className="mb-3 rounded border border-red-500/40 bg-red-500/15 px-2 py-2 text-xs text-red-200">
                  {testError}
                </div>
              )}

              {testResult ? (
                <ResultCard
                  result={testResult}
                  onCopy={() => void copyJson(testResult, "Result JSON")}
                />
              ) : (
                <p className="text-xs text-white/50">Run a policy test to see structured decision output.</p>
              )}

              <div className="mt-4 border-t border-white/10 pt-3">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-white/55">History</h3>
                </div>
                {history.length === 0 ? (
                  <p className="text-xs text-white/45">No test history yet.</p>
                ) : (
                  <ul data-testid="policy-test-history" className="space-y-2">
                    {history.map((entry) => {
                      const decision = (entry.response.decision as Record<string, unknown> | undefined) ?? {};
                      const verdict = decision.denied
                        ? "deny"
                        : decision.warn
                          ? "warn"
                          : decision.allowed
                            ? "allow"
                            : "unknown";
                      return (
                        <li
                          key={entry.id}
                          data-testid="policy-test-history-item"
                          className="rounded border border-white/10 bg-black/20 p-2 text-xs"
                        >
                          <div className="mb-1 flex items-center justify-between gap-2">
                            <span className="font-mono text-white/65">{new Date(entry.at).toLocaleTimeString()}</span>
                            <span
                              className={clsx(
                                "rounded px-1.5 py-0.5 uppercase tracking-wide",
                                verdict === "allow" && "bg-emerald-500/20 text-emerald-300",
                                verdict === "warn" && "bg-amber-500/20 text-amber-300",
                                verdict === "deny" && "bg-red-500/20 text-red-300",
                                verdict === "unknown" && "bg-white/15 text-white/65"
                              )}
                            >
                              {verdict}
                            </span>
                          </div>
                          <p className="truncate font-mono text-white/65">
                            {String((entry.request.eventType as string | undefined) ?? "event")} ·{" "}
                            {String(
                              ((entry.request.data as Record<string, unknown> | undefined)?.path as string | undefined) ??
                                ((entry.request.data as Record<string, unknown> | undefined)?.host as string | undefined) ??
                                ((entry.request.data as Record<string, unknown> | undefined)?.toolName as string | undefined) ??
                                "-"
                            )}
                          </p>
                          <div className="mt-2 flex items-center gap-2">
                            <button
                              type="button"
                              className="rounded border border-white/15 px-2 py-1 text-[11px] text-white/75 hover:text-white"
                              onClick={() => void copyJson(entry.response, "History JSON")}
                            >
                              Copy JSON
                            </button>
                            {entry.error && <span className="text-[11px] text-red-300">{entry.error}</span>}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </div>
          </section>
        )}
      </div>
    </aside>
  );
}

function TabButton({
  "data-testid": dataTestId,
  active,
  onClick,
  children,
}: {
  "data-testid"?: string;
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      data-testid={dataTestId}
      className={clsx(
        "mx-1 flex-1 rounded px-3 py-1.5 text-xs font-semibold uppercase tracking-wide",
        active ? "bg-white/15 text-white" : "text-white/60 hover:text-white/85"
      )}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function ValidationBadge({ status }: { status: "idle" | "running" | "valid" | "invalid" | "error" }) {
  if (status === "running") return <Badge variant="outline">Validating</Badge>;
  if (status === "valid") return <Badge variant="default">Valid</Badge>;
  if (status === "invalid") return <Badge variant="destructive">Invalid</Badge>;
  if (status === "error") return <Badge variant="destructive">Validation Error</Badge>;
  return <Badge variant="outline">Idle</Badge>;
}

function targetPlaceholder(eventType: PolicyTestEventType): string {
  switch (eventType) {
    case "file_read":
    case "file_write":
      return "/workspace/file.txt";
    case "command_exec":
      return "git status --short";
    case "network_egress":
      return "https://api.openai.com/v1/models";
    case "tool_call":
      return "mcp__fs__read_file";
    case "patch_apply":
      return "/workspace/src/main.ts";
    case "secret_access":
      return "OPENAI_API_KEY";
    default:
      return "target";
  }
}

function ResultCard({
  result,
  onCopy,
}: {
  result: Record<string, unknown>;
  onCopy: () => void;
}) {
  const decision = (result.decision as Record<string, unknown> | undefined) ?? {};
  const verdict = decision.denied
    ? "DENY"
    : decision.warn
      ? "WARN"
      : decision.allowed
        ? "ALLOW"
        : "UNKNOWN";

  return (
    <div className="rounded border border-white/12 bg-black/20 p-3 text-xs">
      <div className="mb-2 flex items-center justify-between">
        <span
          className={clsx(
            "rounded px-2 py-1 text-[11px] font-semibold tracking-wide",
            verdict === "ALLOW" && "bg-emerald-500/20 text-emerald-300",
            verdict === "WARN" && "bg-amber-500/20 text-amber-300",
            verdict === "DENY" && "bg-red-500/20 text-red-300",
            verdict === "UNKNOWN" && "bg-white/15 text-white/70"
          )}
        >
          {verdict}
        </span>
        <button
          type="button"
          className="rounded border border-white/15 px-2 py-1 text-[11px] text-white/75 hover:text-white"
          onClick={onCopy}
        >
          Copy JSON
        </button>
      </div>

      <dl className="grid grid-cols-[88px_1fr] gap-x-2 gap-y-1">
        <dt className="text-white/55">Guard</dt>
        <dd className="font-mono">{String(decision.guard ?? "-")}</dd>
        <dt className="text-white/55">Reason</dt>
        <dd>{String(decision.reason ?? decision.message ?? "-")}</dd>
        <dt className="text-white/55">Severity</dt>
        <dd>{String(decision.severity ?? "-")}</dd>
      </dl>

      <pre className="mt-3 max-h-56 overflow-auto rounded border border-white/10 bg-black/30 p-2 text-[11px] text-white/75">
        {JSON.stringify(result, null, 2)}
      </pre>
    </div>
  );
}

function YamlEditor({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const highlighted = React.useMemo(() => highlightYaml(value), [value]);
  const preRef = React.useRef<HTMLPreElement | null>(null);

  return (
    <div className="relative min-h-0 flex-1">
      <pre
        ref={preRef}
        aria-hidden
        className="absolute inset-0 overflow-auto whitespace-pre p-3 font-mono text-xs leading-5 text-white/85"
        dangerouslySetInnerHTML={{ __html: highlighted.length > 0 ? highlighted : "&nbsp;" }}
      />
      <textarea
        data-testid="policy-editor-textarea"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={(event) => {
          if (!preRef.current) return;
          preRef.current.scrollTop = event.currentTarget.scrollTop;
          preRef.current.scrollLeft = event.currentTarget.scrollLeft;
        }}
        spellCheck={false}
        className="absolute inset-0 resize-none overflow-auto bg-transparent p-3 font-mono text-xs leading-5 text-transparent caret-white outline-none"
      />
    </div>
  );
}

function highlightYaml(input: string): string {
  const escaped = escapeHtml(input);
  return escaped
    .split("\n")
    .map((line) => {
      const commentIndex = line.indexOf("#");
      const head = commentIndex >= 0 ? line.slice(0, commentIndex) : line;
      const comment = commentIndex >= 0 ? line.slice(commentIndex) : "";

      const keyColored = head.replace(
        /^(\s*-\s*)?([A-Za-z0-9_."-]+)(\s*:)/,
        (_m, prefix, key, suffix) =>
          `${prefix ?? ""}<span style="color:#7dd3fc">${key}</span><span style="color:#d1d5db">${suffix}</span>`
      );

      const valueColored = keyColored
        .replace(/\b(true|false|null)\b/g, '<span style="color:#fcd34d">$1</span>')
        .replace(/(".*?")/g, '<span style="color:#86efac">$1</span>')
        .replace(/\b([0-9]+)\b/g, '<span style="color:#f9a8d4">$1</span>');

      const commentColored =
        comment.length > 0 ? `<span style="color:#94a3b8">${comment}</span>` : "";

      return valueColored + commentColored;
    })
    .join("\n");
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
