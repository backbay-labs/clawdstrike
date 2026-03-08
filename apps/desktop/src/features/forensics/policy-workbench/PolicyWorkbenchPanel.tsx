import {
  Badge,
  GlassHeader,
  GlassPanel,
  GlowButton,
  GlowInput,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@backbay/glia/primitives";
import { clsx } from "clsx";
import * as React from "react";

import {
  PolicyWorkbenchClient,
  PolicyWorkbenchClientError,
} from "@/services/policyWorkbenchClient";
import { POLICY_WORKBENCH_DIRTY_EVENT, type PolicyWorkbenchDirtyEventDetail } from "./events";
import {
  buildPolicyTestEvent,
  getPolicyTestTargetPlaceholder,
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

type WorkbenchTab = "editor" | "test";

interface PolicyWorkbenchPanelProps {
  daemonUrl: string;
  connected: boolean;
  variant?: "sidebar" | "shelf";
  className?: string;
  runtimeSummary?: {
    connected: boolean;
    statusLabel: string;
    statusDetail?: string;
    nodes: number;
    presence: number;
    approvals: number;
  };
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

export function PolicyWorkbenchPanel({
  daemonUrl,
  connected,
  variant = "sidebar",
  className,
  runtimeSummary,
}: PolicyWorkbenchPanelProps) {
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
  const loadSeq = React.useRef(0);
  const draftYamlRef = React.useRef(state.draftYaml);
  const hasAutoLoadedRef = React.useRef(false);
  const wasConnectedRef = React.useRef(connected);
  const previousDaemonUrlRef = React.useRef(daemonUrl);

  const dirty = isPolicyDraftDirty(state);

  React.useEffect(() => {
    draftYamlRef.current = state.draftYaml;
  }, [state.draftYaml]);

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

  const readPolicy = React.useCallback(
    async (options?: { forceApply?: boolean }) => {
      if (!connected) return;
      const forceApply = Boolean(options?.forceApply);
      const seq = ++loadSeq.current;
      const draftAtRequest = draftYamlRef.current;
      dispatch({ type: "load_start" });
      try {
        const loaded = await client.loadPolicy();
        if (seq !== loadSeq.current) return;
        if (!forceApply && draftYamlRef.current !== draftAtRequest) {
          setCopyStatus("Reload skipped: local draft changed.");
          window.setTimeout(() => setCopyStatus(undefined), 2200);
          return;
        }
        dispatch({
          type: "load_success",
          yaml: loaded.yaml,
          hash: loaded.policy_hash,
          version: loaded.version,
        });
      } catch (err) {
        if (seq !== loadSeq.current) return;
        const message = err instanceof Error ? err.message : "Failed to load policy";
        const code = err instanceof PolicyWorkbenchClientError ? ` (${err.code})` : "";
        dispatch({ type: "load_error", message });
        setCopyStatus(`Load error${code}`);
        window.setTimeout(() => setCopyStatus(undefined), 2200);
      }
    },
    [client, connected],
  );

  const handleReload = React.useCallback(() => {
    if (dirty && !window.confirm("Discard unsaved policy edits and reload from daemon?")) {
      return;
    }
    void readPolicy({ forceApply: true });
  }, [dirty, readPolicy]);

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
    [client, connected],
  );

  const handleSave = React.useCallback(async () => {
    if (!connected) {
      dispatch({
        type: "save_error",
        message: "Daemon disconnected. Reconnect before saving.",
      });
      return;
    }

    const saveYaml = state.draftYaml;
    dispatch({ type: "save_start" });
    const saveValidationSeq = ++validationSeq.current;
    dispatch({ type: "validate_start" });

    let validation;
    try {
      validation = await client.validatePolicy(saveYaml);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Validation failed";
      if (saveValidationSeq === validationSeq.current) {
        dispatch({ type: "validate_error", message });
      }
      dispatch({ type: "save_error", message });
      return;
    }

    if (saveValidationSeq === validationSeq.current) {
      dispatch({
        type: "validate_success",
        valid: validation.valid,
        errors: validation.errors as ValidationIssue[],
        warnings: validation.warnings as ValidationIssue[],
      });
    }
    const normalizedVersion = validation.normalized_version ?? state.loadedVersion;

    if (!validation.valid) {
      dispatch({
        type: "save_error",
        message: "Policy is invalid. Fix validation errors before saving.",
      });
      return;
    }

    try {
      const saved = await client.savePolicy(saveYaml);
      if (!saved.success) {
        dispatch({ type: "save_error", message: saved.message || "Policy save failed" });
        return;
      }

      if (draftYamlRef.current !== saveYaml) {
        dispatch({
          type: "save_success_preserve_draft",
          loadedYaml: saveYaml,
          hash: saved.policy_hash,
          version: normalizedVersion,
        });
        return;
      }

      dispatch({
        type: "save_success",
        yaml: saveYaml,
        hash: saved.policy_hash,
        version: normalizedVersion,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Policy save failed";
      dispatch({ type: "save_error", message });
    }
  }, [client, connected, state.draftYaml, state.loadedVersion]);

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
    const wasConnected = wasConnectedRef.current;
    wasConnectedRef.current = connected;
    const daemonChanged = previousDaemonUrlRef.current !== daemonUrl;
    previousDaemonUrlRef.current = daemonUrl;

    if (!connected) return;

    const firstLoad = !hasAutoLoadedRef.current;
    const reconnected = wasConnected === false;
    if (!firstLoad && !reconnected && !daemonChanged) return;

    if (dirty) {
      if ((reconnected || daemonChanged) && hasAutoLoadedRef.current) {
        setCopyStatus(
          daemonChanged
            ? "Daemon changed. Unsaved edits preserved."
            : "Reconnected. Unsaved edits preserved.",
        );
        window.setTimeout(() => setCopyStatus(undefined), 2200);
      }
      return;
    }

    hasAutoLoadedRef.current = true;
    void readPolicy();
  }, [connected, daemonUrl, dirty, readPolicy]);

  React.useEffect(() => {
    if (!connected || !state.draftYaml || state.isSaving) return;
    const handle = window.setTimeout(() => {
      void validateYaml(state.draftYaml);
    }, 500);
    return () => window.clearTimeout(handle);
  }, [connected, state.draftYaml, state.isSaving, validateYaml]);

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
      }),
    );
  }, [dirty]);

  React.useEffect(
    () => () => {
      window.dispatchEvent(
        new CustomEvent<PolicyWorkbenchDirtyEventDetail>(POLICY_WORKBENCH_DIRTY_EVENT, {
          detail: { dirty: false },
        }),
      );
    },
    [],
  );

  return (
    <aside
      data-testid="policy-workbench-panel"
      className={clsx(
        variant === "sidebar"
          ? "w-[460px] border-l border-white/10 bg-black/45 backdrop-blur-md"
          : "policy-workbench-panel policy-workbench-panel--shelf h-full min-h-0 w-full overflow-hidden rounded-xl border border-[rgba(213,173,87,0.3)] bg-[linear-gradient(180deg,rgba(10,13,20,0.95)_0%,rgba(6,9,14,0.96)_100%)] shadow-[0_18px_40px_rgba(0,0,0,0.46)]",
        className,
      )}
    >
      <div className="flex h-full min-h-0 flex-col overflow-y-auto text-white/90">
        {variant === "sidebar" ? (
          <GlassHeader className="border-b border-white/10 px-4 py-3">
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
          </GlassHeader>
        ) : (
          <div className="policy-workbench-meta-row border-b border-[rgba(213,173,87,0.18)] px-3 py-2">
            <div className="flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2 text-[11px] font-mono">
                <span className="rounded-full border border-[rgba(213,173,87,0.35)] px-2 py-0.5 uppercase tracking-[0.12em] text-[rgba(230,214,170,0.95)]">
                  {runtimeSummary?.statusLabel ?? "OFFLINE"}
                </span>
                <span className="truncate text-[rgba(191,196,210,0.82)]">
                  {runtimeSummary?.statusDetail ?? "Telemetry unavailable"}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                <MetricChip label="nodes" value={runtimeSummary?.nodes ?? 0} />
                <MetricChip label="presence" value={runtimeSummary?.presence ?? 0} />
                <MetricChip label="approvals" value={runtimeSummary?.approvals ?? 0} />
                <MetricChip
                  label="schema"
                  valueLabel={state.loadedVersion ? `${state.loadedVersion}` : "unknown"}
                />
                {dirty && (
                  <Badge variant="destructive" className="text-[10px]">
                    Dirty
                  </Badge>
                )}
                <ValidationBadge status={state.validation.status} />
              </div>
            </div>
          </div>
        )}

        <Tabs
          value={tab}
          onValueChange={(next) => setTab((next as WorkbenchTab) ?? "editor")}
          className="flex min-h-0 flex-1 flex-col"
        >
          <TabsList className="policy-workbench-tabs-list mx-2 mt-2 grid w-auto grid-cols-2 bg-white/8 p-1">
            <TabsTrigger data-testid="policy-workbench-tab-editor" value="editor">
              Editor
            </TabsTrigger>
            <TabsTrigger data-testid="policy-workbench-tab-test" value="test">
              Test
            </TabsTrigger>
          </TabsList>

          <TabsContent
            value="editor"
            className="mt-0 flex min-h-0 flex-1 flex-col overflow-y-auto pb-2"
          >
            <GlassPanel
              variant="flush"
              className="mx-2 mt-2 rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
            >
              {variant === "sidebar" ? (
                <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
                  Editor Actions
                </GlassHeader>
              ) : null}
              <div
                className={clsx(
                  "flex flex-wrap items-center gap-2 px-3 py-2",
                  variant === "shelf" ? "border-b border-white/10" : undefined,
                )}
              >
                <GlowButton
                  data-testid="policy-editor-reload"
                  variant="secondary"
                  onClick={handleReload}
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
                  disabled={!connected || !dirty || state.isSaving}
                  onClick={() => void handleSave()}
                >
                  {state.isSaving ? "Saving..." : "Save"}
                </GlowButton>
                {copyStatus && <span className="text-xs text-white/60">{copyStatus}</span>}
              </div>
            </GlassPanel>

            <div className="px-2 py-2">
              <YamlEditor
                value={state.draftYaml}
                onChange={(yaml) => dispatch({ type: "edit", yaml })}
                disabled={state.isSaving}
              />
            </div>

            <GlassPanel
              variant="flush"
              className="mx-2 mb-2 overflow-y-auto rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
            >
              <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
                Validation
              </GlassHeader>
              <div className="px-3 py-2 text-xs">
                {state.loadError && <p className="text-red-300">{state.loadError}</p>}
                {state.saveError && <p className="text-red-300">{state.saveError}</p>}
                {state.validation.status === "invalid" && (
                  <>
                    <p className="mb-1 text-amber-300">Validation errors</p>
                    {state.validation.errors.map((error, index) => (
                      <p
                        key={`${error.code}-${error.path}-${index}`}
                        className="font-mono text-[11px] text-white/75"
                      >
                        {error.path} [{error.code}] {error.message}
                      </p>
                    ))}
                  </>
                )}
                {state.validation.status === "valid" && (
                  <p className="text-emerald-300">Policy is valid.</p>
                )}
                {(state.validation.status === "valid" || state.validation.status === "invalid") &&
                  state.validation.warnings.length > 0 && (
                    <>
                      <p className="mb-1 mt-2 text-amber-200">Validation warnings</p>
                      {state.validation.warnings.map((warning, index) => (
                        <p
                          key={`${warning.code}-${warning.path}-${index}`}
                          className="font-mono text-[11px] text-white/70"
                        >
                          {warning.path} [{warning.code}] {warning.message}
                        </p>
                      ))}
                    </>
                  )}
                {state.validation.status === "error" && state.validation.message && (
                  <p className="text-red-300">{state.validation.message}</p>
                )}
              </div>
            </GlassPanel>
          </TabsContent>

          <TabsContent
            value="test"
            className="mt-0 flex min-h-0 flex-1 flex-col overflow-y-auto pb-2"
          >
            <GlassPanel
              variant="flush"
              className="mx-2 mt-2 rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
            >
              {variant === "sidebar" ? (
                <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
                  Test Input
                </GlassHeader>
              ) : null}
              <div className="space-y-2 px-3 py-3">
                <div>
                  <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">
                    Event Type
                  </label>
                  <select
                    data-testid="policy-test-event-type"
                    value={testForm.eventType}
                    onChange={(event) =>
                      setTestForm((prev) => ({
                        ...prev,
                        eventType: event.target.value as PolicyTestEventType,
                      }))
                    }
                    className="w-full rounded border border-[rgba(213,173,87,0.32)] bg-[rgba(6,9,14,0.82)] px-2 py-1 text-xs text-white/90"
                  >
                    {POLICY_TEST_EVENT_TYPES.map((eventType) => (
                      <option key={eventType} value={eventType}>
                        {eventType}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">
                    Target / Resource
                  </label>
                  <GlowInput
                    data-testid="policy-test-target"
                    value={testForm.target}
                    onChange={(event) =>
                      setTestForm((prev) => ({ ...prev, target: event.target.value }))
                    }
                    placeholder={getPolicyTestTargetPlaceholder(testForm.eventType)}
                    className="w-full font-mono text-xs"
                  />
                </div>

                {(testForm.eventType === "file_write" || testForm.eventType === "patch_apply") && (
                  <div>
                    <label className="mb-1 block text-[11px] uppercase tracking-wide text-white/55">
                      Content
                    </label>
                    <textarea
                      value={testForm.content}
                      onChange={(event) =>
                        setTestForm((prev) => ({ ...prev, content: event.target.value }))
                      }
                      className="h-20 w-full resize-none rounded-md border border-white/12 bg-white/6 px-3 py-2 font-mono text-xs text-sdr-text-primary placeholder:text-sdr-text-muted focus:outline-none focus:border-sdr-accent-blue"
                      placeholder={
                        testForm.eventType === "patch_apply" ? "--- patch diff ---" : "file content"
                      }
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
                      onChange={(event) =>
                        setTestForm((prev) => ({ ...prev, extra: event.target.value }))
                      }
                      className="h-16 w-full resize-none rounded-md border border-white/12 bg-white/6 px-3 py-2 font-mono text-xs text-sdr-text-primary placeholder:text-sdr-text-muted focus:outline-none focus:border-sdr-accent-blue"
                      placeholder={
                        testForm.eventType === "tool_call" ? '{"path":"/tmp"}' : "runtime"
                      }
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <GlowInput
                    value={testForm.sessionId}
                    onChange={(event) =>
                      setTestForm((prev) => ({ ...prev, sessionId: event.target.value }))
                    }
                    placeholder="sessionId (optional)"
                    className="font-mono text-xs"
                  />
                  <GlowInput
                    value={testForm.agentId}
                    onChange={(event) =>
                      setTestForm((prev) => ({ ...prev, agentId: event.target.value }))
                    }
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
            </GlassPanel>

            <div className="min-h-[220px] flex-1 overflow-y-auto px-2 py-2">
              <GlassPanel
                variant="flush"
                className="rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
              >
                <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
                  Decision Output
                </GlassHeader>
                <div className="px-3 py-3">
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
                    <p className="text-xs text-white/50">
                      Run a policy test to see structured decision output.
                    </p>
                  )}
                </div>
              </GlassPanel>

              <GlassPanel
                variant="flush"
                className="mt-2 rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
              >
                <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
                  History
                </GlassHeader>
                <div className="px-3 py-3">
                  {history.length === 0 ? (
                    <p className="text-xs text-white/45">No test history yet.</p>
                  ) : (
                    <ul data-testid="policy-test-history" className="space-y-2">
                      {history.map((entry) => {
                        const decision =
                          (entry.response.decision as Record<string, unknown> | undefined) ?? {};
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
                              <span className="font-mono text-white/65">
                                {new Date(entry.at).toLocaleTimeString()}
                              </span>
                              <span
                                className={clsx(
                                  "rounded px-1.5 py-0.5 uppercase tracking-wide",
                                  verdict === "allow" && "bg-emerald-500/20 text-emerald-300",
                                  verdict === "warn" && "bg-amber-500/20 text-amber-300",
                                  verdict === "deny" && "bg-red-500/20 text-red-300",
                                  verdict === "unknown" && "bg-white/15 text-white/65",
                                )}
                              >
                                {verdict}
                              </span>
                            </div>
                            <p className="truncate font-mono text-white/65">
                              {String((entry.request.eventType as string | undefined) ?? "event")} ·{" "}
                              {String(
                                ((entry.request.data as Record<string, unknown> | undefined)
                                  ?.path as string | undefined) ??
                                  ((entry.request.data as Record<string, unknown> | undefined)
                                    ?.host as string | undefined) ??
                                  ((entry.request.data as Record<string, unknown> | undefined)
                                    ?.toolName as string | undefined) ??
                                  "-",
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
                              {entry.error && (
                                <span className="text-[11px] text-red-300">{entry.error}</span>
                              )}
                            </div>
                            <details className="mt-2">
                              <summary className="cursor-pointer text-[11px] uppercase tracking-wide text-white/60">
                                Details
                              </summary>
                              <div className="mt-2 space-y-2">
                                <InlineCodeBlock
                                  code={JSON.stringify(entry.request, null, 2)}
                                  title="request"
                                  maxHeight={140}
                                />
                                <InlineCodeBlock
                                  code={JSON.stringify(entry.response, null, 2)}
                                  title="response"
                                  maxHeight={160}
                                />
                              </div>
                            </details>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </GlassPanel>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </aside>
  );
}

function MetricChip({
  label,
  value,
  valueLabel,
}: {
  label: string;
  value?: number;
  valueLabel?: string;
}) {
  const text = typeof valueLabel === "string" ? valueLabel : `${value ?? 0}`;
  return (
    <span className="rounded-full border border-[rgba(213,173,87,0.25)] bg-[rgba(10,14,21,0.72)] px-2 py-0.5 text-[10px] font-mono text-[rgba(191,196,210,0.86)]">
      {label} {text}
    </span>
  );
}

function ValidationBadge({
  status,
}: {
  status: "idle" | "running" | "valid" | "invalid" | "error";
}) {
  if (status === "running") return <Badge variant="outline">Validating</Badge>;
  if (status === "valid") return <Badge variant="default">Valid</Badge>;
  if (status === "invalid") return <Badge variant="destructive">Invalid</Badge>;
  if (status === "error") return <Badge variant="destructive">Validation Error</Badge>;
  return <Badge variant="outline">Idle</Badge>;
}

function ResultCard({ result, onCopy }: { result: Record<string, unknown>; onCopy: () => void }) {
  const decision = (result.decision as Record<string, unknown> | undefined) ?? {};
  const verdict = decision.denied
    ? "DENY"
    : decision.warn
      ? "WARN"
      : decision.allowed
        ? "ALLOW"
        : "UNKNOWN";
  const rawResultJson = JSON.stringify(result, null, 2);

  return (
    <div className="rounded border border-white/12 bg-black/20 p-3 text-xs">
      <div className="mb-2 flex items-center justify-between">
        <span
          className={clsx(
            "rounded px-2 py-1 text-[11px] font-semibold tracking-wide",
            verdict === "ALLOW" && "bg-emerald-500/20 text-emerald-300",
            verdict === "WARN" && "bg-amber-500/20 text-amber-300",
            verdict === "DENY" && "bg-red-500/20 text-red-300",
            verdict === "UNKNOWN" && "bg-white/15 text-white/70",
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
      <InlineCodeBlock
        code={rawResultJson}
        title="policy_eval.response"
        maxHeight={224}
        className="mt-3"
      />
    </div>
  );
}

function YamlEditor({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex min-h-[420px] flex-col gap-2">
      <GlassPanel
        variant="flush"
        className="flex min-h-[220px] flex-1 flex-col overflow-hidden rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
      >
        <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
          Editable YAML
        </GlassHeader>
        <div className="min-h-0 flex-1 p-2">
          <textarea
            data-testid="policy-editor-textarea"
            value={value}
            onChange={(event) => onChange(event.target.value)}
            spellCheck={false}
            readOnly={disabled}
            aria-readonly={disabled ? true : undefined}
            className="h-full min-h-[160px] w-full resize-none rounded border border-white/15 bg-black/25 p-3 font-mono text-xs leading-5 text-white/90 outline-none focus:border-white/30"
          />
        </div>
      </GlassPanel>

      <GlassPanel
        variant="flush"
        className="flex min-h-[180px] flex-1 flex-col overflow-hidden rounded-lg border border-[rgba(213,173,87,0.24)] bg-[rgba(8,12,19,0.82)]"
      >
        <GlassHeader className="border-b border-white/10 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-white/60">
          Read-only Preview
        </GlassHeader>
        <div className="min-h-0 flex-1 p-2">
          <InlineCodeBlock
            code={value}
            title="policy.yaml"
            maxHeight={420}
            className="h-full"
          />
        </div>
      </GlassPanel>
    </div>
  );
}

function InlineCodeBlock({
  code,
  title,
  maxHeight,
  className,
}: {
  code: string;
  title?: string;
  maxHeight?: number;
  className?: string;
}) {
  return (
    <div
      className={clsx(
        "overflow-hidden rounded border border-white/10 bg-black/25 text-xs text-white/80",
        className,
      )}
    >
      {title ? (
        <div className="border-b border-white/10 px-3 py-2 font-mono uppercase tracking-[0.14em] text-white/45">
          {title}
        </div>
      ) : null}
      <pre
        className="overflow-auto p-3 font-mono leading-5"
        style={{ maxHeight: typeof maxHeight === "number" ? `${maxHeight}px` : undefined }}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}
