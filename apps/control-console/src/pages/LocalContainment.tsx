import { useEffect, useMemo, useState } from "react";
import {
  type CausalSliceAffectedIdentities,
  type CausalSliceAffectedTool,
  createResponseAction,
  type EndpointDecisionAction,
  fetchNetworkExtensionEgressPolicyProof,
  fetchResponseExecutions,
  type NetworkExtensionEgressPolicyProofResponse,
  type ResponseActionResponse,
  type ResponseExecutionRecord,
  type ResponseExecutionRollbackResponse,
  type ResponseExecutionsResponse,
  rollbackResponseExecution,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_TTL_SECONDS = 600;
const CONTAINMENT_ACTIONS: EndpointDecisionAction[] = [
  "suspend_process_tree",
  "restrict_egress",
  "collect_evidence",
  "quarantine_file",
  "disable_persistence",
  "revoke_grant",
];

export function LocalContainment(_props: { windowId?: string }) {
  const [rootNodeId, setRootNodeId] = useState("");
  const [processGuid, setProcessGuid] = useState("");
  const [action, setAction] = useState<EndpointDecisionAction>("suspend_process_tree");
  const [ttlSeconds, setTtlSeconds] = useState(DEFAULT_TTL_SECONDS);
  const [actorUser, setActorUser] = useState("local-operator");
  const [actorApprovalId, setActorApprovalId] = useState("");
  const [reason, setReason] = useState("");
  const [planResponse, setPlanResponse] = useState<ResponseActionResponse | null>(null);
  const [executions, setExecutions] = useState<ResponseExecutionsResponse | null>(null);
  const [egressProof, setEgressProof] = useState<NetworkExtensionEgressPolicyProofResponse | null>(
    null,
  );
  const [selectedExecutionId, setSelectedExecutionId] = useState("");
  const [rollback, setRollback] = useState<ResponseExecutionRollbackResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const receiptFamily = useMemo(() => receiptFamilyText(planResponse?.receipt), [planResponse]);
  const executionReceiptFamily = useMemo(
    () => receiptFamilyText(planResponse?.executionReceipt),
    [planResponse],
  );
  const networkExtensionReloadEvidence = useMemo(
    () => networkExtensionReloadEvidenceRows(planResponse?.executionReceipt),
    [planResponse],
  );
  const rollbackReceiptFamily = useMemo(() => receiptFamilyText(rollback?.receipt), [rollback]);
  const egressProofReceiptFamily = useMemo(
    () => receiptFamilyText(egressProof?.receipt),
    [egressProof],
  );
  const egressProofProviderIds = useMemo(
    () =>
      (egressProof?.sensorState?.providers ?? [])
        .map((provider) => provider.providerId)
        .filter(isString),
    [egressProof],
  );
  const egressProofReloadEvidence = useMemo(
    () => egressProofReloadEvidenceRows(egressProof),
    [egressProof],
  );
  const graphNodeLabels = useMemo(() => graphLabels(planResponse), [planResponse]);
  const affectedIdentityLabels = useMemo(
    () => attributionIdentityLabels(planResponse),
    [planResponse],
  );
  const affectedToolLabels = useMemo(() => attributionToolLabels(planResponse), [planResponse]);
  const selectedExecution = useMemo(
    () =>
      executions?.executions.find((record) => record.execution.executionId === selectedExecutionId),
    [executions, selectedExecutionId],
  );
  const exportPayload = useMemo(
    () => [planResponse, executions, rollback, egressProof].filter(Boolean),
    [planResponse, executions, rollback, egressProof],
  );

  useEffect(() => {
    void refreshExecutions();
  }, []);

  async function refreshExecutions() {
    setLoading("refresh");
    try {
      const response = await fetchResponseExecutions({ limit: 25 });
      setExecutions(response);
      setSelectedExecutionId(
        (current) => current || response.executions[0]?.execution.executionId || "",
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load response executions");
    } finally {
      setLoading(null);
    }
  }

  async function submitResponseAction(dryRun: boolean) {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }
    if (!dryRun && !actorApprovalId.trim()) {
      setError("Approval ID is required for live containment");
      return;
    }

    setLoading(dryRun ? "plan" : "execute");
    try {
      const response = await createResponseAction({
        ...target,
        action,
        ttlSeconds,
        dryRun,
        ...(reason.trim() && { reason: reason.trim() }),
        ...(!dryRun && {
          actor: {
            userId: actorUser.trim() || "local-operator",
            approvalId: actorApprovalId.trim(),
          },
        }),
      });
      setPlanResponse(response);
      setRollback(null);
      setError(null);
      if (!dryRun) await refreshExecutions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create response action");
    } finally {
      setLoading(null);
    }
  }

  async function runRollback() {
    const executionId = selectedExecutionId.trim();
    if (!executionId) {
      setError("Select a response execution before rollback");
      return;
    }

    setLoading("rollback");
    try {
      const response = await rollbackResponseExecution(executionId, {
        ...(reason.trim() && { reason: reason.trim() }),
      });
      setRollback(response);
      setError(null);
      await refreshExecutions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to roll back response execution");
    } finally {
      setLoading(null);
    }
  }

  async function fetchEgressProof() {
    setLoading("egress-proof");
    try {
      const executionId = selectedExecutionId.trim();
      const proof = await fetchNetworkExtensionEgressPolicyProof({
        refreshProviders: true,
        ...(executionId && { executionId }),
      });
      setEgressProof(proof);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch NetworkExtension egress proof",
      );
    } finally {
      setLoading(null);
    }
  }

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p
            className="font-mono"
            style={{
              color: "rgba(214,177,90,0.72)",
              fontSize: "0.68rem",
              letterSpacing: "0.16em",
              textTransform: "uppercase",
            }}
          >
            TTL-bound response and rollback
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Local Containment
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton
            variant="primary"
            onClick={() => submitResponseAction(true)}
            disabled={loading != null}
          >
            {loading === "plan" ? "Planning..." : "Dry-run Plan"}
          </GlassButton>
          <GlassButton onClick={() => submitResponseAction(false)} disabled={loading != null}>
            {loading === "execute" ? "Executing..." : "Execute Live"}
          </GlassButton>
          <GlassButton onClick={runRollback} disabled={loading != null || !selectedExecutionId}>
            {loading === "rollback" ? "Rolling back..." : "Rollback Selected"}
          </GlassButton>
          <GlassButton onClick={refreshExecutions} disabled={loading != null}>
            Refresh Executions
          </GlassButton>
          <GlassButton onClick={fetchEgressProof} disabled={loading != null}>
            {loading === "egress-proof" ? "Fetching Proof..." : "Fetch Egress Proof"}
          </GlassButton>
          <GlassButton
            onClick={() =>
              exportAsJSON(
                exportPayload,
                `local-containment-${safeFilenameId(selectedExecutionId)}`,
              )
            }
            disabled={exportPayload.length === 0}
          >
            Export JSON
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.76fr)_minmax(0,1.24fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Target" title="Containment Request" />
          <div className="mt-4 space-y-3">
            <TextField label="Root Node ID" value={rootNodeId} onChange={setRootNodeId} />
            <TextField label="Process GUID" value={processGuid} onChange={setProcessGuid} />
            <SelectField
              label="Action"
              value={action}
              options={CONTAINMENT_ACTIONS}
              onChange={(value) => setAction(value as EndpointDecisionAction)}
            />
            <NumberField
              label="TTL Seconds"
              value={ttlSeconds}
              min={1}
              max={86400}
              onChange={setTtlSeconds}
            />
            <TextField label="Actor User" value={actorUser} onChange={setActorUser} />
            <TextField
              label="Approval ID"
              value={actorApprovalId}
              onChange={setActorApprovalId}
            />
            <TextField label="Reason" value={reason} onChange={setReason} />
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric
              label="Plan"
              value={planResponse ? (planResponse.plan.dryRun ? "Dry run" : "Live") : "-"}
            />
            <Metric
              label="TTL"
              value={planResponse ? `TTL ${planResponse.plan.ttlSeconds}s` : "-"}
            />
            <Metric label="Receipt" value={receiptFamily ?? "-"} />
            <Metric label="Executions" value={numberText(executions?.execution_count)} />
          </div>

          <Plate className="p-4" goldEdge>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle
                eyebrow={planResponse ? "Response Plan" : "No plan"}
                title={planResponse?.plan.action ?? "Containment Plan"}
              />
              <StatusPill value={planResponse ? `TTL ${planResponse.plan.ttlSeconds}s` : "TTL -"} />
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
              <SmallFact label="Action ID" value={planResponse?.plan.actionId ?? "-"} mono />
              <SmallFact label="Graph Slice" value={planResponse?.plan.graphSliceId ?? "-"} mono />
              <SmallFact label="Rollback Ref" value={planResponse?.plan.rollbackRef ?? "-"} mono />
              <SmallFact label="Root" value={planResponse?.plan.rootNodeId ?? "-"} mono />
              <SmallFact label="Nodes" value={numberText(planResponse?.plan.nodeCount)} />
              <SmallFact label="Edges" value={numberText(planResponse?.plan.edgeCount)} />
              <SmallFact
                label="Identities"
                value={numberText(planResponse?.affectedIdentityCount)}
              />
              <SmallFact label="Tools" value={numberText(planResponse?.affectedToolCount)} />
            </div>
          </Plate>

          <Plate className="p-4">
            <PanelTitle
              eyebrow="Signed Execution"
              title={executionReceiptFamily ?? "No execution receipt"}
            />
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-4">
              {networkExtensionReloadEvidence.length === 0 ? (
                <EmptyState text="No NetworkExtension reload evidence" />
              ) : (
                networkExtensionReloadEvidence.map((item) => (
                  <SmallFact key={item.key} label={item.label} value={item.value} mono />
                ))
              )}
            </div>
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Plate className="p-4">
              <PanelTitle eyebrow="Graph Evidence" title="Affected Nodes" />
              <div className="mt-4 space-y-4">
                <div className="flex flex-wrap gap-2">
                  {graphNodeLabels.length === 0 ? (
                    <EmptyState text="No graph nodes loaded" />
                  ) : (
                    graphNodeLabels.map((label) => <Tag key={label}>{label}</Tag>)
                  )}
                </div>
                <LabelList
                  label="Responsible Identities"
                  items={affectedIdentityLabels}
                  emptyText="No identity context loaded"
                />
                <LabelList
                  label="Responsible Tools"
                  items={affectedToolLabels}
                  emptyText="No tool-call context loaded"
                />
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle
                eyebrow="Rollback"
                title={rollback?.rollback.rollbackId ?? "No rollback"}
              />
              <div className="mt-4 space-y-3">
                <SmallFact label="Receipt" value={rollbackReceiptFamily ?? "-"} />
                <SmallFact
                  label="Rollback Ref"
                  value={rollback?.rollback.rollbackRef ?? "-"}
                  mono
                />
                <div className="space-y-2">
                  {!rollback || rollback.rollback.effects.length === 0 ? (
                    <EmptyState text="No rollback effects" />
                  ) : (
                    rollback.rollback.effects.map((effect) => (
                      <EffectRow
                        key={effect.effectId ?? `${effect.effectType}:${effect.target}`}
                        effect={effect}
                      />
                    ))
                  )}
                </div>
              </div>
            </Plate>
          </div>

          <Plate className="p-4">
            <PanelTitle eyebrow="Recent Response Executions" title="Rollback Targets" />
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-[minmax(220px,0.74fr)_minmax(0,1.26fr)]">
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Execution
                </span>
                <select
                  aria-label="Execution"
                  value={selectedExecutionId}
                  onChange={(event) => setSelectedExecutionId(event.target.value)}
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
                >
                  {(executions?.executions ?? []).map((record) => (
                    <option key={record.execution.executionId} value={record.execution.executionId}>
                      {record.execution.executionId}
                    </option>
                  ))}
                </select>
              </label>
              <ExecutionSummary record={selectedExecution} />
            </div>
          </Plate>

          <Plate className="p-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle eyebrow="NetworkExtension" title="Egress Policy Proof" />
              <StatusPill
                value={egressProof ? `Ready ${boolText(egressProof.enforcementReady)}` : "Ready -"}
              />
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-4">
              <SmallFact label="Snapshot Hash" value={egressProof?.snapshotHash ?? "-"} mono />
              <SmallFact label="Receipt" value={egressProofReceiptFamily ?? "-"} />
              <SmallFact label="Flow Counters" value={boolText(egressProof?.flowCounterObserved)} />
              <SmallFact
                label="Observed Flows"
                value={numberText(egressProof?.observedFlowCount)}
              />
              <SmallFact label="Blocked Flows" value={numberText(egressProof?.blockedFlowCount)} />
              <SmallFact
                label="Remediation Requests"
                value={numberText(egressProof?.remediationRequestCount)}
              />
              <SmallFact
                label="Dropped Verdicts"
                value={numberText(egressProof?.droppedVerdictCount)}
              />
              <SmallFact
                label="Active Restrictions"
                value={numberText(egressProof?.activeRestrictionCount)}
              />
              {egressProofReloadEvidence.map((item) => (
                <SmallFact key={item.key} label={item.label} value={item.value} mono />
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {egressProofProviderIds.length === 0 ? (
                <EmptyState text="No provider state loaded" />
              ) : (
                egressProofProviderIds.map((providerId) => <Tag key={providerId}>{providerId}</Tag>)
              )}
            </div>
          </Plate>
        </section>
      </div>
    </div>
  );
}

function TextField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", minWidth: 0 }}
      />
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
      >
        {options.map((item) => (
          <option key={item} value={item}>
            {item}
          </option>
        ))}
      </select>
    </label>
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(clampNumber(event.target.value, min, max, value))}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)" }}
      />
    </label>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <Plate className="p-4">
      <p
        className="font-mono"
        style={{
          position: "relative",
          color: "rgba(154,167,181,0.58)",
          fontSize: "0.62rem",
          letterSpacing: "0.13em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className="font-display mt-2 truncate"
        style={{ position: "relative", color: "var(--text)", fontSize: "1.08rem", fontWeight: 700 }}
      >
        {value}
      </p>
    </Plate>
  );
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div style={{ position: "relative" }}>
      <p
        className="font-mono"
        style={{
          color: "rgba(214,177,90,0.66)",
          fontSize: "0.62rem",
          letterSpacing: "0.14em",
          textTransform: "uppercase",
        }}
      >
        {eyebrow}
      </p>
      <h2
        className="font-display mt-1"
        style={{ color: "var(--text)", fontSize: "1.05rem", fontWeight: 700 }}
      >
        {title}
      </h2>
    </div>
  );
}

function SmallFact({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className={mono ? "font-mono mt-1 break-all" : "font-body mt-1 truncate"}
        style={{ color: "var(--text)", fontSize: mono ? "0.72rem" : "0.88rem" }}
      >
        {value}
      </p>
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  return (
    <span
      className="font-mono rounded-md px-3 py-1"
      style={{
        border: "1px solid rgba(214,177,90,0.36)",
        background: "rgba(214,177,90,0.08)",
        color: "var(--gold)",
        fontSize: "0.72rem",
      }}
    >
      {value}
    </span>
  );
}

function ExecutionSummary({ record }: { record?: ResponseExecutionRecord }) {
  if (!record) return <EmptyState text="No response execution selected" />;
  const affectedIdentityLabels = attributionIdentityLabels(record);
  const affectedToolLabels = attributionToolLabels(record);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <SmallFact label="Execution ID" value={record.execution.executionId} mono />
        <SmallFact label="Action" value={record.execution.action ?? "-"} />
        <SmallFact label="Status" value={record.execution.status ?? "-"} />
        <SmallFact label="Expires" value={record.expiresAt ?? "-"} />
        <SmallFact label="Expired" value={String(record.expired)} />
        <SmallFact label="Effects" value={numberText(record.execution.effects?.length)} />
        <SmallFact label="Identities" value={numberText(record.affectedIdentityCount)} />
        <SmallFact label="Tools" value={numberText(record.affectedToolCount)} />
      </div>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <LabelList
          label="Responsible Identities"
          items={affectedIdentityLabels}
          emptyText="No identity context loaded"
        />
        <LabelList
          label="Responsible Tools"
          items={affectedToolLabels}
          emptyText="No tool-call context loaded"
        />
      </div>
    </div>
  );
}

function EffectRow({ effect }: { effect: { effectType?: string; target?: string } }) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <p className="font-body" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
        {effect.effectType ?? "-"}
      </p>
      <p
        className="font-mono mt-1 break-all"
        style={{ color: "rgba(154,167,181,0.58)", fontSize: "0.66rem" }}
      >
        {effect.target ?? "-"}
      </p>
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return (
    <span
      className="font-mono rounded-md px-2 py-1"
      style={{
        border: "1px solid rgba(27,34,48,0.82)",
        background: "rgba(0,0,0,0.22)",
        color: "var(--text)",
        fontSize: "0.66rem",
      }}
    >
      {children}
    </span>
  );
}

function LabelList({
  label,
  items,
  emptyText,
}: {
  label: string;
  items: string[];
  emptyText: string;
}) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length === 0 ? (
          <EmptyState text={emptyText} />
        ) : (
          items.map((item) => <Tag key={item}>{item}</Tag>)
        )}
      </div>
    </div>
  );
}

function StatusBanner({ message }: { message: string }) {
  return (
    <div
      className="glass-panel"
      style={{
        background: "rgba(194,59,59,0.08)",
        border: "1px solid rgba(194,59,59,0.3)",
        padding: "0.7rem 1rem",
      }}
    >
      <NoiseGrain />
      <p
        className="font-mono"
        style={{ position: "relative", color: "var(--crimson)", fontSize: "0.78rem" }}
      >
        {message}
      </p>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <p
      className="font-mono"
      style={{
        position: "relative",
        color: "rgba(154,167,181,0.5)",
        fontSize: "0.78rem",
        letterSpacing: "0.06em",
      }}
    >
      {text}
    </p>
  );
}

function buildTargetInput(rootNodeId: string, processGuid: string) {
  const root = rootNodeId.trim();
  if (root) return { rootNodeId: root };
  const guid = processGuid.trim();
  if (guid) return { process: { processGuid: guid } };
  return null;
}

function receiptFamilyText(receipt: SignedReceiptJson | null | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function egressProofReloadEvidenceRows(
  proof: NetworkExtensionEgressPolicyProofResponse | null,
): Array<{ key: string; label: string; value: string }> {
  if (!proof) return [];
  const provider = isRecord(proof.networkExtensionProvider) ? proof.networkExtensionProvider : null;
  const observation = isRecord(provider?.last_reload_observation)
    ? provider.last_reload_observation
    : null;
  const observed =
    typeof proof.providerReloadObserved === "boolean"
      ? proof.providerReloadObserved
      : observation != null;
  const rows = [
    {
      key: "providerReloadDeliveryMatched",
      label: "Delivery Matched",
      value: boolValue(proof.providerReloadDelivery?.matched),
    },
    {
      key: "providerReloadDeliveryExecution",
      label: "Delivery Execution",
      value: stringValue(proof.providerReloadDelivery?.executionId),
    },
    { key: "providerReloadObserved", label: "Reload Observed", value: String(observed) },
    {
      key: "providerReloadRequestId",
      label: "Observed Request",
      value: stringValue(proof.providerReloadRequestId ?? observation?.request_id),
    },
    {
      key: "providerReloadGeneration",
      label: "Observed Generation",
      value: stringValue(proof.providerReloadGeneration ?? observation?.generation),
    },
    {
      key: "providerReloadReloaded",
      label: "Provider Reloaded",
      value: boolValue(proof.providerReloadReloaded ?? observation?.reloaded),
    },
    {
      key: "providerReloadSnapshotPath",
      label: "Observed Snapshot",
      value: stringValue(
        proof.providerReloadPolicySnapshotPath ?? observation?.policy_snapshot_path,
      ),
    },
  ];
  return rows.filter(
    (item): item is { key: string; label: string; value: string } => item.value != null,
  );
}

function networkExtensionReloadEvidenceRows(
  receipt: SignedReceiptJson | null | undefined,
): Array<{ key: string; label: string; value: string }> {
  const specs = [
    { key: "networkExtensionReloadRequested", label: "Reload Requested" },
    { key: "networkExtensionReloadSaved", label: "Reload Saved" },
    { key: "networkExtensionReloadRequestId", label: "Reload Request ID" },
    { key: "networkExtensionReloadGeneration", label: "Reload Generation" },
    { key: "networkExtensionReloadError", label: "Reload Error" },
  ];
  return specs
    .map((spec) => ({
      ...spec,
      value: receiptEvidenceHash(receipt, spec.key),
    }))
    .filter((item): item is { key: string; label: string; value: string } => item.value != null);
}

function receiptEvidenceHash(
  receipt: SignedReceiptJson | null | undefined,
  key: string,
): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const evidence = Array.isArray(decision?.evidence) ? decision.evidence : [];
  for (const item of evidence) {
    if (!isRecord(item) || item.key !== key) continue;
    const valueHash = item.valueHash ?? item.value_hash;
    return typeof valueHash === "string" && valueHash.trim() ? valueHash : null;
  }
  return null;
}

function graphLabels(response: ResponseActionResponse | null): string[] {
  return Object.values(response?.graph.nodes ?? {})
    .map((node) => node.label)
    .filter(isString)
    .sort();
}

interface AttributionSummary {
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
}

function attributionIdentityLabels(summary: AttributionSummary | null): string[] {
  const identities = summary?.affectedIdentities;
  if (!identities) return [];
  return [
    ...identityBucketLabels("Host", identities.hosts),
    ...identityBucketLabels("User", identities.users),
    ...identityBucketLabels("Session", identities.sessions),
    ...identityBucketLabels("Agent", identities.agents),
    ...identityBucketLabels("Workload", identities.workloads),
    ...identityBucketLabels("Approval", identities.approvals),
  ].sort();
}

function identityBucketLabels(
  prefix: string,
  identities: Array<{ id: string; label: string }>,
): string[] {
  return identities
    .map((identity) => `${prefix}: ${identity.id || identity.label}`)
    .filter(isString);
}

function attributionToolLabels(summary: AttributionSummary | null): string[] {
  return (summary?.affectedTools ?? [])
    .map((tool) => tool.toolName || tool.label)
    .filter(isString)
    .sort();
}

function numberText(value: number | undefined): string {
  return typeof value === "number" ? String(value) : "-";
}

function boolText(value: boolean | undefined): string {
  return typeof value === "boolean" ? String(value) : "-";
}

function stringValue(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function boolValue(value: unknown): string | null {
  return typeof value === "boolean" ? String(value) : null;
}

function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
