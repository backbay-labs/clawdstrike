import { useEffect, useMemo, useState } from "react";
import {
  createResponseAction,
  type EndpointDecisionAction,
  fetchNetworkExtensionEgressPolicyProof,
  fetchResponseExecutions,
  type NetworkExtensionEgressPolicyProofResponse,
  type ResponseActionResponse,
  type ResponseExecutionRollbackResponse,
  type ResponseExecutionsResponse,
  rollbackResponseExecution,
} from "../api/client";
import { GlassButton, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";
import { NumberField, SelectField, TextField } from "./LocalContainment/fields";
import {
  EffectRow,
  EmptyState,
  ExecutionSummary,
  LabelList,
  Metric,
  PanelTitle,
  SmallFact,
  StatusBanner,
  StatusPill,
  Tag,
} from "./LocalContainment/display";
import {
  attributionIdentityLabels,
  attributionToolLabels,
  boolText,
  buildTargetInput,
  egressProofReloadEvidenceRows,
  graphLabels,
  isString,
  networkExtensionReloadEvidenceRows,
  numberText,
  receiptFamilyText,
  safeFilenameId,
} from "./LocalContainment/utils";

const DEFAULT_TTL_SECONDS = 600;
const CONTAINMENT_ACTIONS: EndpointDecisionAction[] = [
  "suspend_process_tree",
  "restrict_egress",
  "collect_evidence",
  "quarantine_file",
  "disable_persistence",
  "revoke_grant",
  "terminate_process_tree",
];

export function LocalContainment(_props: { windowId?: string }) {
  const [rootNodeId, setRootNodeId] = useState("");
  const [processGuid, setProcessGuid] = useState("");
  const [action, setAction] = useState<EndpointDecisionAction>("suspend_process_tree");
  const [ttlSeconds, setTtlSeconds] = useState(DEFAULT_TTL_SECONDS);
  const [actorUser, setActorUser] = useState("local-operator");
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

    setLoading(dryRun ? "plan" : "execute");
    try {
      const response = await createResponseAction({
        ...target,
        action,
        ttlSeconds,
        dryRun,
        ...(reason.trim() && { reason: reason.trim() }),
        ...(!dryRun && { actor: { userId: actorUser.trim() || "local-operator" } }),
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
