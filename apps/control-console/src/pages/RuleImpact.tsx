import { useMemo, useState } from "react";
import {
  applyPolicyDelta,
  createDetectionCandidate,
  createPolicyDelta,
  createStagedDetection,
  type DetectionCandidateResponse,
  dryRunPolicyDeltaApply,
  type EndpointDecisionAction,
  type PolicyDeltaApplyResponse,
  type PolicyDeltaResponse,
  type StageDetectionResponse,
} from "../api/client";
import { GlassButton, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";
import { NumberField, SelectField, TextField } from "./RuleImpact/fields";
import {
  AffectedNodeRow,
  EmptyState,
  IdentityContextRow,
  Metric,
  PanelTitle,
  SmallFact,
  StageRow,
  StatusBanner,
  StatusPill,
  ToolContextRow,
} from "./RuleImpact/display";
import {
  boolText,
  buildTargetInput,
  exportFilenameId,
  numberText,
  receiptFamilyText,
} from "./RuleImpact/utils";

const DEFAULT_MAX_DEPTH = 8;
const RULE_ACTIONS: EndpointDecisionAction[] = [
  "block",
  "warn",
  "alert",
  "restrict_egress",
  "suspend_process_tree",
  "collect_evidence",
];
const STAGES = ["observe", "audit", "warn", "limited_block", "full_block"];

export function RuleImpact(_props: { windowId?: string }) {
  const [rootNodeId, setRootNodeId] = useState("");
  const [processGuid, setProcessGuid] = useState("");
  const [action, setAction] = useState<EndpointDecisionAction>("block");
  const [selectedStage, setSelectedStage] = useState("audit");
  const [maxDepth, setMaxDepth] = useState(DEFAULT_MAX_DEPTH);
  const [operator, setOperator] = useState("local-agent");
  const [note, setNote] = useState("");
  const [candidate, setCandidate] = useState<DetectionCandidateResponse | null>(null);
  const [staged, setStaged] = useState<StageDetectionResponse | null>(null);
  const [delta, setDelta] = useState<PolicyDeltaResponse | null>(null);
  const [applyResult, setApplyResult] = useState<PolicyDeltaApplyResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const candidateReceipt = useMemo(() => receiptFamilyText(candidate?.receipt), [candidate]);
  const deltaReceipt = useMemo(() => receiptFamilyText(delta?.record.receipt), [delta]);
  const postApplyReceipt = useMemo(
    () => receiptFamilyText(applyResult?.postApplyEnforcement?.receipt),
    [applyResult],
  );
  const proofImpactHash =
    applyResult?.postApplyEnforcement?.crossWindowImpactHash ??
    applyResult?.record.crossWindowImpactHash ??
    delta?.record.artifact.rollout.crossWindowImpactHash ??
    staged?.record.crossWindowImpactHash ??
    "-";
  const proofRecommendationHash =
    applyResult?.postApplyEnforcement?.crossWindowRecommendationHash ??
    applyResult?.record.crossWindowRecommendationHash ??
    delta?.record.artifact.rollout.crossWindowRecommendationHash ??
    staged?.record.crossWindowRecommendationHash ??
    "-";
  const postApplySynced = boolText(applyResult?.postApplyEnforcement?.policySyncedToDisk);
  const providerAck = boolText(
    applyResult?.postApplyEnforcement?.providerAcknowledgementPoll?.satisfied,
  );
  const providerAckAttempts = numberText(
    applyResult?.postApplyEnforcement?.providerAcknowledgementPoll?.attempts,
  );
  const providerAcknowledgements =
    applyResult?.postApplyEnforcement?.providerPolicyAcknowledgements ?? [];
  const affectedIdentities = candidate?.simulation.affectedIdentities ?? [];
  const affectedTools = candidate?.simulation.affectedTools ?? [];
  const deltaSourceIdentities = delta?.record.artifact.sourceAffectedIdentities ?? [];
  const deltaSourceTools = delta?.record.artifact.sourceAffectedTools ?? [];
  const exportPayload = useMemo(
    () => [candidate, staged, delta, applyResult].filter(Boolean),
    [candidate, staged, delta, applyResult],
  );

  async function generateCandidate() {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading("candidate");
    try {
      const response = await createDetectionCandidate({ ...target, action, maxDepth });
      setCandidate(response);
      setSelectedStage(response.recommendedStage || selectedStage);
      setStaged(null);
      setDelta(null);
      setApplyResult(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate detection candidate");
    } finally {
      setLoading(null);
    }
  }

  async function stageDetection() {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading("stage");
    try {
      const response = await createStagedDetection({
        ...target,
        action,
        maxDepth,
        selectedStage,
        stagedBy: operator.trim() || "local-agent",
        ...(note.trim() && { note: note.trim() }),
      });
      setStaged(response);
      setDelta(null);
      setApplyResult(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stage detection");
    } finally {
      setLoading(null);
    }
  }

  async function generateDelta() {
    const stagedDetectionId = staged?.record.stagedDetectionId;
    if (!stagedDetectionId) {
      setError("Stage a detection before generating a policy delta");
      return;
    }

    setLoading("delta");
    try {
      const response = await createPolicyDelta({
        stagedDetectionId,
        generatedBy: operator.trim() || "local-agent",
        ...(note.trim() && { note: note.trim() }),
      });
      setDelta(response);
      setApplyResult(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate policy delta");
    } finally {
      setLoading(null);
    }
  }

  async function dryRunApply() {
    const policyDeltaId = delta?.record.policyDeltaId;
    if (!policyDeltaId) {
      setError("Generate a policy delta before dry-run apply");
      return;
    }

    setLoading("apply");
    try {
      const response = await dryRunPolicyDeltaApply(policyDeltaId, {
        appliedBy: operator.trim() || "local-agent",
        ...(note.trim() && { note: note.trim() }),
      });
      setApplyResult(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to dry-run policy delta apply");
    } finally {
      setLoading(null);
    }
  }

  async function applyDelta() {
    const policyDeltaId = delta?.record.policyDeltaId;
    if (!policyDeltaId) {
      setError("Generate a policy delta before apply");
      return;
    }
    if (applyResult?.record.dryRun !== true) {
      setError("Dry-run the policy delta before live apply");
      return;
    }

    setLoading("live-apply");
    try {
      const response = await applyPolicyDelta(policyDeltaId, {
        dryRun: false,
        appliedBy: operator.trim() || "local-agent",
        verifyProtectionState: true,
        ...(note.trim() && { note: note.trim() }),
      });
      setApplyResult(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to apply policy delta");
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
            Rule impact and staged enforcement
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Rule Impact
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={generateCandidate} disabled={loading != null}>
            {loading === "candidate" ? "Generating..." : "Generate Candidate"}
          </GlassButton>
          <GlassButton onClick={stageDetection} disabled={loading != null}>
            {loading === "stage" ? "Staging..." : "Stage Detection"}
          </GlassButton>
          <GlassButton onClick={generateDelta} disabled={loading != null || !staged}>
            {loading === "delta" ? "Generating..." : "Generate Delta"}
          </GlassButton>
          <GlassButton onClick={dryRunApply} disabled={loading != null || !delta}>
            {loading === "apply" ? "Dry-running..." : "Dry-run Apply"}
          </GlassButton>
          <GlassButton
            onClick={applyDelta}
            disabled={loading != null || !delta || applyResult?.record.dryRun !== true}
          >
            {loading === "live-apply" ? "Applying..." : "Apply Delta"}
          </GlassButton>
          <GlassButton
            onClick={() => exportAsJSON(exportPayload, `rule-impact-${exportFilenameId(delta)}`)}
            disabled={exportPayload.length === 0}
          >
            Export JSON
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.78fr)_minmax(0,1.22fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Target" title="Candidate Source" />
          <div className="mt-4 space-y-3">
            <TextField label="Root Node ID" value={rootNodeId} onChange={setRootNodeId} />
            <TextField label="Process GUID" value={processGuid} onChange={setProcessGuid} />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <SelectField
                label="Action"
                value={action}
                options={RULE_ACTIONS}
                onChange={(value) => setAction(value as EndpointDecisionAction)}
              />
              <NumberField
                label="Max Depth"
                value={maxDepth}
                min={1}
                max={8}
                onChange={setMaxDepth}
              />
            </div>
            <SelectField
              label="Selected Stage"
              value={selectedStage}
              options={STAGES}
              onChange={setSelectedStage}
            />
            <TextField label="Operator" value={operator} onChange={setOperator} />
            <TextField label="Note" value={note} onChange={setNote} />
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric
              label="Breakage"
              value={candidate ? `${candidate.simulation.developerBreakageScore}/100` : "-"}
            />
            <Metric label="Impact" value={candidate?.simulation.impactLevel ?? "-"} />
            <Metric label="Recommended" value={candidate?.recommendedStage ?? "-"} />
            <Metric
              label="Target Epoch"
              value={
                delta?.record.artifact.targetPolicy.targetPolicyEpoch == null
                  ? "-"
                  : `Epoch ${delta.record.artifact.targetPolicy.targetPolicyEpoch}`
              }
            />
          </div>

          <Plate className="p-4" goldEdge>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle
                eyebrow={candidate ? "Generated Candidate" : "No candidate"}
                title={candidate?.candidate.rootLabel ?? "Rule Candidate"}
              />
              <StatusPill
                value={candidate ? `Recommended: ${candidate.recommendedStage}` : "Recommended: -"}
              />
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
              <SmallFact label="Rule ID" value={candidate?.candidate.ruleId ?? "-"} mono />
              <SmallFact
                label="Graph Slice"
                value={candidate?.candidate.graphSliceId ?? "-"}
                mono
              />
              <SmallFact label="Receipt" value={candidateReceipt ?? "-"} />
              <SmallFact label="Root" value={candidate?.candidate.rootNodeId ?? "-"} mono />
              <SmallFact
                label="Would Block"
                value={candidate ? String(candidate.simulation.wouldBlock) : "-"}
              />
              <SmallFact
                label="Affected Nodes"
                value={numberText(candidate?.simulation.affectedNodeCount)}
              />
            </div>
            {candidate && (
              <p
                className="font-body mt-4"
                style={{ color: "rgba(229,231,235,0.78)", fontSize: "0.88rem" }}
              >
                {candidate.simulation.summary}
              </p>
            )}
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Plate className="p-4">
              <PanelTitle eyebrow="Promotion Plan" title="Stages" />
              <div className="mt-4 space-y-2">
                {!candidate || candidate.stagePlan.length === 0 ? (
                  <EmptyState text="No staged rollout plan" />
                ) : (
                  candidate.stagePlan.map((stage) => (
                    <StageRow
                      key={`${stage.stage}:${stage.action}`}
                      stage={stage.stage}
                      action={stage.action}
                      gate={stage.promotionGate}
                      recommended={stage.recommended}
                    />
                  ))
                )}
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle eyebrow="Affected Graph" title="Developer Blast Radius" />
              <div className="mt-4 space-y-2">
                {!candidate || candidate.simulation.affectedNodes.length === 0 ? (
                  <EmptyState text="No affected nodes" />
                ) : (
                  candidate.simulation.affectedNodes.map((node) => (
                    <AffectedNodeRow key={node.nodeId} node={node} />
                  ))
                )}
              </div>
            </Plate>
          </div>

          <Plate className="p-4">
            <PanelTitle eyebrow="Attribution" title="Affected Identities and Tools" />
            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="space-y-2">
                {!candidate || affectedIdentities.length === 0 ? (
                  <EmptyState text="No affected identities" />
                ) : (
                  affectedIdentities.map((identity) => (
                    <IdentityContextRow
                      key={`${identity.identityKind}:${identity.value}:${identity.sourceNodeId}`}
                      identity={identity}
                    />
                  ))
                )}
              </div>
              <div className="space-y-2">
                {!candidate || affectedTools.length === 0 ? (
                  <EmptyState text="No affected tools" />
                ) : (
                  affectedTools.map((tool) => (
                    <ToolContextRow
                      key={`${tool.toolName}:${tool.toolCallId ?? ""}:${tool.sourceNodeId}`}
                      tool={tool}
                    />
                  ))
                )}
              </div>
            </div>
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Plate className="p-4">
              <PanelTitle eyebrow="Staged Detection" title={staged?.record.stage ?? "Not staged"} />
              <div className="mt-4 space-y-3">
                <SmallFact
                  label="Staged Detection ID"
                  value={staged?.record.stagedDetectionId ?? "-"}
                  mono
                />
                <SmallFact label="Staged By" value={staged?.record.stagedBy ?? "-"} />
                <SmallFact
                  label="Policy Epoch"
                  value={
                    staged?.record.policy.policyEpoch == null
                      ? "-"
                      : `Epoch ${staged.record.policy.policyEpoch}`
                  }
                />
                <SmallFact label="Ledger" value={staged?.path ?? "-"} mono />
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle eyebrow="Policy Delta" title={delta?.record.stage ?? "No delta"} />
              <div className="mt-4 space-y-3">
                <SmallFact
                  label="Policy Delta ID"
                  value={delta?.record.policyDeltaId ?? "-"}
                  mono
                />
                <SmallFact label="Artifact Hash" value={delta?.record.artifactHash ?? "-"} mono />
                <SmallFact label="Receipt" value={deltaReceipt ?? "-"} />
                <SmallFact
                  label="Apply Preview"
                  value={
                    applyResult ? `Dry run: ${String(applyResult.record.dryRun)}` : "Dry run: -"
                  }
                />
                <SmallFact
                  label="Apply Status"
                  value={
                    applyResult ? `Applied: ${String(applyResult.record.applied)}` : "Applied: -"
                  }
                />
                <SmallFact
                  label="New Epoch"
                  value={
                    applyResult?.record.newPolicyEpoch == null
                      ? "-"
                      : String(applyResult.record.newPolicyEpoch)
                  }
                />
                <SmallFact label="Validation Impact" value={proofImpactHash} mono />
                <SmallFact label="Validation Recommendation" value={proofRecommendationHash} mono />
                <SmallFact label="Post-apply Proof" value={postApplyReceipt ?? "-"} />
                <SmallFact label="Synced" value={`Synced: ${postApplySynced}`} />
                <SmallFact label="Provider ACK" value={`Provider ACK: ${providerAck}`} />
                <SmallFact label="ACK Attempts" value={`ACK Attempts: ${providerAckAttempts}`} />
                <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                  <div className="space-y-2">
                    {deltaSourceIdentities.length === 0 ? (
                      <EmptyState text="No source identities" />
                    ) : (
                      deltaSourceIdentities.map((identity) => (
                        <IdentityContextRow
                          key={`delta:${identity.identityKind}:${identity.value}:${identity.sourceNodeId}`}
                          identity={identity}
                        />
                      ))
                    )}
                  </div>
                  <div className="space-y-2">
                    {deltaSourceTools.length === 0 ? (
                      <EmptyState text="No source tools" />
                    ) : (
                      deltaSourceTools.map((tool) => (
                        <ToolContextRow
                          key={`delta:${tool.toolName}:${tool.toolCallId ?? ""}:${tool.sourceNodeId}`}
                          tool={tool}
                        />
                      ))
                    )}
                  </div>
                </div>
                {providerAcknowledgements.map((ack) => (
                  <SmallFact
                    key={ack.providerId ?? String(ack.providerKind ?? "provider")}
                    label="Provider"
                    value={`${ack.providerId ?? "provider"}: ${
                      ack.acknowledged ? "acknowledged" : "not acknowledged"
                    }`}
                    mono
                  />
                ))}
              </div>
            </Plate>
          </div>
        </section>
      </div>
    </div>
  );
}
