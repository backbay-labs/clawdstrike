import {
  type CausalSliceAffectedIdentities,
  type CausalSliceAffectedTool,
  type NetworkExtensionEgressPolicyProofResponse,
  type ResponseActionResponse,
  type SignedReceiptJson,
} from "../../api/client";

export function buildTargetInput(rootNodeId: string, processGuid: string) {
  const root = rootNodeId.trim();
  if (root) return { rootNodeId: root };
  const guid = processGuid.trim();
  if (guid) return { process: { processGuid: guid } };
  return null;
}

export function receiptFamilyText(receipt: SignedReceiptJson | null | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

export function egressProofReloadEvidenceRows(
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

export function networkExtensionReloadEvidenceRows(
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

export function receiptEvidenceHash(
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

export function graphLabels(response: ResponseActionResponse | null): string[] {
  return Object.values(response?.graph.nodes ?? {})
    .map((node) => node.label)
    .filter(isString)
    .sort();
}

export interface AttributionSummary {
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
}

export function attributionIdentityLabels(summary: AttributionSummary | null): string[] {
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

export function identityBucketLabels(
  prefix: string,
  identities: Array<{ id: string; label: string }>,
): string[] {
  return identities
    .map((identity) => `${prefix}: ${identity.id || identity.label}`)
    .filter(isString);
}

export function attributionToolLabels(summary: AttributionSummary | null): string[] {
  return (summary?.affectedTools ?? [])
    .map((tool) => tool.toolName || tool.label)
    .filter(isString)
    .sort();
}

export function numberText(value: number | undefined): string {
  return typeof value === "number" ? String(value) : "-";
}

export function boolText(value: boolean | undefined): string {
  return typeof value === "boolean" ? String(value) : "-";
}

export function stringValue(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

export function boolValue(value: unknown): string | null {
  return typeof value === "boolean" ? String(value) : null;
}

export function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
