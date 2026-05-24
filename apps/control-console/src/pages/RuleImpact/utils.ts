import {
  type PolicyDeltaResponse,
  type SignedReceiptJson,
} from "../../api/client";

export function buildTargetInput(rootNodeId: string, processGuid: string) {
  const root = rootNodeId.trim();
  if (root) return { rootNodeId: root };
  const guid = processGuid.trim();
  if (guid) return { process: { processGuid: guid } };
  return null;
}

export function receiptFamilyText(receipt: SignedReceiptJson | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

export function numberText(value: number | undefined): string {
  return typeof value === "number" ? String(value) : "-";
}

export function boolText(value: boolean | undefined): string {
  return typeof value === "boolean" ? String(value) : "-";
}

export function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export function exportFilenameId(delta: PolicyDeltaResponse | null): string {
  return safeFilenameId(delta?.record.policyDeltaId ?? "candidate");
}

export function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
