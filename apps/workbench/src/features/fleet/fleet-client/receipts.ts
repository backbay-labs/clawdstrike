import {
  controlHeaders,
  jsonFetch,
  preferredUrl,
  proxyUrl,
} from "./internal";
import type {
  FleetConnection,
  FleetReceipt,
  FleetReceiptListResponse,
  FleetReceiptVerifyResponse,
} from "./types";

interface StoreReceiptPayload {
  timestamp: string;
  verdict: string;
  guard: string;
  policy_name: string;
  signature: string;
  public_key: string;
  chain_hash?: string;
  evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  signed_receipt?: Record<string, unknown>;
}

export async function fetchReceipts(
  conn: FleetConnection,
  opts?: { offset?: number; limit?: number },
): Promise<FleetReceiptListResponse> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { receipts: [], total: 0, offset: 0, limit: 50 };

  const params = new URLSearchParams();
  if (opts?.offset != null) params.set("offset", String(opts.offset));
  if (opts?.limit != null) params.set("limit", String(opts.limit));
  const qs = params.toString();
  const endpoint = `${url}/api/v1/receipts${qs ? `?${qs}` : ""}`;

  const res = await jsonFetch<unknown>(
    proxyUrl(endpoint, kind),
    { headers: controlHeaders(conn) },
  );

  // Handle response shapes: { items, total, offset, limit }, { receipts, ... }, or bare array.
  if (Array.isArray(res)) {
    const receipts = res.filter(isFleetReceipt);
    return { receipts, total: receipts.length, offset: opts?.offset ?? 0, limit: opts?.limit ?? 50 };
  }
  if (res && typeof res === "object") {
    const obj = res as Record<string, unknown>;
    const items =
      "items" in obj && Array.isArray(obj.items)
        ? obj.items
        : "receipts" in obj && Array.isArray(obj.receipts)
          ? obj.receipts
          : null;
    if (items) {
      return {
        receipts: items.filter(isFleetReceipt),
        total: typeof obj.total === "number" ? obj.total : items.length,
        offset: typeof obj.offset === "number" ? obj.offset : (opts?.offset ?? 0),
        limit: typeof obj.limit === "number" ? obj.limit : (opts?.limit ?? 50),
      };
    }
  }

  throw new Error("[fleet-client] fetchReceipts: unexpected response shape");
}

export async function storeReceipt(
  conn: FleetConnection,
  receipt: FleetReceipt,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(toStoreReceiptPayload(receipt)),
      },
    );
    const storedId =
      res && typeof res === "object" && typeof (res as Record<string, unknown>).id === "string"
        ? ((res as Record<string, unknown>).id as string)
        : receipt.id;
    return { success: true, id: storedId };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function storeReceiptsBatch(
  conn: FleetConnection,
  receipts: FleetReceipt[],
): Promise<{ success: boolean; stored: number; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, stored: 0, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts/batch`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({ receipts: receipts.map(toStoreReceiptPayload) }),
      },
    );
    const response = res as Record<string, unknown>;
    const storedCount =
      typeof response?.count === "number"
        ? response.count
        : Array.isArray(response?.stored)
          ? response.stored.length
          : receipts.length;
    return { success: true, stored: storedCount };
  } catch (err) {
    return {
      success: false,
      stored: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchReceiptChain(
  conn: FleetConnection,
  policyName: string,
): Promise<FleetReceipt[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts/chain/${encodeURIComponent(policyName)}`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle array, PaginatedResponse { items }, or wrapped { receipts } response
    if (Array.isArray(res)) {
      return res.filter(isFleetReceipt);
    }
    if (res && typeof res === "object") {
      const obj = res as Record<string, unknown>;
      const items =
        "items" in obj && Array.isArray(obj.items)
          ? obj.items
          : "receipts" in obj && Array.isArray(obj.receipts)
            ? obj.receipts
            : null;
      if (items) {
        return (items as unknown[]).filter(isFleetReceipt);
      }
    }
    throw new Error("[fleet-client] fetchReceiptChain: unexpected response shape");
  } catch (e) {
    console.warn("[fleet-client] fetchReceiptChain failed:", e);
    return [];
  }
}

export async function verifyReceiptRemote(
  conn: FleetConnection,
  receiptId: string,
): Promise<FleetReceiptVerifyResponse> {
  const { url, kind } = preferredUrl(conn);
  if (!url) throw new Error("No API URL configured");

  const res = await jsonFetch<unknown>(
    proxyUrl(`${url}/api/v1/receipts/${encodeURIComponent(receiptId)}/verify`, kind),
    {
      method: "POST",
      headers: controlHeaders(conn),
      body: JSON.stringify({}),
    },
  );

  if (!res || typeof res !== "object") {
    throw new Error("[fleet-client] verifyReceiptRemote: unexpected response shape");
  }

  const obj = res as Record<string, unknown>;
  const errors = Array.isArray(obj.errors)
    ? obj.errors.filter((value): value is string => typeof value === "string")
    : [];
  const valid = typeof obj.valid === "boolean" ? obj.valid : false;
  const signerValid = typeof obj.signer_valid === "boolean" ? obj.signer_valid : valid;

  return {
    receipt_id: typeof obj.receipt_id === "string" ? obj.receipt_id : receiptId,
    valid,
    signer_valid: signerValid,
    errors,
    reason: errors.length > 0 ? errors.join("; ") : undefined,
    verified_at: new Date().toISOString(),
  };
}

function isFleetReceipt(value: unknown): value is FleetReceipt {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.id === "string" &&
    typeof obj.timestamp === "string" &&
    typeof obj.verdict === "string" &&
    typeof obj.guard === "string" &&
    typeof obj.policy_name === "string" &&
    typeof obj.signature === "string" &&
    typeof obj.public_key === "string"
  );
}

function toStoreReceiptPayload(receipt: FleetReceipt): StoreReceiptPayload {
  const metadata: Record<string, unknown> = { ...(receipt.metadata ?? {}) };
  const signedReceipt =
    receipt.signed_receipt ??
    (receipt.evidence?.signed_receipt &&
    typeof receipt.evidence.signed_receipt === "object" &&
    !Array.isArray(receipt.evidence.signed_receipt)
      ? (receipt.evidence.signed_receipt as Record<string, unknown>)
      : undefined);

  metadata.client_receipt_id = receipt.id;
  if (receipt.action_type) metadata.action_type = receipt.action_type;
  if (receipt.action_target) metadata.action_target = receipt.action_target;
  if (typeof receipt.valid === "boolean") metadata.valid = receipt.valid;

  const payload: StoreReceiptPayload = {
    timestamp: receipt.timestamp,
    verdict: receipt.verdict,
    guard: receipt.guard,
    policy_name: receipt.policy_name,
    signature: receipt.signature,
    public_key: receipt.public_key,
  };

  if (receipt.chain_hash) payload.chain_hash = receipt.chain_hash;
  if (receipt.evidence) payload.evidence = receipt.evidence;
  if (Object.keys(metadata).length > 0) payload.metadata = metadata;
  if (signedReceipt) payload.signed_receipt = signedReceipt;

  return payload;
}
