export type GatewayFrameType = "req" | "res" | "event";

export type GatewayRequestFrame<TParams = unknown> = {
  type: "req";
  id: string;
  method: string;
  params?: TParams;
};

export type GatewayResponseError = {
  code?: string;
  message: string;
  details?: unknown;
  retryable?: boolean;
  retryAfterMs?: number;
};

export type GatewayResponseFrame<TPayload = unknown> = {
  type: "res";
  id: string;
  ok: boolean;
  payload?: TPayload;
  error?: GatewayResponseError;
};

export type GatewayEventFrame<TPayload = unknown> = {
  type: "event";
  event: string;
  payload?: TPayload;
  seq?: number;
  stateVersion?: number | string;
};

export type GatewayFrame =
  | GatewayRequestFrame
  | GatewayResponseFrame
  | GatewayEventFrame;

export type GatewayRole = "operator" | "node";

export type GatewayOperatorScope =
  | "operator.read"
  | "operator.write"
  | "operator.admin"
  | "operator.approvals"
  | "operator.pairing";

export type GatewayConnectParams = {
  minProtocol: number;
  maxProtocol: number;
  client: {
    id: string;
    displayName?: string;
    version?: string;
    platform?: string;
    mode?: string;
    instanceId?: string;
  };
  role?: GatewayRole;
  scopes?: GatewayOperatorScope[];
  caps?: string[];
  commands?: string[];
  permissions?: Record<string, unknown>;
  auth?: {
    token?: string;
    deviceToken?: string;
  };
  locale?: string;
  userAgent?: string;
  device?: {
    id: string;
    publicKey?: string;
    signature?: string;
    signedAt?: number;
    nonce?: string;
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function safeParseGatewayFrame(raw: string): GatewayFrame | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;
  const type = parsed.type;
  if (type !== "req" && type !== "res" && type !== "event") return null;

  if (type === "req") {
    if (typeof parsed.id !== "string" || typeof parsed.method !== "string") return null;
    return parsed as GatewayRequestFrame;
  }

  if (type === "res") {
    if (typeof parsed.id !== "string" || typeof parsed.ok !== "boolean") return null;
    return parsed as GatewayResponseFrame;
  }

  if (typeof parsed.event !== "string") return null;
  return parsed as GatewayEventFrame;
}

export function createRequestId(prefix = "sdr"): string {
  try {
    if (globalThis.crypto?.randomUUID) return `${prefix}:${globalThis.crypto.randomUUID()}`;
  } catch {
    // ignore
  }
  return `${prefix}:${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

