import { createHash, randomBytes, randomUUID } from "node:crypto";

import * as ed25519 from "@noble/ed25519";

export type BrokerProvider = "openai" | "github" | "slack" | "generic_https";
export type BrokerHttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type BrokerProofBindingMode = "loopback" | "dpop";
export type BrokerIntentRiskLevel = "low" | "medium" | "high";
export type BrokerApprovalState = "not_required" | "pending" | "approved" | "rejected";

export interface BrokerIntentResource {
  kind: string;
  value: string;
}

export interface BrokerIntentPreview {
  previewId: string;
  provider: BrokerProvider;
  operation: string;
  summary: string;
  createdAt: string;
  riskLevel: BrokerIntentRiskLevel;
  dataClasses: string[];
  resources: BrokerIntentResource[];
  egressHost: string;
  estimatedCostUsdMicros?: number;
  approvalRequired: boolean;
  approvalState: BrokerApprovalState;
  approvedAt?: string;
  approver?: string;
}

export interface BrokerExecutionIntent {
  provider: BrokerProvider;
  secretRef: string;
  request: {
    url: string;
    method: BrokerHttpMethod;
    headers?: Record<string, string>;
    body?: string;
    bodySha256?: string;
  };
  sessionId?: string;
  endpointAgentId?: string;
  runtimeAgentId?: string;
  runtimeAgentKind?: string;
  originFingerprint?: string;
  previewId?: string;
  delegationToken?: string;
}

export interface BrokerExecutionResponse {
  executionId: string;
  capabilityId: string;
  provider: BrokerProvider;
  status: number;
  headers: Record<string, string>;
  body?: string;
  contentType?: string;
}

export interface BrokerExecutionStreamResponse {
  executionId: string;
  capabilityId: string;
  provider: BrokerProvider;
  status: number;
  headers: Record<string, string>;
  body: ReadableStream<Uint8Array>;
  contentType?: string;
}

export interface SecretBrokerClientOptions {
  hushdBaseUrl: string;
  brokerdBaseUrl: string;
  token?: string;
  timeoutMs?: number;
  proofBindingMode?: BrokerProofBindingMode;
  previewBeforeExecute?: boolean;
  fetchImpl?: typeof fetch;
}

type BrokerCapabilityResponse = {
  capability: string;
  capability_id: string;
  expires_at: string;
  policy_hash: string;
};

type BrokerExecuteResponse = {
  execution_id: string;
  capability_id: string;
  provider: BrokerProvider;
  status: number;
  headers?: Record<string, string>;
  body?: string;
  content_type?: string;
};

type BrokerPreviewResponse = {
  preview: {
    preview_id: string;
    provider: BrokerProvider;
    operation: string;
    summary: string;
    created_at: string;
    risk_level: BrokerIntentRiskLevel;
    data_classes?: string[];
    resources?: BrokerIntentResource[];
    egress_host: string;
    estimated_cost_usd_micros?: number;
    approval_required: boolean;
    approval_state: BrokerApprovalState;
    approved_at?: string;
    approver?: string;
  };
};

const BROKER_EXECUTION_ID_HEADER = "x-clawdstrike-execution-id";
const BROKER_CAPABILITY_ID_HEADER = "x-clawdstrike-capability-id";
const BROKER_PROVIDER_HEADER = "x-clawdstrike-provider";

type CapabilityProofBinding =
  | {
      mode: "loopback";
      binding_sha256: string;
    }
  | {
      mode: "dpop";
      key_thumbprint: string;
    };

type DpopBindingMaterial = {
  privateKey: Uint8Array;
  publicKeyHex: string;
  keyThumbprint: string;
};

type ExecuteBindingProof = {
  mode: "dpop";
  public_key: string;
  signature: string;
  issued_at: string;
  nonce: string;
};

export class BrokerPreviewApprovalRequiredError extends Error {
  readonly preview: BrokerIntentPreview;

  constructor(preview: BrokerIntentPreview) {
    super(`BROKER_PREVIEW_APPROVAL_REQUIRED:${preview.previewId}`);
    this.name = "BrokerPreviewApprovalRequiredError";
    this.preview = preview;
  }
}

export class SecretBrokerClient {
  private readonly hushdBaseUrl: string;
  private readonly brokerdBaseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly proofBindingMode?: BrokerProofBindingMode;
  private readonly previewBeforeExecute: boolean;
  private readonly fetchImpl: typeof fetch;

  constructor(options: SecretBrokerClientOptions) {
    this.hushdBaseUrl = options.hushdBaseUrl.replace(/\/+$/, "");
    this.brokerdBaseUrl = options.brokerdBaseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.proofBindingMode = options.proofBindingMode;
    this.previewBeforeExecute = options.previewBeforeExecute ?? true;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async previewIntent(intent: BrokerExecutionIntent): Promise<BrokerIntentPreview> {
    const payload = await this.postJson<BrokerPreviewResponse>(
      `${this.hushdBaseUrl}/api/v1/broker/previews`,
      {
        provider: intent.provider,
        url: intent.request.url,
        method: intent.request.method,
        secret_ref: intent.secretRef,
        body: intent.request.body,
        body_sha256: intent.request.bodySha256,
        session_id: intent.sessionId,
        endpoint_agent_id: intent.endpointAgentId,
        runtime_agent_id: intent.runtimeAgentId,
        runtime_agent_kind: intent.runtimeAgentKind,
        origin_fingerprint: intent.originFingerprint,
      },
      "BROKER_PREVIEW_REQUEST_FAILED",
    );
    return normalizePreview(payload.preview);
  }

  async execute(intent: BrokerExecutionIntent): Promise<BrokerExecutionResponse> {
    const prepared = await this.prepareExecution(intent);
    const executed = await this.postJson<BrokerExecuteResponse>(
      `${this.brokerdBaseUrl}/v1/execute`,
      prepared.executePayload,
      "BROKER_EXECUTE_FAILED",
    );

    return {
      executionId: executed.execution_id,
      capabilityId: executed.capability_id,
      provider: executed.provider,
      status: executed.status,
      headers: executed.headers ?? {},
      body: executed.body,
      contentType: executed.content_type,
    };
  }

  async executeStream(intent: BrokerExecutionIntent): Promise<BrokerExecutionStreamResponse> {
    const prepared = await this.prepareExecution(intent);
    const response = await this.postResponse(
      `${this.brokerdBaseUrl}/v1/execute/stream`,
      prepared.executePayload,
      "BROKER_EXECUTE_STREAM_FAILED",
    );

    if (!response.body) {
      throw new Error("BROKER_EXECUTE_STREAM_EMPTY");
    }

    return {
      executionId: response.headers.get(BROKER_EXECUTION_ID_HEADER) ?? prepared.capabilityId,
      capabilityId: response.headers.get(BROKER_CAPABILITY_ID_HEADER) ?? prepared.capabilityId,
      provider:
        (response.headers.get(BROKER_PROVIDER_HEADER) as BrokerProvider | null) ?? intent.provider,
      status: response.status,
      headers: headersToObject(response.headers),
      body: response.body,
      contentType: response.headers.get("content-type") ?? undefined,
    };
  }

  private async issueCapability(
    intent: BrokerExecutionIntent,
    proofBinding: CapabilityProofBinding,
    previewId?: string,
  ): Promise<BrokerCapabilityResponse> {
    return this.postJson<BrokerCapabilityResponse>(
      `${this.hushdBaseUrl}/api/v1/broker/capabilities`,
      {
        provider: intent.provider,
        url: intent.request.url,
        method: intent.request.method,
        secret_ref: intent.secretRef,
        body_sha256: intent.request.bodySha256,
        session_id: intent.sessionId,
        endpoint_agent_id: intent.endpointAgentId,
        runtime_agent_id: intent.runtimeAgentId,
        runtime_agent_kind: intent.runtimeAgentKind,
        origin_fingerprint: intent.originFingerprint,
        proof_binding: proofBinding,
        preview_id: previewId,
        delegation_token: intent.delegationToken,
      },
      "BROKER_CAPABILITY_REQUEST_FAILED",
    );
  }

  private async postJson<T>(
    url: string,
    body: unknown,
    errorCode: string,
  ): Promise<T> {
    const response = await this.postResponse(url, body, errorCode);
    try {
      return (await response.json()) as T;
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(`${errorCode}:${cause}`);
    }
  }

  private async postResponse(
    url: string,
    body: unknown,
    errorCode: string,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    timeoutId.unref?.();

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: this.requestHeaders(),
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`${errorCode}:${response.status}`);
      }

      return response;
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(`${errorCode}:${cause}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async prepareExecution(
    intent: BrokerExecutionIntent,
  ): Promise<{ capabilityId: string; executePayload: Record<string, unknown> }> {
    const proofBindingMode = this.proofBindingMode ?? defaultProofBindingMode(this.brokerdBaseUrl);
    const loopbackBindingSecret = proofBindingMode === "loopback" ? randomUUID() : undefined;
    const dpopBinding = proofBindingMode === "dpop" ? await createDpopBindingMaterial() : undefined;
    const preview =
      intent.previewId || !this.previewBeforeExecute ? undefined : await this.previewIntent(intent);
    if (
      preview &&
      preview.approvalRequired &&
      preview.approvalState !== "approved" &&
      preview.approvalState !== "not_required"
    ) {
      throw new BrokerPreviewApprovalRequiredError(preview);
    }
    const capability = await this.issueCapability(
      intent,
      proofBindingMode === "loopback"
        ? {
            mode: "loopback",
            binding_sha256: sha256Hex(loopbackBindingSecret!),
          }
        : {
            mode: "dpop",
            key_thumbprint: dpopBinding!.keyThumbprint,
          },
      intent.previewId ?? preview?.previewId,
    );
    const executePayload: Record<string, unknown> = {
      capability: capability.capability,
      request: {
        url: intent.request.url,
        method: intent.request.method,
        headers: intent.request.headers ?? {},
        body: intent.request.body,
        body_sha256: intent.request.bodySha256,
      },
    };
    if (loopbackBindingSecret) {
      executePayload.binding_secret = loopbackBindingSecret;
    }
    if (dpopBinding) {
      executePayload.binding_proof = await createDpopBindingProof(
        dpopBinding,
        capability.capability_id,
        intent.request,
      );
    }

    return {
      capabilityId: capability.capability_id,
      executePayload,
    };
  }

  private requestHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.token) {
      headers.authorization = `Bearer ${this.token}`;
    }
    return headers;
  }
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

async function createDpopBindingMaterial(): Promise<DpopBindingMaterial> {
  const privateKey = randomBytes(32);
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  const publicKeyHex = bytesToHex(publicKey);
  return {
    privateKey,
    publicKeyHex,
    keyThumbprint: sha256Hex(publicKeyHex),
  };
}

async function createDpopBindingProof(
  material: DpopBindingMaterial,
  capabilityId: string,
  request: BrokerExecutionIntent["request"],
): Promise<ExecuteBindingProof> {
  const issuedAt = new Date().toISOString();
  const nonce = randomUUID();
  const message = bindingProofMessage(
    capabilityId,
    request.method,
    request.url,
    request.bodySha256,
    issuedAt,
    nonce,
  );
  const signature = await ed25519.signAsync(Buffer.from(message, "utf8"), material.privateKey);
  return {
    mode: "dpop",
    public_key: material.publicKeyHex,
    signature: bytesToHex(signature),
    issued_at: issuedAt,
    nonce,
  };
}

function defaultProofBindingMode(brokerdBaseUrl: string): BrokerProofBindingMode {
  try {
    const host = new URL(brokerdBaseUrl).hostname;
    return isLoopbackHost(host) ? "loopback" : "dpop";
  } catch {
    return "dpop";
  }
}

function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function bindingProofMessage(
  capabilityId: string,
  method: BrokerHttpMethod,
  url: string,
  bodySha256: string | undefined,
  issuedAt: string,
  nonce: string,
): string {
  return [
    `broker-capability:${capabilityId}`,
    `method:${method}`,
    `url:${url}`,
    `body-sha256:${bodySha256 ?? "-"}`,
    `issued-at:${issuedAt}`,
    `nonce:${nonce}`,
  ].join("\n");
}

function bytesToHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function normalizePreview(payload: BrokerPreviewResponse["preview"]): BrokerIntentPreview {
  return {
    previewId: payload.preview_id,
    provider: payload.provider,
    operation: payload.operation,
    summary: payload.summary,
    createdAt: payload.created_at,
    riskLevel: payload.risk_level,
    dataClasses: payload.data_classes ?? [],
    resources: payload.resources ?? [],
    egressHost: payload.egress_host,
    estimatedCostUsdMicros: payload.estimated_cost_usd_micros,
    approvalRequired: payload.approval_required,
    approvalState: payload.approval_state,
    approvedAt: payload.approved_at,
    approver: payload.approver,
  };
}
