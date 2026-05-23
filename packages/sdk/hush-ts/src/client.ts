// API client for hushd v1 endpoints.
//
// Public surfaces here are typed to match the Rust serde definitions in
// `crates/services/hushd/src/api/certification.rs` and the related
// `hush_certification` crate. Server responses use camelCase serialization;
// these interfaces mirror that.
//
// Runtime validation here is intentionally lightweight: each method runs a
// thin shape check (`isV1ResponseEnvelope`) to fail closed if the server
// returns something unexpected, then returns the inner `data` field. This
// keeps `Promise<any>` out of the public surface without pulling in a
// schema library.

export interface ClawdstrikeClientOptions {
  baseUrl: string; // e.g. https://api.openclaw.dev
  token?: string; // Bearer token
  userAgent?: string;
}

export interface V1Meta {
  requestId: string;
  timestamp?: string;
  totalCount?: number;
}

export interface V1Links {
  self?: string;
  next?: string;
  // Discoverability links emitted by hushd for some resources. Strict typing
  // here would require duplicating the server-side link map; allow extra
  // string fields by keeping `Record<string, string | undefined>`.
  [link: string]: string | undefined;
}

export interface V1Response<T> {
  data: T;
  meta: V1Meta;
  links?: V1Links;
}

export interface V1ErrorBody {
  code: string;
  message: string;
  details?: unknown;
  requestId: string;
  retryAfter?: number;
}

export interface V1ErrorEnvelope {
  error: V1ErrorBody;
}

export class ClawdstrikeError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly requestId?: string;
  public readonly details?: unknown;
  public readonly retryAfter?: number;

  constructor(status: number, err: V1ErrorBody) {
    super(err.message);
    this.name = "ClawdstrikeError";
    this.status = status;
    this.code = err.code;
    this.requestId = err.requestId;
    this.details = err.details;
    this.retryAfter = err.retryAfter;
  }
}

// =============================================================================
// Certification domain types — mirror crates/libs/hush-certification.
// =============================================================================

export type CertificationTier = "certified" | "silver" | "gold" | "platinum";
export type CertificationStatus = "active" | "expired" | "revoked";

export interface CertificationSubject {
  /** Subject type tag, e.g. "agent", "org". Serialized as `type` server-side. */
  type: string;
  id: string;
  name: string;
  organizationId?: string;
  metadata?: Record<string, unknown>;
}

export interface CertificationPolicyBinding {
  hash: string;
  version: string;
  ruleset?: string;
}

export interface CertificationEvidenceBinding {
  receiptCount: number;
  merkleRoot?: string;
  auditLogRef?: string;
  lastUpdated?: string;
}

export interface CertificationIssuer {
  id: string;
  name: string;
  publicKey: string;
  signature: string;
  signedAt: string;
}

export interface CertificationIssuerSummary {
  id: string;
  name: string;
}

export interface CertificationSummary {
  tier: CertificationTier;
  issueDate: string;
  expiryDate: string;
  frameworks: string[];
  status: CertificationStatus;
}

export interface CertificationPolicySummary {
  hash: string;
  version: string;
  ruleset?: string;
}

export interface CertificationListItem {
  certificationId: string;
  subject: CertificationSubject;
  certification: CertificationSummary;
  policy: CertificationPolicySummary;
  issuer: CertificationIssuerSummary;
}

export interface CertificationDetail {
  certificationId: string;
  version: string;
  subject: CertificationSubject;
  certification: CertificationSummary;
  policy: CertificationPolicySummary;
  evidence: CertificationEvidenceBinding;
  issuer: CertificationIssuer;
}

export interface CreateCertificationInput {
  subject: CertificationSubject;
  tier: CertificationTier;
  frameworks: string[];
  policy: CertificationPolicyBinding;
  evidence?: CertificationEvidenceBinding;
  validityDays?: number;
}

export interface CreateCertificationResult {
  certificationId: string;
  status: CertificationStatus;
  issueDate: string;
  expiryDate: string;
}

export interface VerificationContext {
  requiredTier?: CertificationTier;
  requiredFrameworks?: string[];
  checkRevocation?: boolean;
  checkExpiry?: boolean;
}

export interface VerifyCertificationRequest {
  verificationContext?: VerificationContext;
}

export interface VerifyCheck {
  passed: boolean;
  reason?: string;
  daysRemaining?: number;
  actual?: unknown;
  required?: unknown;
}

export interface VerifyChecks {
  signature: VerifyCheck;
  expiry: VerifyCheck;
  revocation: VerifyCheck;
  tierRequirement: VerifyCheck;
  frameworkRequirement: VerifyCheck;
}

export interface VerifyCertificationData {
  valid: boolean;
  certificationId: string;
  subject?: CertificationSubject;
  tier?: CertificationTier;
  status?: CertificationStatus;
  checks: VerifyChecks;
  failureReasons?: string[];
  verifiedAt: string;
}

export interface EvidenceExportDateRange {
  start: string;
  end: string;
}

export interface ExportEvidenceRequest {
  /** Only `"zip"` is currently accepted by hushd. */
  format?: "zip";
  dateRange?: EvidenceExportDateRange;
  includeTypes?: string[];
  complianceTemplate?: string;
  notifyEmail?: string;
}

export type EvidenceExportStatusEnum = "processing" | "completed" | "failed";

export interface ExportEvidenceResponse {
  exportId: string;
  status: EvidenceExportStatusEnum;
  estimatedSize?: number;
  estimatedCompletion?: string;
}

export interface EvidenceExportStatus {
  exportId: string;
  status: EvidenceExportStatusEnum;
  downloadUrl?: string;
  expiresAt?: string;
  size?: number;
  /** Hash string, formatted as `sha256:<hex>` when present. */
  hash?: string;
}

export interface ListCertificationsParams {
  organizationId?: string;
  agentId?: string;
  tier?: CertificationTier;
  status?: CertificationStatus;
  framework?: string;
  limit?: number;
  cursor?: string;
}

// =============================================================================
// Runtime shape checks (fail-closed on malformed responses)
// =============================================================================

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isV1ResponseEnvelope(value: unknown): value is V1Response<unknown> {
  if (!isRecord(value)) return false;
  if (!("data" in value)) return false;
  const meta = (value as { meta?: unknown }).meta;
  if (!isRecord(meta)) return false;
  if (typeof (meta as { requestId?: unknown }).requestId !== "string") return false;
  return true;
}

function isV1ErrorEnvelope(value: unknown): value is V1ErrorEnvelope {
  if (!isRecord(value)) return false;
  const err = (value as { error?: unknown }).error;
  if (!isRecord(err)) return false;
  return typeof err.code === "string" && typeof err.message === "string";
}

export class ClawdstrikeClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly userAgent?: string;

  constructor(opts: ClawdstrikeClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.userAgent = opts.userAgent;
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const incomingHeaders: Record<string, string> = isRecord(init.headers)
      ? (init.headers as Record<string, string>)
      : {};
    const headers: Record<string, string> = {
      ...incomingHeaders,
      accept: "application/json",
    };
    if (this.userAgent) headers["user-agent"] = this.userAgent;
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;

    const resp = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers,
    });

    const text = await resp.text();
    let json: unknown;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch (e) {
        throw new Error(
          `Failed to parse response body from ${path}: ${(e as Error).message}`,
        );
      }
    }

    if (!resp.ok) {
      if (isV1ErrorEnvelope(json)) {
        throw new ClawdstrikeError(resp.status, json.error);
      }
      throw new Error(`HTTP ${resp.status}`);
    }

    if (!isV1ResponseEnvelope(json)) {
      throw new Error(
        `Malformed v1 response from ${path}: missing data/meta envelope`,
      );
    }

    return json.data as T;
  }

  listCertifications(params?: ListCertificationsParams): Promise<CertificationListItem[]> {
    const qp = new URLSearchParams();
    if (params) {
      const mapping: Record<string, string | number | undefined> = {
        organization_id: params.organizationId,
        agent_id: params.agentId,
        tier: params.tier,
        status: params.status,
        framework: params.framework,
        limit: params.limit,
        cursor: params.cursor,
      };
      for (const [k, v] of Object.entries(mapping)) {
        if (v === undefined) continue;
        qp.set(k, String(v));
      }
    }
    const qs = qp.toString();
    return this.request<CertificationListItem[]>(
      `/v1/certifications${qs ? `?${qs}` : ""}`,
      { method: "GET" },
    );
  }

  getCertification(certificationId: string): Promise<CertificationDetail> {
    return this.request<CertificationDetail>(
      `/v1/certifications/${encodeURIComponent(certificationId)}`,
      { method: "GET" },
    );
  }

  verifyCertification(
    certificationId: string,
    body?: VerifyCertificationRequest,
  ): Promise<VerifyCertificationData> {
    return this.request<VerifyCertificationData>(
      `/v1/certifications/${encodeURIComponent(certificationId)}/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body ?? {}),
      },
    );
  }

  createCertification(body: CreateCertificationInput): Promise<CreateCertificationResult> {
    return this.request<CreateCertificationResult>(`/v1/certifications`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  exportEvidence(
    certificationId: string,
    body: ExportEvidenceRequest,
  ): Promise<ExportEvidenceResponse> {
    return this.request<ExportEvidenceResponse>(
      `/v1/certifications/${encodeURIComponent(certificationId)}/evidence/export`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
    );
  }

  getEvidenceExport(exportId: string): Promise<EvidenceExportStatus> {
    return this.request<EvidenceExportStatus>(
      `/v1/evidence-exports/${encodeURIComponent(exportId)}`,
      { method: "GET" },
    );
  }
}
