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
    const headers: Record<string, string> = {
      ...(init.headers as any),
      accept: "application/json",
    };
    if (this.userAgent) headers["user-agent"] = this.userAgent;
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;

    const resp = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers,
    });

    const text = await resp.text();
    const json = text ? JSON.parse(text) : undefined;

    if (!resp.ok) {
      const err: V1ErrorEnvelope | undefined = json;
      if (err?.error?.code) throw new ClawdstrikeError(resp.status, err.error);
      throw new Error(`HTTP ${resp.status}`);
    }

    return (json as V1Response<T>).data;
  }

  listCertifications(params?: Record<string, string | number | boolean | undefined>): Promise<any[]> {
    const qp = new URLSearchParams();
    for (const [k, v] of Object.entries(params ?? {})) {
      if (v === undefined) continue;
      qp.set(k, String(v));
    }
    const qs = qp.toString();
    return this.request<any[]>(`/v1/certifications${qs ? `?${qs}` : ""}`, { method: "GET" });
  }

  getCertification(certificationId: string): Promise<any> {
    return this.request<any>(`/v1/certifications/${encodeURIComponent(certificationId)}`, {
      method: "GET",
    });
  }

  verifyCertification(
    certificationId: string,
    body?: any
  ): Promise<any> {
    return this.request<any>(`/v1/certifications/${encodeURIComponent(certificationId)}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
  }

  createCertification(body: any): Promise<any> {
    return this.request<any>(`/v1/certifications`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  exportEvidence(certificationId: string, body: any): Promise<any> {
    return this.request<any>(
      `/v1/certifications/${encodeURIComponent(certificationId)}/evidence/export`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }
    );
  }

  getEvidenceExport(exportId: string): Promise<any> {
    return this.request<any>(`/v1/evidence-exports/${encodeURIComponent(exportId)}`, {
      method: "GET",
    });
  }
}

