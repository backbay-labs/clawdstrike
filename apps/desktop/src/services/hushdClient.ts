/**
 * HushdClient - HTTP client for hushd daemon API
 */
import type {
  AuditFilter,
  AuditResponse,
  AuditStats,
  ActionType,
} from "@/types/events";
import type { PolicyBundle, ValidationResult } from "@/types/policies";

export interface CheckRequest {
  action_type: ActionType;
  target: string;
  content?: string;
  args?: Record<string, unknown>;
  session_id?: string;
  agent_id?: string;
}

export interface CheckResponse {
  allowed: boolean;
  guard?: string;
  severity?: string;
  message?: string;
  details?: Record<string, unknown>;
}

export interface PolicyEvalResponse {
  version: number;
  command: "policy_eval";
  decision: {
    allowed: boolean;
    denied: boolean;
    warn: boolean;
    guard?: string;
    severity?: string;
    message?: string;
    reason?: string;
  };
  report?: {
    overall: GuardEvalResult;
    per_guard: GuardEvalResult[];
  };
}

export interface GuardEvalResult {
  guard: string;
  allowed: boolean;
  severity: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ApiResponse<T> {
  data: T;
  meta?: {
    requestId?: string;
    timestamp?: string;
    totalCount?: number;
  };
  links?: {
    self?: string;
    next?: string;
  };
}

export class HushdClient {
  constructor(
    private baseUrl: string,
    private token?: string
  ) {}

  private unwrapData<T>(payload: T | ApiResponse<T>): T {
    if (
      payload &&
      typeof payload === "object" &&
      "data" in payload &&
      (payload as { data?: unknown }).data !== undefined
    ) {
      return (payload as ApiResponse<T>).data;
    }
    return payload as T;
  }

  private async fetch<T>(
    path: string,
    options: Parameters<typeof fetch>[1] = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API error ${response.status}: ${error}`);
    }

    return response.json();
  }

  // === Health ===

  async health(): Promise<{ version: string; status: string }> {
    return this.fetch("/health");
  }

  // === Policy ===

  async getPolicy(): Promise<PolicyBundle> {
    const response = await this.fetch<PolicyBundle | ApiResponse<PolicyBundle>>("/api/v1/policy");
    return this.unwrapData(response);
  }

  async validatePolicy(yaml: string): Promise<ValidationResult> {
    void yaml;
    return {
      valid: false,
      errors: [
        {
          path: "policy",
          code: "unsupported_endpoint",
          message: "Daemon does not expose /api/v1/policy/validate",
        },
      ],
      warnings: [],
    };
  }

  async reloadPolicy(): Promise<void> {
    await this.fetch("/api/v1/policy/reload", { method: "POST" });
  }

  // === Check/Eval ===

  async check(request: CheckRequest): Promise<CheckResponse> {
    const response = await this.fetch<CheckResponse | ApiResponse<CheckResponse>>("/api/v1/check", {
      method: "POST",
      body: JSON.stringify(request),
    });
    return this.unwrapData(response);
  }

  async eval(event: Record<string, unknown>): Promise<PolicyEvalResponse> {
    const response = await this.fetch<PolicyEvalResponse | ApiResponse<PolicyEvalResponse>>("/api/v1/eval", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return this.unwrapData(response);
  }

  // === Audit ===

  async getAuditEvents(filter?: AuditFilter): Promise<AuditResponse> {
    const params = new URLSearchParams();
    if (filter) {
      Object.entries(filter).forEach(([key, value]) => {
        if (value !== undefined) {
          params.set(key, String(value));
        }
      });
    }
    const query = params.toString();
    const path = query ? `/api/v1/audit?${query}` : "/api/v1/audit";
    const response = await this.fetch<AuditResponse | ApiResponse<AuditResponse>>(path);
    return this.unwrapData(response);
  }

  async getAuditStats(): Promise<AuditStats> {
    const response = await this.fetch<AuditStats | ApiResponse<AuditStats>>("/api/v1/audit/stats");
    return this.unwrapData(response);
  }

  // === Sessions ===

  async createSession(agentId?: string): Promise<{ session_id: string }> {
    const response = await this.fetch<{ session_id: string } | ApiResponse<{ session_id: string }>>("/api/v1/session", {
      method: "POST",
      body: JSON.stringify({ agent_id: agentId }),
    });
    return this.unwrapData(response);
  }

  async getSession(sessionId: string): Promise<Record<string, unknown>> {
    const response = await this.fetch<Record<string, unknown> | ApiResponse<Record<string, unknown>>>(
      `/api/v1/session/${sessionId}`
    );
    return this.unwrapData(response);
  }

  async terminateSession(sessionId: string): Promise<void> {
    await this.fetch(`/api/v1/session/${sessionId}`, { method: "DELETE" });
  }

  // === Agents ===

  async getAgents(): Promise<{ agents: unknown[] }> {
    return { agents: [] };
  }

  async getDelegations(): Promise<{ delegations: unknown[] }> {
    return { delegations: [] };
  }
}

// Default client instance (can be replaced with configured instance)
let defaultClient: HushdClient | null = null;

export function getHushdClient(): HushdClient {
  if (!defaultClient) {
    defaultClient = new HushdClient("http://localhost:9876");
  }
  return defaultClient;
}

export function setHushdClient(client: HushdClient): void {
  defaultClient = client;
}

export function createHushdClient(baseUrl: string, token?: string): HushdClient {
  return new HushdClient(baseUrl, token);
}
