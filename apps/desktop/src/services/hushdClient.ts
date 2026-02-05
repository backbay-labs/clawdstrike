/**
 * HushdClient - HTTP client for hushd daemon API
 */
import type {
  AuditEvent,
  AuditFilter,
  AuditResponse,
  AuditStats,
  ActionType,
} from "@/types/events";
import type { Policy, PolicyBundle, ValidationResult } from "@/types/policies";

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
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  guards: GuardEvalResult[];
}

export interface GuardEvalResult {
  guard_id: string;
  guard_name: string;
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  severity?: string;
  message?: string;
  duration_ms?: number;
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

  private async fetch<T>(
    path: string,
    options: RequestInit = {}
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
    const response = await this.fetch<ApiResponse<PolicyBundle>>("/api/v1/policy");
    return response.data;
  }

  async validatePolicy(yaml: string): Promise<ValidationResult> {
    const response = await fetch(`${this.baseUrl}/api/v1/policy/validate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-yaml",
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      },
      body: yaml,
    });
    const data = await response.json();
    return data.data ?? data;
  }

  async reloadPolicy(): Promise<void> {
    await this.fetch("/api/v1/policy/reload", { method: "POST" });
  }

  // === Check/Eval ===

  async check(request: CheckRequest): Promise<CheckResponse> {
    const response = await this.fetch<ApiResponse<CheckResponse>>("/api/v1/check", {
      method: "POST",
      body: JSON.stringify(request),
    });
    return response.data;
  }

  async eval(event: Record<string, unknown>): Promise<PolicyEvalResponse> {
    const response = await this.fetch<ApiResponse<PolicyEvalResponse>>("/api/v1/eval", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return response.data;
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
    const response = await this.fetch<ApiResponse<AuditResponse>>(path);
    return response.data;
  }

  async getAuditStats(): Promise<AuditStats> {
    const response = await this.fetch<ApiResponse<AuditStats>>("/api/v1/audit/stats");
    return response.data;
  }

  // === Sessions ===

  async createSession(agentId?: string): Promise<{ session_id: string }> {
    const response = await this.fetch<ApiResponse<{ session_id: string }>>("/api/v1/session", {
      method: "POST",
      body: JSON.stringify({ agent_id: agentId }),
    });
    return response.data;
  }

  async getSession(sessionId: string): Promise<Record<string, unknown>> {
    const response = await this.fetch<ApiResponse<Record<string, unknown>>>(
      `/api/v1/session/${sessionId}`
    );
    return response.data;
  }

  async terminateSession(sessionId: string): Promise<void> {
    await this.fetch(`/api/v1/session/${sessionId}`, { method: "DELETE" });
  }

  // === Agents ===

  async getAgents(): Promise<{ agents: unknown[] }> {
    const response = await this.fetch<ApiResponse<{ agents: unknown[] }>>("/api/v1/agents");
    return response.data;
  }

  async getDelegations(): Promise<{ delegations: unknown[] }> {
    const response = await this.fetch<ApiResponse<{ delegations: unknown[] }>>(
      "/api/v1/delegations"
    );
    return response.data;
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
