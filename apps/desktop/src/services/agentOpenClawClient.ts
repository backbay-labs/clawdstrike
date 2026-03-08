import type { GatewayEventFrame } from "@/services/openclaw/gatewayProtocol";
import { isTauri, openclawAgentRequest } from "@/services/tauri";

export type AgentGatewayRuntime = {
  status: "disconnected" | "connecting" | "connected" | "error";
  last_error: string | null;
  connected_at_ms: number | null;
  last_message_at_ms: number | null;
  presence: unknown[];
  nodes: unknown[];
  devices: unknown;
  exec_approval_queue: unknown[];
};

export type AgentGatewayView = {
  id: string;
  label: string;
  gateway_url: string;
  has_token: boolean;
  has_device_token: boolean;
  runtime: AgentGatewayRuntime;
};

export type AgentGatewayListResponse = {
  active_gateway_id: string | null;
  gateways: AgentGatewayView[];
  secret_store_mode: "keyring" | "memory_fallback";
};

type AgentOpenClawEvent =
  | {
      type: "status";
      gateway_id: string;
      runtime: AgentGatewayRuntime;
    }
  | {
      type: "gateway_event";
      gateway_id: string;
      frame: GatewayEventFrame;
    };

type AgentAuthInfo = {
  baseUrl: string;
  token: string;
};

type ClientMode = { kind: "tauri" } | { kind: "http"; auth: AgentAuthInfo };

let cachedAuth: AgentAuthInfo | null = null;

async function resolveHttpAgentAuth(): Promise<AgentAuthInfo> {
  if (cachedAuth) return cachedAuth;

  const baseUrl = import.meta.env.VITE_AGENT_API_URL ?? "http://127.0.0.1:9878";
  const token = import.meta.env.VITE_AGENT_API_TOKEN ?? "";
  cachedAuth = { baseUrl, token };
  return cachedAuth;
}

function createJsonError(status: number, body: string): Error {
  const trimmed = body.trim();
  if (!trimmed) return new Error(`Agent API request failed (${status})`);
  return new Error(`Agent API request failed (${status}): ${trimmed}`);
}

function normalizeMethod(method?: string): "GET" | "POST" | "PATCH" | "PUT" | "DELETE" {
  const upper = (method ?? "GET").toUpperCase();
  switch (upper) {
    case "GET":
    case "POST":
    case "PATCH":
    case "PUT":
    case "DELETE":
      return upper;
    default:
      throw new Error(`Unsupported request method: ${upper}`);
  }
}

export class AgentOpenClawClient {
  private constructor(private readonly mode: ClientMode) {}

  static async create(): Promise<AgentOpenClawClient> {
    if (isTauri()) {
      return new AgentOpenClawClient({ kind: "tauri" });
    }

    const auth = await resolveHttpAgentAuth();
    if (!auth.token.trim()) {
      throw new Error("Agent local API token is unavailable");
    }

    return new AgentOpenClawClient({ kind: "http", auth });
  }

  private async request<T>(path: string, init?: RequestInit & { bodyJson?: unknown }): Promise<T> {
    if (this.mode.kind === "tauri") {
      return openclawAgentRequest<T>(normalizeMethod(init?.method), path, init?.bodyJson);
    }

    const headers = new Headers(init?.headers ?? {});
    headers.set("Authorization", `Bearer ${this.mode.auth.token}`);
    if (init?.bodyJson !== undefined) headers.set("Content-Type", "application/json");

    const response = await fetch(`${this.mode.auth.baseUrl}${path}`, {
      ...init,
      headers,
      body: init?.bodyJson === undefined ? init?.body : JSON.stringify(init.bodyJson),
    });

    if (!response.ok) {
      const body = await response.text();
      throw createJsonError(response.status, body);
    }

    const text = await response.text();
    if (!text) return null as T;
    return JSON.parse(text) as T;
  }

  async listGateways(): Promise<AgentGatewayListResponse> {
    return this.request<AgentGatewayListResponse>("/api/v1/openclaw/gateways");
  }

  async createGateway(payload: {
    label: string;
    gatewayUrl: string;
    token?: string;
    deviceToken?: string;
  }): Promise<AgentGatewayView> {
    return this.request<AgentGatewayView>("/api/v1/openclaw/gateways", {
      method: "POST",
      bodyJson: {
        label: payload.label,
        gateway_url: payload.gatewayUrl,
        token: payload.token,
        device_token: payload.deviceToken,
      },
    });
  }

  async patchGateway(
    id: string,
    payload: {
      label?: string;
      gatewayUrl?: string;
      token?: string;
      deviceToken?: string;
    },
  ): Promise<AgentGatewayView> {
    return this.request<AgentGatewayView>(`/api/v1/openclaw/gateways/${encodeURIComponent(id)}`, {
      method: "PATCH",
      bodyJson: {
        label: payload.label,
        gateway_url: payload.gatewayUrl,
        token: payload.token,
        device_token: payload.deviceToken,
      },
    });
  }

  async deleteGateway(id: string): Promise<void> {
    await this.request<void>(`/api/v1/openclaw/gateways/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  }

  async connectGateway(id: string): Promise<void> {
    await this.request(`/api/v1/openclaw/gateways/${encodeURIComponent(id)}/connect`, {
      method: "POST",
    });
  }

  async disconnectGateway(id: string): Promise<void> {
    await this.request(`/api/v1/openclaw/gateways/${encodeURIComponent(id)}/disconnect`, {
      method: "POST",
    });
  }

  async discover(timeoutMs?: number): Promise<unknown> {
    return this.request("/api/v1/openclaw/discover", {
      method: "POST",
      bodyJson: { timeout_ms: timeoutMs },
    });
  }

  async probe(timeoutMs?: number): Promise<unknown> {
    return this.request("/api/v1/openclaw/probe", {
      method: "POST",
      bodyJson: { timeout_ms: timeoutMs },
    });
  }

  async relayRequest<TPayload = unknown>(payload: {
    gatewayId: string;
    method: string;
    params?: unknown;
    timeoutMs?: number;
  }): Promise<TPayload> {
    return this.request<TPayload>("/api/v1/openclaw/request", {
      method: "POST",
      bodyJson: {
        gateway_id: payload.gatewayId,
        method: payload.method,
        params: payload.params,
        timeout_ms: payload.timeoutMs,
      },
    });
  }

  async importDesktopGateways(payload: {
    activeGatewayId?: string | null;
    gateways: Array<{
      id?: string;
      label: string;
      gatewayUrl: string;
      token?: string;
      deviceToken?: string;
    }>;
  }): Promise<{ imported: number; skipped: number }> {
    return this.request("/api/v1/openclaw/import-desktop-gateways", {
      method: "POST",
      bodyJson: {
        active_gateway_id: payload.activeGatewayId ?? null,
        gateways: payload.gateways.map((item) => ({
          id: item.id,
          label: item.label,
          gateway_url: item.gatewayUrl,
          token: item.token,
          device_token: item.deviceToken,
        })),
      },
    });
  }

  async updateActiveGateway(activeGatewayId: string | null): Promise<void> {
    await this.request("/api/v1/openclaw/active-gateway", {
      method: "PUT",
      bodyJson: {
        active_gateway_id: activeGatewayId,
      },
    });
  }

  subscribeEvents(
    onEvent: (event: AgentOpenClawEvent) => void,
    onError?: (error: Error) => void,
  ): () => void {
    const runtimeDigest = new Map<string, string>();
    let closed = false;
    let inFlight = false;

    const emitDiff = (payload: AgentGatewayListResponse) => {
      const seen = new Set<string>();
      for (const gateway of payload.gateways) {
        seen.add(gateway.id);
        const digest = JSON.stringify(gateway.runtime);
        if (runtimeDigest.get(gateway.id) === digest) continue;
        runtimeDigest.set(gateway.id, digest);
        onEvent({
          type: "status",
          gateway_id: gateway.id,
          runtime: gateway.runtime,
        });
      }

      for (const gatewayId of Array.from(runtimeDigest.keys())) {
        if (!seen.has(gatewayId)) runtimeDigest.delete(gatewayId);
      }
    };

    const poll = async () => {
      if (closed || inFlight) return;
      inFlight = true;
      try {
        emitDiff(await this.listGateways());
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        onError?.(new Error(`OpenClaw event sync failed: ${message}`));
      } finally {
        inFlight = false;
      }
    };

    const timer = setInterval(() => {
      void poll();
    }, 1000);

    return () => {
      closed = true;
      clearInterval(timer);
    };
  }
}
