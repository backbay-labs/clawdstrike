import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const openclawAgentRequestMock = vi.fn();

vi.mock("@/services/tauri", () => ({
  isTauri: () => true,
  openclawAgentRequest: openclawAgentRequestMock,
}));

function makeListPayload(status: "disconnected" | "connecting" | "connected" | "error") {
  return {
    active_gateway_id: "gw-1",
    secret_store_mode: "keyring",
    gateways: [
      {
        id: "gw-1",
        label: "Gateway",
        gateway_url: "ws://127.0.0.1:18789",
        has_token: true,
        has_device_token: false,
        runtime: {
          status,
          last_error: null,
          connected_at_ms: status === "connected" ? 100 : null,
          last_message_at_ms: status === "connected" ? 101 : null,
          presence: [],
          nodes: [],
          devices: null,
          exec_approval_queue: [],
        },
      },
    ],
  };
}

describe("AgentOpenClawClient", () => {
  beforeEach(() => {
    vi.resetModules();
    openclawAgentRequestMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends OpenClaw API requests through Tauri backend proxy", async () => {
    openclawAgentRequestMock.mockResolvedValue(makeListPayload("disconnected"));

    const { AgentOpenClawClient } = await import("./agentOpenClawClient");
    const client = await AgentOpenClawClient.create();
    await client.listGateways();

    expect(openclawAgentRequestMock).toHaveBeenCalledTimes(1);
    expect(openclawAgentRequestMock).toHaveBeenLastCalledWith(
      "GET",
      "/api/v1/openclaw/gateways",
      undefined,
    );
  });

  it("maps import-desktop-gateways payload fields to agent API schema", async () => {
    openclawAgentRequestMock.mockResolvedValue({ imported: 1, skipped: 0 });

    const { AgentOpenClawClient } = await import("./agentOpenClawClient");
    const client = await AgentOpenClawClient.create();
    const result = await client.importDesktopGateways({
      activeGatewayId: "gw-legacy",
      gateways: [
        {
          id: "gw-legacy",
          label: "Legacy",
          gatewayUrl: "ws://127.0.0.1:18789",
          token: "tok",
          deviceToken: "devtok",
        },
      ],
    });

    expect(result).toEqual({ imported: 1, skipped: 0 });
    expect(openclawAgentRequestMock).toHaveBeenCalledWith(
      "POST",
      "/api/v1/openclaw/import-desktop-gateways",
      {
        active_gateway_id: "gw-legacy",
        gateways: [
          {
            id: "gw-legacy",
            label: "Legacy",
            gateway_url: "ws://127.0.0.1:18789",
            token: "tok",
            device_token: "devtok",
          },
        ],
      },
    );
  });

  it("updates active gateway through scoped OpenClaw endpoint", async () => {
    openclawAgentRequestMock.mockResolvedValue({ ok: true, active_gateway_id: "gw-2" });

    const { AgentOpenClawClient } = await import("./agentOpenClawClient");
    const client = await AgentOpenClawClient.create();
    await client.updateActiveGateway("gw-2");

    expect(openclawAgentRequestMock).toHaveBeenCalledWith(
      "PUT",
      "/api/v1/openclaw/active-gateway",
      {
        active_gateway_id: "gw-2",
      },
    );
  });

  it("polls gateway runtime snapshots and emits status events on change", async () => {
    vi.useFakeTimers();
    openclawAgentRequestMock
      .mockResolvedValueOnce(makeListPayload("disconnected"))
      .mockResolvedValueOnce(makeListPayload("disconnected"))
      .mockResolvedValueOnce(makeListPayload("connected"));

    const { AgentOpenClawClient } = await import("./agentOpenClawClient");
    const client = await AgentOpenClawClient.create();

    const onEvent = vi.fn();
    const onError = vi.fn();
    const unsubscribe = client.subscribeEvents(onEvent, onError);

    await vi.advanceTimersByTimeAsync(1000);
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1000);
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1000);
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledTimes(2);
    expect(onError).toHaveBeenCalledTimes(0);

    unsubscribe();
  });
});
