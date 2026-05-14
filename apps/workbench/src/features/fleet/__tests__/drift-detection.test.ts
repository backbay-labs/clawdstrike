import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock http-transport -- this is used by jsonFetch inside fleet-client.ts
const mockHttpFetch = vi.fn();
vi.mock("@/lib/workbench/http-transport", () => ({
  httpFetch: (...args: unknown[]) => mockHttpFetch(...args),
}));

// Mock fleet-url-policy
vi.mock("@/features/fleet/fleet-url-policy", () => ({
  isPrivateOrLoopbackFleetHostname: vi.fn(() => false),
  validateFleetUrl: vi.fn(() => ({ valid: true })),
}));

// Mock swarm-protocol
vi.mock("@/features/swarm/swarm-protocol", () => ({
  isHeadAnnouncement: vi.fn(() => false),
  isHubConfig: vi.fn(() => false),
}));

// Mock yaml-utils
vi.mock("@/features/policy/yaml-utils", () => ({
  yamlToPolicy: vi.fn(() => ({})),
}));

// Mock secure-store
vi.mock("@/features/settings/secure-store", () => ({
  secureStore: {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue(undefined),
    remove: vi.fn().mockResolvedValue(undefined),
    isSecure: vi.fn().mockResolvedValue(false),
  },
}));

import { fetchAgentList, type FleetConnection } from "@/features/fleet/fleet-client";

// ---- Helpers ----

function makeConn(overrides: Partial<FleetConnection> = {}): FleetConnection {
  return {
    hushdUrl: "http://localhost:9876",
    controlApiUrl: "",
    apiKey: "test-key",
    controlApiToken: "",
    connected: true,
    hushdHealth: null,
    agentCount: 0,
    ...overrides,
  };
}

function makeAgentResponse() {
  return JSON.stringify({
    generated_at: "2026-03-19T10:00:00Z",
    stale_after_secs: 90,
    endpoints: [
      {
        endpoint_agent_id: "agent-1",
        last_heartbeat_at: "2026-03-19T10:00:00Z",
        online: true,
        seconds_since_heartbeat: 10,
        drift: { policy_drift: false, daemon_drift: false, stale: false },
      },
    ],
    runtimes: [],
  });
}

describe("fetchAgentList drift detection", () => {
  let capturedUrl: string | undefined;

  beforeEach(() => {
    capturedUrl = undefined;

    // httpFetch is the low-level fetch used by jsonFetch. We intercept it
    // to capture the URL fleet-client builds. Returns a real Response object
    // so readResponseTextWithLimit can read the body.
    mockHttpFetch.mockImplementation(async (url: string) => {
      capturedUrl = url;
      const body = makeAgentResponse();
      return new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("with remotePolicyVersion appends expected_policy_version to the URL", async () => {
    const conn = makeConn();
    await fetchAgentList(conn, { expectedPolicyVersion: "sha256:abc" });

    expect(capturedUrl).toBeDefined();
    expect(capturedUrl).toContain("expected_policy_version=");
    expect(capturedUrl).toContain("sha256");
  });

  it("without remotePolicyVersion does NOT add expected_policy_version param", async () => {
    const conn = makeConn();
    await fetchAgentList(conn);

    expect(capturedUrl).toBeDefined();
    expect(capturedUrl).not.toContain("expected_policy_version");
  });

  it("includes both include_stale=true AND expected_policy_version when both are present", async () => {
    const conn = makeConn();
    await fetchAgentList(conn, { expectedPolicyVersion: "sha256:abc" });

    expect(capturedUrl).toBeDefined();
    expect(capturedUrl).toContain("include_stale=true");
    expect(capturedUrl).toContain("expected_policy_version=");
  });
});
