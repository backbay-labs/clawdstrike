// ---------------------------------------------------------------------------
// Fleet Client E2E Tests — uses MSW mock server
// ---------------------------------------------------------------------------
//
// The fleet-client uses import.meta.env.DEV (true in Vitest) which causes
// proxyUrl() to rewrite absolute URLs to /_proxy/hushd/* and /_proxy/control/*.
// The mock server handles both proxy and direct paths.
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from "vitest";
import {
  mockFleetServer,
  MOCK_DATA,
  injectError,
  injectPostError,
  injectBareArrayAuditResponse,
  injectGrantsData,
  injectEmptyApprovals,
} from "@/test/mock-fleet-server";
import {
  testConnection,
  fetchAgentList,
  fetchAuditEvents,
  deployPolicy,
  validateRemotely,
  fetchRemotePolicy,
  fetchAgentCount,
  fetchApprovals,
  resolveApproval,
  distributePolicy,
  fetchDelegationGraphFromApi,
  fleetClient,
  loadSavedConnection,
  saveConnectionConfig,
  clearConnectionConfig,
  type FleetConnection,
} from "../fleet-client";

// ---- MSW lifecycle ----

beforeAll(() => mockFleetServer.listen({ onUnhandledRequest: "warn" }));
afterEach(() => mockFleetServer.resetHandlers());
afterAll(() => mockFleetServer.close());

// ---- Helpers ----

/** A standard FleetConnection pointing to our mock hushd + control-api. */
function makeConn(overrides?: Partial<FleetConnection>): FleetConnection {
  return {
    hushdUrl: "http://localhost:9876",
    controlApiUrl: "http://localhost:9877",
    apiKey: "test-api-key",
    controlApiToken: "test-control-token",
    connected: true,
    hushdHealth: null,
    agentCount: 0,
    ...overrides,
  };
}

// ---- Tests ----

describe("testConnection", () => {
  it("returns health response on success", async () => {
    const health = await testConnection("http://localhost:9876", "test-key");
    expect(health).toMatchObject({
      status: "healthy",
      version: "0.2.5-test",
    });
    expect(health.uptime_secs).toBe(3600);
  });

  it("strips trailing slashes from URL", async () => {
    // proxyUrl sees the URL and rewrites it; trailing slashes should be stripped
    const health = await testConnection("http://localhost:9876///", "test-key");
    expect(health.status).toBe("healthy");
  });

  it("throws on network error", async () => {
    injectError("/_proxy/hushd/health", 500);
    await expect(
      testConnection("http://localhost:9876", "test-key"),
    ).rejects.toThrow();
  });

  it("throws on non-200 status", async () => {
    injectError("/_proxy/hushd/health", 503);
    await expect(
      testConnection("http://localhost:9876", "test-key"),
    ).rejects.toThrow();
  });
});

describe("fetchAgentList", () => {
  it("returns agent list from hushd", async () => {
    const conn = makeConn();
    const agents = await fetchAgentList(conn);

    expect(agents).toHaveLength(MOCK_DATA.agents.endpoints.length);
    expect(agents[0].endpoint_agent_id).toBe("agent-test-001");
    expect(agents[0].online).toBe(true);
    expect(agents[0].drift.policy_drift).toBe(false);
  });

  it("contains both online and offline agents", async () => {
    const agents = await fetchAgentList(makeConn());
    const onlineCount = agents.filter((a) => a.online).length;
    const offlineCount = agents.filter((a) => !a.online).length;
    expect(onlineCount).toBeGreaterThan(0);
    expect(offlineCount).toBeGreaterThan(0);
  });

  it("returns empty array on auth failure (401)", async () => {
    // With no apiKey and no controlApiUrl, hushd returns 401 and fallback
    // to control-api also has no auth, so we get an empty array.
    const conn = makeConn({ apiKey: "", controlApiUrl: "" });
    const agents = await fetchAgentList(conn);
    expect(agents).toEqual([]);
  });

  it("falls back to control-api when hushd fails", async () => {
    // Inject a failure on the hushd agent endpoint
    injectError("/_proxy/hushd/api/v1/agents/status", 500);

    const conn = makeConn();
    const agents = await fetchAgentList(conn);

    // The control-api fallback returns agents with a different shape,
    // but fetchAgentList maps them. The response length should match.
    expect(agents).toHaveLength(MOCK_DATA.agents.endpoints.length);
  });

  it("returns empty array when hushd fails and no control-api configured", async () => {
    injectError("/_proxy/hushd/api/v1/agents/status", 500);

    const conn = makeConn({ controlApiUrl: "" });
    const agents = await fetchAgentList(conn);
    expect(agents).toEqual([]);
  });

  it("throws when both hushd and control-api fail", async () => {
    injectError("/_proxy/hushd/api/v1/agents/status", 500);
    injectError("/_proxy/control/api/v1/agents", 500);

    const conn = makeConn();
    await expect(fetchAgentList(conn)).rejects.toThrow();
  });
});

describe("fetchAgentCount", () => {
  it("returns number of agents", async () => {
    const count = await fetchAgentCount(makeConn());
    expect(count).toBe(MOCK_DATA.agents.endpoints.length);
  });

  it("returns 0 when request fails", async () => {
    injectError("/_proxy/hushd/api/v1/agents/status", 500);
    injectError("/_proxy/control/api/v1/agents", 500);
    const count = await fetchAgentCount(makeConn());
    expect(count).toBe(0);
  });
});

describe("fetchAuditEvents", () => {
  it("returns events array", async () => {
    const events = await fetchAuditEvents(makeConn());
    expect(events).toHaveLength(MOCK_DATA.auditEvents.length);
    expect(events[0].id).toBe("evt-001");
    expect(events[0].decision).toBe("deny");
    expect(events[0].guard).toBe("ForbiddenPathGuard");
  });

  it("returns events with varied severities and decisions", async () => {
    const events = await fetchAuditEvents(makeConn());
    const decisions = new Set(events.map((e) => e.decision));
    expect(decisions.has("allow")).toBe(true);
    expect(decisions.has("deny")).toBe(true);

    const guards = new Set(events.map((e) => e.guard));
    expect(guards.size).toBeGreaterThan(3);
  });

  it("handles { events: [...] } response shape", async () => {
    // Default mock returns { events: [...] } shape
    const events = await fetchAuditEvents(makeConn());
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);
  });

  it("handles bare array response shape", async () => {
    injectBareArrayAuditResponse();
    const events = await fetchAuditEvents(makeConn());
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBe(MOCK_DATA.auditEvents.length);
  });

  it("supports filter parameters", async () => {
    // Filters are passed as query params — the mock server doesn't filter,
    // but we verify the function doesn't break with filters set.
    const events = await fetchAuditEvents(makeConn(), {
      since: "2026-01-01T00:00:00Z",
      until: "2026-12-31T23:59:59Z",
      action_type: "file_read",
      decision: "deny",
      agent_id: "agent-test-001",
      limit: 5,
    });
    expect(Array.isArray(events)).toBe(true);
  });

  it("throws on auth failure", async () => {
    const conn = makeConn({ apiKey: "" });
    await expect(fetchAuditEvents(conn)).rejects.toThrow();
  });
});

describe("deployPolicy", () => {
  it("returns success with hash on 200", async () => {
    const result = await deployPolicy(
      makeConn(),
      'schema_version: "1.2.0"\nname: test\n',
    );
    expect(result.success).toBe(true);
    expect(result.hash).toBe("sha256:deployed123");
    expect(result.error).toBeUndefined();
  });

  it("returns error on failure", async () => {
    injectPostError("/_proxy/hushd/api/v2/policy", 500);
    const result = await deployPolicy(makeConn(), "bad yaml");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns error on auth failure", async () => {
    const result = await deployPolicy(
      makeConn({ apiKey: "" }),
      'schema_version: "1.2.0"\n',
    );
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe("validateRemotely", () => {
  it("returns valid=true for valid policy", async () => {
    const result = await validateRemotely(
      makeConn(),
      'schema_version: "1.2.0"\nname: test\nextends: strict\n',
    );
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("returns valid=false with errors for invalid policy", async () => {
    const result = await validateRemotely(
      makeConn(),
      "name: test\nextends: strict\n",
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Missing schema_version");
  });

  it("returns warnings array", async () => {
    const result = await validateRemotely(
      makeConn(),
      'schema_version: "1.2.0"\nname: test\n',
    );
    expect(result).toHaveProperty("warnings");
    expect(Array.isArray(result.warnings)).toBe(true);
  });
});

describe("fetchRemotePolicy", () => {
  it("returns policy yaml and metadata", async () => {
    const result = await fetchRemotePolicy(makeConn());
    expect(result.yaml).toContain("schema_version");
    expect(result.yaml).toContain("test-policy");
    expect(result.name).toBe("test-policy");
    expect(result.version).toBe("1.0.0");
    expect(result.policyHash).toBe("sha256:test123456789");
  });

  it("throws on auth failure", async () => {
    await expect(fetchRemotePolicy(makeConn({ apiKey: "" }))).rejects.toThrow();
  });
});

describe("proxyUrl (tested indirectly)", () => {
  // proxyUrl is a private function that rewrites absolute URLs in dev mode.
  // We verify it works correctly through the public API: in Vitest,
  // import.meta.env.DEV is true, so URLs get rewritten to /_proxy/* paths.
  // If proxyUrl were broken, all the above tests would fail.

  it("rewrites absolute URL to proxy path in dev mode", async () => {
    // The fact that testConnection("http://localhost:9876", ...) succeeds
    // proves proxyUrl rewrites to /_proxy/hushd/health (our mock endpoint).
    const health = await testConnection("http://localhost:9876", "test-key");
    expect(health.status).toBe("healthy");
  });

  it("preserves query parameters through proxy rewrite", async () => {
    // fetchAgentList appends ?include_stale=true to the URL.
    // If query params were lost, the mock wouldn't receive the right path.
    const agents = await fetchAgentList(makeConn());
    expect(agents.length).toBeGreaterThan(0);
  });
});

describe("fetchApprovals", () => {
  it("returns requests and decisions from control-api", async () => {
    const conn = makeConn();
    const result = await fetchApprovals(conn);

    expect(result.requests).toHaveLength(MOCK_DATA.approvalRequests.length);
    expect(result.decisions).toHaveLength(MOCK_DATA.approvalDecisions.length);
    expect(result.requests[0].id).toBe("apr-001");
    expect(result.requests[0].toolName).toBe("shell_exec");
    expect(result.requests[0].status).toBe("pending");
    expect(result.requests[0].originContext.provider).toBe("slack");
  });

  it("returns second request with github origin", async () => {
    const result = await fetchApprovals(makeConn());
    expect(result.requests[1].id).toBe("apr-002");
    expect(result.requests[1].originContext.provider).toBe("github");
    expect(result.requests[1].riskLevel).toBe("medium");
  });

  it("returns empty arrays when no approvals exist", async () => {
    injectEmptyApprovals();
    const result = await fetchApprovals(makeConn());
    expect(result.requests).toEqual([]);
    expect(result.decisions).toEqual([]);
  });

  it("falls back to hushd URL when controlApiUrl is not set", async () => {
    // When controlApiUrl is empty, fetchApprovals uses hushdUrl with kind "hushd"
    // Our mock doesn't have a hushd approvals endpoint, so this will throw.
    // This tests the fallback URL selection logic.
    const conn = makeConn({ controlApiUrl: "" });
    await expect(fetchApprovals(conn)).rejects.toThrow();
  });

  it("throws on auth failure", async () => {
    const conn = makeConn({ apiKey: "", controlApiToken: "" });
    await expect(fetchApprovals(conn)).rejects.toThrow();
  });

  it("throws on server error", async () => {
    injectError("/_proxy/control/api/v1/approvals", 500);
    await expect(fetchApprovals(makeConn())).rejects.toThrow();
  });
});

describe("resolveApproval", () => {
  it("returns success when approving a request", async () => {
    const result = await resolveApproval(makeConn(), "apr-001", "approved");
    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("returns success when denying a request", async () => {
    const result = await resolveApproval(makeConn(), "apr-001", "denied");
    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("passes scope and reason options", async () => {
    const result = await resolveApproval(makeConn(), "apr-001", "approved", {
      scope: { ttlSeconds: 300, threadOnly: true },
      reason: "One-time exception for deploy",
    });
    expect(result.success).toBe(true);
  });

  it("returns error when request not found (404)", async () => {
    const result = await resolveApproval(makeConn(), "nonexistent", "approved");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns error on server failure", async () => {
    injectPostError("/_proxy/control/api/v1/approvals/apr-001/resolve", 500);
    const result = await resolveApproval(makeConn(), "apr-001", "approved");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns error on auth failure", async () => {
    const conn = makeConn({ apiKey: "", controlApiToken: "" });
    const result = await resolveApproval(conn, "apr-001", "denied");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("falls back to hushd URL when controlApiUrl is not set", async () => {
    // Without controlApiUrl, resolve uses hushdUrl — no mock handler for that
    const conn = makeConn({ controlApiUrl: "" });
    const result = await resolveApproval(conn, "apr-001", "approved");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe("distributePolicy", () => {
  it("returns success with hash on 200", async () => {
    const result = await distributePolicy(
      makeConn(),
      'schema_version: "1.2.0"\nname: test\n',
    );
    expect(result.success).toBe(true);
    expect(result.hash).toBe("sha256:distributed456");
    expect(result.error).toBeUndefined();
  });

  it("returns error when controlApiUrl is not configured", async () => {
    const result = await distributePolicy(
      makeConn({ controlApiUrl: "" }),
      'schema_version: "1.2.0"\n',
    );
    expect(result.success).toBe(false);
    expect(result.error).toBe("Control API URL not configured");
  });

  it("returns error on server failure", async () => {
    injectPostError("/_proxy/control/api/v1/policy/distribute", 500);
    const result = await distributePolicy(makeConn(), "some yaml");
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns error on auth failure", async () => {
    const conn = makeConn({ apiKey: "", controlApiToken: "" });
    const result = await distributePolicy(
      conn,
      'schema_version: "1.2.0"\n',
    );
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe("fetchDelegationGraphFromApi", () => {
  it("returns null when controlApiUrl is not configured", async () => {
    const result = await fetchDelegationGraphFromApi(makeConn({ controlApiUrl: "" }));
    expect(result).toBeNull();
  });

  it("returns null when grants endpoint returns empty array", async () => {
    // Default mock returns [] for grants
    const result = await fetchDelegationGraphFromApi(makeConn());
    expect(result).toBeNull();
  });

  it("builds delegation graph from grants data", async () => {
    injectGrantsData();
    const result = await fetchDelegationGraphFromApi(makeConn());

    expect(result).not.toBeNull();
    // MOCK_GRANTS has 2 grants with 3 unique principals:
    //   principal-root, principal-agent-001 (appears as both issuer and subject),
    //   principal-agent-002
    // Plus 2 grant nodes = 5 total nodes
    expect(result!.nodes).toHaveLength(5);
    // Each grant produces 2 edges (IssuedGrant + ReceivedGrant) = 4 edges
    expect(result!.edges).toHaveLength(4);
  });

  it("produces correct node kinds from grants", async () => {
    injectGrantsData();
    const result = await fetchDelegationGraphFromApi(makeConn());

    const principalNodes = result!.nodes.filter((n) => n.kind === "Principal");
    const grantNodes = result!.nodes.filter((n) => n.kind === "Grant");
    expect(principalNodes).toHaveLength(3);
    expect(grantNodes).toHaveLength(2);
  });

  it("produces correct edge kinds from grants", async () => {
    injectGrantsData();
    const result = await fetchDelegationGraphFromApi(makeConn());

    const issuedEdges = result!.edges.filter((e) => e.kind === "IssuedGrant");
    const receivedEdges = result!.edges.filter((e) => e.kind === "ReceivedGrant");
    expect(issuedEdges).toHaveLength(2);
    expect(receivedEdges).toHaveLength(2);
  });

  it("preserves grant metadata (depth, status, purpose, capabilities)", async () => {
    injectGrantsData();
    const result = await fetchDelegationGraphFromApi(makeConn());

    const grantNode = result!.nodes.find((n) => n.id === "grant-grant-001");
    expect(grantNode).toBeDefined();
    expect(grantNode!.label).toBe("delegation");
    expect(grantNode!.metadata?.depth).toBe(1);
    expect(grantNode!.metadata?.status).toBe("active");
    expect(grantNode!.metadata?.purpose).toBe("Code review automation");
    expect(grantNode!.metadata?.capabilities).toEqual(["FileRead", "FileWrite"]);
  });

  it("deduplicates principal nodes that appear in multiple grants", async () => {
    injectGrantsData();
    const result = await fetchDelegationGraphFromApi(makeConn());

    // principal-agent-001 is both subject in grant-001 and issuer in grant-002
    const agent001Nodes = result!.nodes.filter((n) => n.id === "principal-agent-001");
    expect(agent001Nodes).toHaveLength(1);
  });

  it("returns null on server error (does not throw)", async () => {
    injectError("/_proxy/control/api/v1/grants", 500);
    const result = await fetchDelegationGraphFromApi(makeConn());
    expect(result).toBeNull();
  });

  it("returns null on auth failure (does not throw)", async () => {
    const conn = makeConn({ apiKey: "", controlApiToken: "" });
    const result = await fetchDelegationGraphFromApi(conn);
    expect(result).toBeNull();
  });
});

describe("fleetClient convenience object", () => {
  // The fleetClient methods use savedConnection() which reads localStorage,
  // so we need the localStorage mock here too.
  let fleetLsStore: Record<string, string>;

  const fleetLocalStorageMock = {
    getItem: (key: string) => fleetLsStore[key] ?? null,
    setItem: (key: string, value: string) => { fleetLsStore[key] = value; },
    removeItem: (key: string) => { delete fleetLsStore[key]; },
    clear: () => { fleetLsStore = {}; },
    get length() { return Object.keys(fleetLsStore).length; },
    key: (index: number) => Object.keys(fleetLsStore)[index] ?? null,
  };

  function seedLocalStorage() {
    fleetLsStore["clawdstrike_hushd_url"] = "http://localhost:9876";
    fleetLsStore["clawdstrike_control_api_url"] = "http://localhost:9877";
    fleetLsStore["clawdstrike_api_key"] = "test-api-key";
    fleetLsStore["clawdstrike_control_api_token"] = "test-control-token";
  }

  beforeEach(() => {
    fleetLsStore = {};
    vi.stubGlobal("localStorage", fleetLocalStorageMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("healthCheck", () => {
    it("returns true when hushd is reachable", async () => {
      seedLocalStorage();
      const ok = await fleetClient.healthCheck();
      expect(ok).toBe(true);
    });

    it("returns false when no hushdUrl is saved", async () => {
      // localStorage is empty => hushdUrl is ""
      const ok = await fleetClient.healthCheck();
      expect(ok).toBe(false);
    });

    it("returns false when hushd is unreachable", async () => {
      seedLocalStorage();
      injectError("/_proxy/hushd/health", 500);
      const ok = await fleetClient.healthCheck();
      expect(ok).toBe(false);
    });
  });

  describe("fetchDelegationGraph", () => {
    it("returns null when no controlApiUrl is saved", async () => {
      fleetLsStore["clawdstrike_hushd_url"] = "http://localhost:9876";
      // controlApiUrl not set
      const graph = await fleetClient.fetchDelegationGraph();
      expect(graph).toBeNull();
    });

    it("returns null when grants are empty", async () => {
      seedLocalStorage();
      const graph = await fleetClient.fetchDelegationGraph();
      expect(graph).toBeNull();
    });

    it("returns graph when grants data is available", async () => {
      seedLocalStorage();
      injectGrantsData();
      const graph = await fleetClient.fetchDelegationGraph();
      expect(graph).not.toBeNull();
      expect(graph!.nodes.length).toBeGreaterThan(0);
      expect(graph!.edges.length).toBeGreaterThan(0);
    });
  });

  describe("fetchApprovals", () => {
    it("returns null when no connection URLs are saved", async () => {
      // localStorage is empty
      const result = await fleetClient.fetchApprovals();
      expect(result).toBeNull();
    });

    it("returns approvals when connection is configured", async () => {
      seedLocalStorage();
      const result = await fleetClient.fetchApprovals();
      expect(result).not.toBeNull();
      expect(result!.requests).toHaveLength(MOCK_DATA.approvalRequests.length);
    });

    it("returns null on server error (does not throw)", async () => {
      seedLocalStorage();
      injectError("/_proxy/control/api/v1/approvals", 500);
      const result = await fleetClient.fetchApprovals();
      expect(result).toBeNull();
    });
  });

  describe("resolveApproval", () => {
    it("resolves approval via saved connection", async () => {
      seedLocalStorage();
      const result = await fleetClient.resolveApproval("apr-001", "approved");
      expect(result.success).toBe(true);
    });

    it("passes scope and reason through", async () => {
      seedLocalStorage();
      const result = await fleetClient.resolveApproval("apr-001", "denied", {
        scope: { ttlSeconds: 60 },
        reason: "Not needed",
      });
      expect(result.success).toBe(true);
    });
  });
});

// ---- Edge cases ----

describe("edge cases", () => {
  it("fetchAuditEvents handles response with missing events field", async () => {
    // Inject a response that returns {} (no events key, not an array)
    const { http: mswHttp, HttpResponse: MswResponse } = await import("msw");
    mockFleetServer.use(
      mswHttp.get("/_proxy/hushd/api/v1/audit", ({ request }) => {
        const auth = request.headers.get("Authorization");
        if (!auth) return new MswResponse(null, { status: 401 });
        return MswResponse.json({});
      }),
    );
    const events = await fetchAuditEvents(makeConn());
    expect(events).toEqual([]);
  });

  it("fetchApprovals handles response with missing fields", async () => {
    // Inject a response that returns {} (no requests/decisions keys)
    const { http: mswHttp, HttpResponse: MswResponse } = await import("msw");
    mockFleetServer.use(
      mswHttp.get("/_proxy/control/api/v1/approvals", ({ request }) => {
        const auth = request.headers.get("Authorization");
        if (!auth) return new MswResponse(null, { status: 401 });
        return MswResponse.json({});
      }),
    );
    const result = await fetchApprovals(makeConn());
    expect(result.requests).toEqual([]);
    expect(result.decisions).toEqual([]);
  });

  it("distributePolicy strips trailing slashes from control-api URL", async () => {
    const conn = makeConn({ controlApiUrl: "http://localhost:9877///" });
    const result = await distributePolicy(conn, 'schema_version: "1.2.0"\n');
    expect(result.success).toBe(true);
  });

  it("fetchDelegationGraphFromApi strips trailing slashes from URL", async () => {
    injectGrantsData();
    const conn = makeConn({ controlApiUrl: "http://localhost:9877///" });
    const result = await fetchDelegationGraphFromApi(conn);
    expect(result).not.toBeNull();
  });
});

// ---- localStorage mock (jsdom in this project doesn't provide full localStorage) ----

let lsStore: Record<string, string>;

const localStorageMock = {
  getItem: (key: string) => lsStore[key] ?? null,
  setItem: (key: string, value: string) => { lsStore[key] = value; },
  removeItem: (key: string) => { delete lsStore[key]; },
  clear: () => { lsStore = {}; },
  get length() { return Object.keys(lsStore).length; },
  key: (index: number) => Object.keys(lsStore)[index] ?? null,
};

describe("persistence helpers", () => {
  beforeEach(() => {
    lsStore = {};
    vi.stubGlobal("localStorage", localStorageMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("saveConnectionConfig persists to localStorage", () => {
    saveConnectionConfig({
      hushdUrl: "http://localhost:9876",
      controlApiUrl: "http://localhost:9877",
      apiKey: "my-key",
      controlApiToken: "my-token",
    });

    expect(localStorage.getItem("clawdstrike_hushd_url")).toBe(
      "http://localhost:9876",
    );
    expect(localStorage.getItem("clawdstrike_api_key")).toBe("my-key");
  });

  it("loadSavedConnection reads from localStorage", () => {
    localStorage.setItem("clawdstrike_hushd_url", "http://saved:9876");
    localStorage.setItem("clawdstrike_api_key", "saved-key");

    const saved = loadSavedConnection();
    expect(saved.hushdUrl).toBe("http://saved:9876");
    expect(saved.apiKey).toBe("saved-key");
  });

  it("loadSavedConnection returns empty strings when nothing saved", () => {
    const saved = loadSavedConnection();
    expect(saved.hushdUrl).toBe("");
    expect(saved.apiKey).toBe("");
  });

  it("clearConnectionConfig removes all keys", () => {
    saveConnectionConfig({
      hushdUrl: "http://localhost:9876",
      controlApiUrl: "http://localhost:9877",
      apiKey: "key",
      controlApiToken: "token",
    });
    clearConnectionConfig();

    expect(localStorage.getItem("clawdstrike_hushd_url")).toBeNull();
    expect(localStorage.getItem("clawdstrike_api_key")).toBeNull();
    expect(localStorage.getItem("clawdstrike_control_api_url")).toBeNull();
    expect(localStorage.getItem("clawdstrike_control_api_token")).toBeNull();
  });
});
