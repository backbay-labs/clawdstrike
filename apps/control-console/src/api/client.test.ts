import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchAgentStatus,
  fetchAuditEvents,
  fetchAuditStats,
  fetchHealth,
  fetchIntegrationSettings,
  fetchPolicy,
  saveIntegrationSettings,
  testIntegrationDelivery,
} from "./client";

const mockFetch = vi.fn();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal("fetch", mockFetch);
  // Clear localStorage mock
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

describe("fetchHealth", () => {
  it("returns health data on success", async () => {
    mockFetch.mockReturnValue(jsonResponse({ status: "ok", version: "0.2.0" }));
    const result = await fetchHealth();
    expect(result.status).toBe("ok");
    expect(result.version).toBe("0.2.0");
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockReturnValue(jsonResponse({}, 500));
    await expect(fetchHealth()).rejects.toThrow("Health check failed: 500");
  });
});

describe("fetchAuditEvents", () => {
  it("builds query string from filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ events: [], total: 0 }));
    await fetchAuditEvents({
      decision: "blocked",
      limit: 10,
      offset: 5,
      runtime_agent_id: "runtime-1",
      runtime_agent_kind: "claude_code",
    });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("decision=blocked");
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=5");
    expect(url).toContain("runtime_agent_id=runtime-1");
    expect(url).toContain("runtime_agent_kind=claude_code");
  });

  it("omits empty filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ events: [], total: 0 }));
    await fetchAuditEvents({});

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("/api/v1/audit");
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockReturnValue(jsonResponse({}, 403));
    await expect(fetchAuditEvents()).rejects.toThrow("Audit query failed: 403");
  });
});

describe("fetchAgentStatus", () => {
  it("queries agent status endpoint with filters", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        generated_at: "2026-03-04T00:00:00Z",
        stale_after_secs: 90,
        endpoints: [],
        runtimes: [],
      }),
    );
    await fetchAgentStatus({
      endpoint_agent_id: "endpoint-1",
      include_stale: true,
      limit: 25,
    });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v1/agents/status");
    expect(url).toContain("endpoint_agent_id=endpoint-1");
    expect(url).toContain("include_stale=true");
    expect(url).toContain("limit=25");
  });
});

describe("fetchAuditStats", () => {
  it("returns stats data on success", async () => {
    const data = { total_events: 100, violations: 5, allowed: 95, uptime_secs: 3600 };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchAuditStats();
    expect(result.total_events).toBe(100);
    expect(result.violations).toBe(5);
  });
});

describe("fetchPolicy", () => {
  it("returns policy data on success", async () => {
    const data = { name: "default", version: "1.0" };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchPolicy();
    expect(result.name).toBe("default");
  });
});

describe("fetchIntegrationSettings", () => {
  it("fetches from correct endpoint", async () => {
    const data = {
      siem: { provider: "datadog", endpoint: "", api_key: "", enabled: false },
      webhooks: { url: "", secret: "", enabled: false },
    };
    mockFetch.mockReturnValue(jsonResponse(data));
    const result = await fetchIntegrationSettings();
    expect(result.siem.provider).toBe("datadog");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/integrations");
  });
});

describe("saveIntegrationSettings", () => {
  it("sends PUT with body", async () => {
    const responseData = { integrations: {}, restarted: true };
    mockFetch.mockReturnValue(jsonResponse(responseData));

    await saveIntegrationSettings({ siem: { provider: "splunk" }, apply: true });

    expect(mockFetch.mock.calls[0][1].method).toBe("PUT");
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.siem.provider).toBe("splunk");
    expect(body.apply).toBe(true);
  });

  it("throws with response text on error", async () => {
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 400,
        text: () => Promise.resolve("bad request"),
      }),
    );
    await expect(saveIntegrationSettings({})).rejects.toThrow("bad request");
  });
});

describe("testIntegrationDelivery", () => {
  it("sends POST payload with target and retry count", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        target: "siem",
        endpoint: "https://collector.example",
        delivered: true,
        status_code: 200,
        attempts: 1,
        retry_count: 0,
        latency_ms: 42,
        tested_at: "2026-03-03T12:00:00Z",
      }),
    );

    const result = await testIntegrationDelivery("siem", 3);
    expect(result.target).toBe("siem");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/agent/integrations/test");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.target).toBe("siem");
    expect(body.max_retries).toBe(3);
  });

  it("throws with response text on test failure", async () => {
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 502,
        text: () => Promise.resolve("upstream unavailable"),
      }),
    );
    await expect(testIntegrationDelivery("webhook")).rejects.toThrow("upstream unavailable");
  });
});

describe("auth header logic", () => {
  it("includes Authorization header when apiBase and apiKey are set", async () => {
    localStorage.setItem("hushd_url", "http://remote:9876");
    localStorage.setItem("hushd_api_key", "my-secret");
    mockFetch.mockReturnValue(jsonResponse({ status: "ok" }));

    await fetchHealth();

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer my-secret");
  });

  it("omits Authorization header when apiBase is empty", async () => {
    localStorage.setItem("hushd_api_key", "my-secret");
    mockFetch.mockReturnValue(jsonResponse({ status: "ok" }));

    await fetchHealth();

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBeUndefined();
  });
});
