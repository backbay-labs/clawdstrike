import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  approveBrokerPreview,
  exportBrokerCompletionBundle,
  fetchBrokerPreview,
  fetchBrokerPreviews,
  fetchBrokerCapabilities,
  fetchBrokerCapability,
  fetchFrozenBrokerProviders,
  fetchAgentStatus,
  fetchAuditEvents,
  fetchAuditStats,
  fetchHealth,
  fetchIntegrationSettings,
  fetchPolicy,
  freezeBrokerProvider,
  replayBrokerCapability,
  revokeAllBrokerCapabilities,
  revokeBrokerCapability,
  saveIntegrationSettings,
  testIntegrationDelivery,
  unfreezeBrokerProvider,
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

describe("broker control-plane client helpers", () => {
  it("queries broker capabilities with filters", async () => {
    mockFetch.mockReturnValue(jsonResponse({ capabilities: [] }));

    await fetchBrokerCapabilities({ state: "active", provider: "github", limit: 25 });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v1/broker/capabilities");
    expect(url).toContain("state=active");
    expect(url).toContain("provider=github");
    expect(url).toContain("limit=25");
  });

  it("fetches a single broker capability detail envelope", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability: {
          capability_id: "cap-1",
          provider: "openai",
          state: "active",
          issued_at: "2026-03-12T00:00:00Z",
          expires_at: "2026-03-12T00:01:00Z",
          policy_hash: "hash-1",
          secret_ref_id: "openai/dev",
          url: "https://api.openai.com/v1/responses",
          method: "POST",
          execution_count: 0,
        },
        executions: [
          {
            execution_id: "exec-1",
            capability_id: "cap-1",
            provider: "openai",
            phase: "completed",
            executed_at: "2026-03-12T00:00:30Z",
            secret_ref_id: "openai/dev",
            url: "https://api.openai.com/v1/responses",
            method: "POST",
            bytes_sent: 12,
            bytes_received: 24,
          },
        ],
      }),
    );

    const result = await fetchBrokerCapability("cap-1");
    expect(result.capability.capability_id).toBe("cap-1");
    expect(result.executions).toHaveLength(1);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-1");
  });

  it("queries broker previews with filters and fetches a single preview", async () => {
    mockFetch
      .mockReturnValueOnce(
        jsonResponse({
          previews: [
            {
              preview_id: "preview-1",
              provider: "github",
              operation: "issues.create",
              summary: "Create incident issue in production repo",
              created_at: "2026-03-12T00:00:00Z",
              risk_level: "high",
              data_classes: ["code", "secrets"],
              resources: [{ kind: "repo", value: "acme/api" }],
              egress_host: "api.github.com",
              approval_required: true,
              approval_state: "pending",
            },
          ],
        }),
      )
      .mockReturnValueOnce(
        jsonResponse({
          preview: {
            preview_id: "preview-1",
            provider: "github",
            operation: "issues.create",
            summary: "Create incident issue in production repo",
            created_at: "2026-03-12T00:00:00Z",
            risk_level: "high",
            data_classes: ["code", "secrets"],
            resources: [{ kind: "repo", value: "acme/api" }],
            egress_host: "api.github.com",
            approval_required: true,
            approval_state: "pending",
          },
        }),
      );

    const previews = await fetchBrokerPreviews({ provider: "github", limit: 10 });
    const preview = await fetchBrokerPreview("preview-1");

    expect(previews.previews).toHaveLength(1);
    expect(preview.preview.preview_id).toBe("preview-1");
    expect(mockFetch.mock.calls[0][0]).toContain("/api/v1/broker/previews");
    expect(mockFetch.mock.calls[0][0]).toContain("provider=github");
    expect(mockFetch.mock.calls[0][0]).toContain("limit=10");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/broker/previews/preview-1");
  });

  it("posts broker preview approval requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        preview: {
          preview_id: "preview-approve-1",
          provider: "slack",
          operation: "messages.post",
          summary: "Post incident update to on-call channel",
          created_at: "2026-03-12T00:00:00Z",
          risk_level: "medium",
          data_classes: ["incident_context"],
          resources: [{ kind: "channel", value: "#on-call" }],
          egress_host: "slack.com",
          approval_required: true,
          approval_state: "approved",
          approver: "operator@example.com",
          approved_at: "2026-03-12T00:01:00Z",
        },
      }),
    );

    const result = await approveBrokerPreview("preview-approve-1", "operator@example.com");
    expect(result.approval_state).toBe("approved");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/previews/preview-approve-1/approve");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).approver).toBe("operator@example.com");
  });

  it("posts capability revocation requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability: {
          capability_id: "cap-2",
          provider: "github",
          state: "revoked",
          issued_at: "2026-03-12T00:00:00Z",
          expires_at: "2026-03-12T00:01:00Z",
          policy_hash: "hash-2",
          secret_ref_id: "github/prod",
          url: "https://api.github.com/repos/acme/repo/issues",
          method: "POST",
          execution_count: 1,
        },
      }),
    );

    const result = await revokeBrokerCapability("cap-2", "panic revoke");
    expect(result.state).toBe("revoked");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-2/revoke");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).reason).toBe("panic revoke");
  });

  it("fetches and mutates provider freeze state", async () => {
    mockFetch
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [] }))
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [{ provider: "slack" }] }))
      .mockReturnValueOnce(jsonResponse({ frozen_providers: [] }));

    await fetchFrozenBrokerProviders();
    await freezeBrokerProvider("slack", "incident response");
    await unfreezeBrokerProvider("slack");

    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/providers/freeze");
    expect(mockFetch.mock.calls[1][0]).toBe("/api/v1/broker/providers/slack/freeze");
    expect(mockFetch.mock.calls[1][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[1][1].body).reason).toBe("incident response");
    expect(mockFetch.mock.calls[2][1].method).toBe("DELETE");
  });

  it("posts broker replay requests", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        capability_id: "cap-3",
        current_policy_hash: "hash-3",
        current_state: "active",
        provider_frozen: false,
        egress_allowed: true,
        provider_allowed: true,
        policy_changed: true,
        approval_required: true,
        preview_still_approved: false,
        delegated_subject: "runtime:agent-7",
        minted_identity_kind: "github_app_installation",
        would_allow: true,
        reason: "current policy would still authorize this capability",
        diffs: [
          {
            field: "preview_approval",
            previous: "approved",
            current: "missing",
          },
        ],
      }),
    );

    const result = await replayBrokerCapability("cap-3");
    expect(result.would_allow).toBe(true);
    expect(result.policy_changed).toBe(true);
    expect(result.diffs?.[0]?.field).toBe("preview_approval");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-3/replay");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
  });

  it("exports completion bundles for a capability", async () => {
    mockFetch.mockReturnValue(
      jsonResponse({
        envelope: "signed-bundle-envelope",
        bundle: {
          generated_at: "2026-03-12T00:02:00Z",
          capability: {
            capability_id: "cap-4",
            provider: "openai",
            state: "active",
            issued_at: "2026-03-12T00:00:00Z",
            expires_at: "2026-03-12T00:30:00Z",
            policy_hash: "hash-4",
            secret_ref_id: "openai/prod",
            url: "https://api.openai.com/v1/responses",
            method: "POST",
            execution_count: 2,
          },
          executions: [],
        },
      }),
    );

    const result = await exportBrokerCompletionBundle("cap-4");
    expect(result.envelope).toBe("signed-bundle-envelope");
    expect(result.bundle.capability.capability_id).toBe("cap-4");
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/cap-4/bundle");
    expect(mockFetch.mock.calls[0][1].headers["Content-Type"]).toBe("application/json");
  });

  it("posts panic revoke requests", async () => {
    mockFetch.mockReturnValue(jsonResponse({ revoked_count: 7 }));

    const result = await revokeAllBrokerCapabilities("incident drill");
    expect(result.revoked_count).toBe(7);
    expect(mockFetch.mock.calls[0][0]).toBe("/api/v1/broker/capabilities/revoke-all");
    expect(mockFetch.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).reason).toBe("incident drill");
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
