import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PolicyEvent } from "../../types.js";
import handler, {
  buildToolResultDeveloperActivitiesForEdr,
  buildToolResultPolicyEventForEdr,
  initialize,
} from "./handler.js";

describe("tool-result guard EDR telemetry", () => {
  beforeEach(() => {
    delete process.env.CLAWDSTRIKE_APPROVAL_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN;
    delete process.env.CLAWDSTRIKE_POLICY_EVENTS_URL;
    delete process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL;
    delete process.env.CLAWDSTRIKE_AGENT_URL;
    process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH = "/tmp/clawdstrike-openclaw-missing-agent-token";

    initialize({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "deterministic",
      logLevel: "error",
    });
  });

  afterEach(() => {
    delete process.env.CLAWDSTRIKE_APPROVAL_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN;
    delete process.env.CLAWDSTRIKE_POLICY_EVENTS_URL;
    delete process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL;
    delete process.env.CLAWDSTRIKE_AGENT_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("omits raw tool results from posted PolicyEvent evidence", () => {
    const event: PolicyEvent = {
      eventId: "result-secret-1",
      eventType: "tool_call",
      timestamp: new Date().toISOString(),
      sessionId: "sess-result",
      data: {
        type: "tool",
        toolName: "api_call",
        parameters: {},
        result: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      },
      metadata: { toolName: "api_call" },
    };

    const edrEvent = buildToolResultPolicyEventForEdr(
      event,
      "api_call",
      {
        status: "deny",
        reason_code: "secret_leak",
        guard: "secret_leak",
        severity: "critical",
        reason: "Detected potential secrets in output: github_pat",
      },
      {
        agentId: "agent:openclaw",
        toolCallId: "tool-call-result-1",
      },
    );

    expect(edrEvent.data).toMatchObject({
      type: "tool",
      toolName: "api_call",
      result: expect.stringContaining("omitted by openclaw_tool_result"),
    });
    expect(JSON.stringify(edrEvent)).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    expect(edrEvent.metadata).toMatchObject({
      collectorKind: "openclaw_tool_result",
      postExecution: true,
      policyAllowed: false,
      policyStatus: "deny",
      resultOmitted: true,
      resultHash: expect.any(String),
      agentId: "agent:openclaw",
      workloadId: "openclaw-tool-result",
      toolCallId: "tool-call-result-1",
    });
  });

  it("maps result-discovered downloads to browser download developer activity", () => {
    const event = baseToolEvent("result-download-1");
    const activities = buildToolResultDeveloperActivitiesForEdr(
      event,
      "browser.download",
      { browser: "Chrome", url: "https://example.test/report.zip" },
      {
        downloadPath: "/tmp/report.zip",
        sourceUrl: "https://example.test/report.zip?token=MY_RAW_SECRET#fragment",
      },
      { status: "allow" },
      { agentId: "agent:openclaw", toolCallId: "tool-call-download-1" },
    );

    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "browser_download",
          browser: "Chrome",
          path: "/tmp/report.zip",
          sourceUrl: "https://example.test/report.zip",
          sessionId: "sess-result",
          agentId: "agent:openclaw",
          workloadId: "openclaw-tool-result",
          metadata: expect.objectContaining({
            collectorKind: "openclaw_tool_result",
            activityClassifier: "browser_download",
            toolCallId: "tool-call-download-1",
          }),
        }),
        expect.objectContaining({
          kind: "local_api_key",
          path: "https://example.test/report.zip",
          name: "url_credential",
          metadata: expect.objectContaining({
            activityClassifier: "url_secret",
          }),
        }),
      ]),
    );
    expect(JSON.stringify(activities)).not.toContain("MY_RAW_SECRET");
  });

  it("scrubs tokenized source URLs from result-discovered extension credential facts", () => {
    const event = baseToolEvent("result-extension-token-1");
    const activities = buildToolResultDeveloperActivitiesForEdr(
      event,
      "browser.extension.install",
      { browser: "Chrome", sourceUrl: "https://example.test/ext.crx?token=MY_RAW_SECRET" },
      {
        extensionId: "abcdefghijklmnopabcdefghijklmnop",
        extensionPath: "/Users/test/Library/Application Support/Google/Chrome/Extensions/ext",
      },
      { status: "allow" },
      { agentId: "agent:openclaw" },
    );

    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "browser_extension",
          source: "https://example.test/ext.crx",
        }),
        expect.objectContaining({
          kind: "local_api_key",
          path: "https://example.test/ext.crx",
          name: "url_credential",
          metadata: expect.objectContaining({
            activityClassifier: "url_secret",
          }),
        }),
      ]),
    );
    expect(JSON.stringify(activities)).not.toContain("MY_RAW_SECRET");
  });

  it("maps secret-like tool outputs to redacted local API key activity", () => {
    const event = baseToolEvent("result-secret-2");
    const activities = buildToolResultDeveloperActivitiesForEdr(
      event,
      "api_call",
      {},
      { text: "created token ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
      { status: "deny", reason_code: "secret_leak", guard: "secret_leak" },
      { agentId: "agent:openclaw" },
    );

    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "local_api_key",
          name: "github_token",
          credentialKind: "api_token",
          metadata: expect.objectContaining({
            activityClassifier: "secret_output",
            rawSecretOmitted: true,
          }),
        }),
      ]),
    );
    expect(JSON.stringify(activities)).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
  });

  it("maps result-discovered credential paths to repo-secret developer activity", () => {
    const event = baseToolEvent("result-repo-secret-1");
    const activities = buildToolResultDeveloperActivitiesForEdr(
      event,
      "read_file",
      {},
      { files: ["/repo/.env"] },
      { status: "allow" },
      { agentId: "agent:openclaw" },
    );

    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "repo_secret",
          path: "/repo/.env",
          name: ".env",
          credentialKind: "api_token",
          metadata: expect.objectContaining({
            activityClassifier: "repo_secret_path",
            rawSecretOmitted: true,
          }),
        }),
      ]),
    );
  });

  it("maps result-discovered browser extension installs to developer activity", () => {
    const event = baseToolEvent("result-extension-1");
    const activities = buildToolResultDeveloperActivitiesForEdr(
      event,
      "browser.extension.install",
      { browser: "Chrome", sourceUrl: "https://example.test/ext.crx?token=MY_RAW_SECRET" },
      {
        extensionId: "abcdefghijklmnopabcdefghijklmnop",
        extensionPath: "/Users/test/Library/Application Support/Google/Chrome/Extensions/ext",
      },
      { status: "allow" },
      { agentId: "agent:openclaw" },
    );

    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "browser_extension",
          browser: "Chrome",
          extensionId: "abcdefghijklmnopabcdefghijklmnop",
          path: "/Users/test/Library/Application Support/Google/Chrome/Extensions/ext",
          source: "https://example.test/ext.crx",
          metadata: expect.objectContaining({
            activityClassifier: "browser_extension",
          }),
        }),
      ]),
    );
    expect(JSON.stringify(activities)).not.toContain("MY_RAW_SECRET");
  });

  it("posts post-result PolicyEvent and developer activity when local token is configured", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/developer-activity";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "browser.download",
        toolCallId: "tool-call-download-2",
        message: {
          details: {
            params: {
              browser: "Chrome",
              url: "https://example.test/report.zip",
            },
          },
          result: {
            downloadPath: "/tmp/report.zip",
            sourceUrl: "https://example.test/report.zip",
          },
        },
      } as any,
      {
        agentId: "agent:openclaw",
        sessionKey: "sess-modern",
        toolCallId: "tool-call-download-2",
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const policyCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/policy-events"),
    );
    const activityCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/developer-activity"),
    );
    expect(policyCall).toBeDefined();
    expect(activityCall).toBeDefined();

    const [, policyInit] = policyCall as [string, RequestInit];
    expect((policyInit.headers as Record<string, string>).Authorization).toBe("Bearer test-token");
    const policyBody = JSON.parse(String(policyInit.body));
    expect(policyBody.events[0]).toMatchObject({
      sessionId: "sess-modern",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_result",
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-result",
        toolCallId: "tool-call-download-2",
      }),
    });

    const [, activityInit] = activityCall as [string, RequestInit];
    const activityBody = JSON.parse(String(activityInit.body));
    expect(activityBody.activities[0]).toMatchObject({
      kind: "browser_download",
      path: "/tmp/report.zip",
      sessionId: "sess-modern",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_result",
        activityClassifier: "browser_download",
      }),
    });
  });

  it("binds modern endpoint identity into posted post-result EDR payloads", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/developer-activity";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "browser.download",
        toolCallId: "tool-call-result-identity-1",
        message: {
          details: {
            params: {
              browser: "Chrome",
              url: "https://example.test/report.zip",
            },
          },
          result: {
            downloadPath: "/tmp/report.zip",
            sourceUrl: "https://example.test/report.zip",
          },
        },
      } as any,
      {
        agentId: "agent:openclaw",
        sessionKey: "sess-result-identity",
        toolCallId: "tool-call-result-identity-1",
        hostId: "endpoint:devbook",
        userId: "principal:alice",
        workloadId: "workload:openclaw-agent",
        approvalId: "approval:change-456",
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const policyCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/policy-events"),
    );
    const activityCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/developer-activity"),
    );
    expect(policyCall).toBeDefined();
    expect(activityCall).toBeDefined();

    const [, policyInit] = policyCall as [string, RequestInit];
    const policyBody = JSON.parse(String(policyInit.body));
    expect(policyBody.events[0]).toMatchObject({
      sessionId: "sess-result-identity",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_result",
        hostId: "endpoint:devbook",
        userId: "principal:alice",
        sessionId: "sess-result-identity",
        agentId: "agent:openclaw",
        workloadId: "workload:openclaw-agent",
        approvalId: "approval:change-456",
        toolCallId: "tool-call-result-identity-1",
      }),
    });

    const [, activityInit] = activityCall as [string, RequestInit];
    const activityBody = JSON.parse(String(activityInit.body));
    expect(activityBody.activities[0]).toMatchObject({
      kind: "browser_download",
      hostId: "endpoint:devbook",
      userId: "principal:alice",
      sessionId: "sess-result-identity",
      agentId: "agent:openclaw",
      workloadId: "workload:openclaw-agent",
      approvalId: "approval:change-456",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_result",
        toolCallId: "tool-call-result-identity-1",
      }),
    });
  });
});

function baseToolEvent(eventId: string): PolicyEvent {
  return {
    eventId,
    eventType: "tool_call",
    timestamp: new Date().toISOString(),
    sessionId: "sess-result",
    data: {
      type: "tool",
      toolName: "api_call",
      parameters: {},
    },
    metadata: { toolName: "api_call" },
  };
}
