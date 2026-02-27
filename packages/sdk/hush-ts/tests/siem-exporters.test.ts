import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { BaseExporter, SchemaFormat } from "../src/siem/framework";
import type { ExportResult } from "../src/siem/framework";
import type { SecurityEvent } from "../src/siem/types";
import { uuidv7 } from "../src/siem/types";

import { WebhookExporter } from "../src/siem/exporters/webhooks";
import { AlertingExporter } from "../src/siem/exporters/alerting";
import { DatadogExporter } from "../src/siem/exporters/datadog";
import { ElasticExporter } from "../src/siem/exporters/elastic";
import { SplunkExporter } from "../src/siem/exporters/splunk";
import { SumoLogicExporter } from "../src/siem/exporters/sumo-logic";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    schema_version: "1.0.0",
    event_id: overrides.event_id ?? uuidv7(),
    event_type: overrides.event_type ?? "guard_block",
    event_category: overrides.event_category ?? "tool",
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    agent: overrides.agent ?? {
      id: "agent-1",
      name: "agent-1",
      version: "0.1.0",
      type: "clawdstrike",
    },
    session: overrides.session ?? { id: "sess-1" },
    outcome: overrides.outcome ?? "failure",
    action: overrides.action ?? "tool_call_blocked",
    threat: overrides.threat ?? {},
    decision: overrides.decision ?? {
      allowed: false,
      guard: "egress",
      severity: "high",
      reason: "blocked by guard",
    },
    resource: overrides.resource ?? { type: "network", name: "evil.com" },
    metadata: overrides.metadata ?? {},
    labels: overrides.labels ?? {},
  };
}

function makeAllowedEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return makeEvent({
    event_type: "policy_allow",
    outcome: "success",
    decision: {
      allowed: true,
      guard: "egress",
      severity: "info",
      reason: "ok",
    },
    ...overrides,
  });
}

function mockFetchOk(body: unknown = {}): ReturnType<typeof vi.fn> {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } })
  );
}

function mockFetchStatus(status: number, body = ""): ReturnType<typeof vi.fn> {
  return vi.fn().mockResolvedValue(
    new Response(body, { status, headers: { "Content-Type": "text/plain" } })
  );
}

// ---------------------------------------------------------------------------
// Framework: BaseExporter
// ---------------------------------------------------------------------------

describe("BaseExporter", () => {
  class TestExporter extends BaseExporter {
    readonly name = "test";
    readonly schema = SchemaFormat.Native;
    exportCalls: SecurityEvent[][] = [];
    healthCheckCalled = false;

    async export(events: SecurityEvent[]): Promise<ExportResult> {
      this.exportCalls.push(events);
      return { exported: events.length, failed: 0, errors: [] };
    }

    async healthCheck(): Promise<void> {
      this.healthCheckCalled = true;
    }
  }

  it("defaults config values", () => {
    const exporter = new TestExporter();
    expect(exporter["config"].batchSize).toBe(100);
    expect(exporter["config"].flushIntervalMs).toBe(5000);
    expect(exporter["config"].retry.maxRetries).toBe(3);
  });

  it("accepts custom config values", () => {
    const exporter = new TestExporter({
      batchSize: 50,
      flushIntervalMs: 1000,
      retry: { maxRetries: 1, initialBackoffMs: 100, maxBackoffMs: 500, backoffMultiplier: 1.5 },
    });
    expect(exporter["config"].batchSize).toBe(50);
    expect(exporter["config"].flushIntervalMs).toBe(1000);
    expect(exporter["config"].retry.maxRetries).toBe(1);
  });

  it("enqueue + flush lifecycle", async () => {
    const exporter = new TestExporter({ batchSize: 3 });
    const e1 = makeEvent();
    const e2 = makeEvent();

    await exporter.enqueue(e1);
    await exporter.enqueue(e2);
    // Not yet flushed (below batchSize)
    expect(exporter.exportCalls).toHaveLength(0);

    const result = await exporter.flush();
    expect(result.exported).toBe(2);
    expect(exporter.exportCalls).toHaveLength(1);
    expect(exporter.exportCalls[0]).toHaveLength(2);
  });

  it("auto-flushes when batchSize is reached", async () => {
    const exporter = new TestExporter({ batchSize: 2 });
    await exporter.enqueue(makeEvent());
    await exporter.enqueue(makeEvent()); // This should trigger flush
    expect(exporter.exportCalls).toHaveLength(1);
    expect(exporter.exportCalls[0]).toHaveLength(2);
  });

  it("flush on empty buffer returns zero counts", async () => {
    const exporter = new TestExporter();
    const result = await exporter.flush();
    expect(result.exported).toBe(0);
    expect(result.failed).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it("shutdown flushes the buffer", async () => {
    const exporter = new TestExporter();
    await exporter.enqueue(makeEvent());
    await exporter.shutdown();
    expect(exporter.exportCalls).toHaveLength(1);
  });

  it("exportWithRetry retries on failure then gives up", async () => {
    const exporter = new (class extends BaseExporter {
      readonly name = "failing";
      readonly schema = SchemaFormat.Native;
      calls = 0;

      async export(_events: SecurityEvent[]): Promise<ExportResult> {
        this.calls++;
        throw new Error("boom");
      }

      async healthCheck(): Promise<void> {}
    })({
      retry: { maxRetries: 2, initialBackoffMs: 1, maxBackoffMs: 10, backoffMultiplier: 2 },
    });

    const events = [makeEvent()];
    const result = await exporter["exportWithRetry"](events);

    // 1 initial + 2 retries = 3 total calls
    expect(exporter.calls).toBe(3);
    expect(result.failed).toBe(1);
    expect(result.exported).toBe(0);
    expect(result.errors[0].error).toBe("boom");
    expect(result.errors[0].retryable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// WebhookExporter
// ---------------------------------------------------------------------------

describe("WebhookExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = mockFetchOk();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("exports events to a generic webhook", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });

    const event = makeEvent();
    const result = await exporter.export([event]);

    expect(result.exported).toBe(1);
    expect(result.failed).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://hooks.example.com/ingest");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
  });

  it("sends custom headers on generic webhooks", async () => {
    const exporter = new WebhookExporter({
      webhooks: [
        {
          url: "https://hooks.example.com/ingest",
          headers: { "X-Custom": "value" },
        },
      ],
    });

    await exporter.export([makeEvent()]);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["X-Custom"]).toBe("value");
  });

  it("attaches bearer auth header", async () => {
    const exporter = new WebhookExporter({
      webhooks: [
        {
          url: "https://hooks.example.com/ingest",
          auth: { type: "bearer", token: "my-token" },
        },
      ],
    });

    await exporter.export([makeEvent()]);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer my-token");
  });

  it("attaches basic auth header", async () => {
    const exporter = new WebhookExporter({
      webhooks: [
        {
          url: "https://hooks.example.com/ingest",
          auth: { type: "basic", username: "user", password: "pass" },
        },
      ],
    });

    await exporter.export([makeEvent()]);
    const [, init] = fetchMock.mock.calls[0];
    const expected = `Basic ${Buffer.from("user:pass").toString("base64")}`;
    expect(init.headers.Authorization).toBe(expected);
  });

  it("attaches custom header auth", async () => {
    const exporter = new WebhookExporter({
      webhooks: [
        {
          url: "https://hooks.example.com/ingest",
          auth: { type: "header", headerName: "X-Api-Key", headerValue: "secret123" },
        },
      ],
    });

    await exporter.export([makeEvent()]);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["X-Api-Key"]).toBe("secret123");
  });

  it("tracks filtered count when events are below minSeverity", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
      minSeverity: "high",
    });

    const lowEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "low", reason: "low" },
    });
    const highEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "high" },
    });

    const result = await exporter.export([lowEvent, highEvent]);
    expect(result.exported).toBe(1);
    expect(result.filtered).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("filters by includeGuards", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
      includeGuards: ["secret_leak"],
    });

    const egressEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    const secretEvent = makeEvent({
      decision: { allowed: false, guard: "secret_leak", severity: "high", reason: "leak detected" },
    });

    const result = await exporter.export([egressEvent, secretEvent]);
    expect(result.exported).toBe(1);
    expect(result.filtered).toBe(1);
  });

  it("filters by excludeGuards", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
      excludeGuards: ["egress"],
    });

    const egressEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    const secretEvent = makeEvent({
      decision: { allowed: false, guard: "secret_leak", severity: "high", reason: "leak" },
    });

    const result = await exporter.export([egressEvent, secretEvent]);
    expect(result.exported).toBe(1);
    expect(result.filtered).toBe(1);
  });

  it("handles fetch failure gracefully", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));

    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });

    const result = await exporter.export([makeEvent()]);
    expect(result.failed).toBe(1);
    expect(result.errors[0].error).toBe("network error");
    expect(result.errors[0].retryable).toBe(true);
  });

  it("handles non-OK HTTP response", async () => {
    vi.stubGlobal("fetch", mockFetchStatus(500, "server error"));

    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });

    const result = await exporter.export([makeEvent()]);
    expect(result.failed).toBe(1);
    expect(result.errors[0].error).toContain("500");
  });

  it("sends to Slack webhook", async () => {
    const exporter = new WebhookExporter({
      slack: { webhookUrl: "https://hooks.slack.com/services/T/B/xxx" },
    });

    await exporter.export([makeEvent()]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://hooks.slack.com/services/T/B/xxx");
    const body = JSON.parse(init.body);
    expect(body.text).toContain("Clawdstrike security event");
    expect(body.blocks).toBeDefined();
  });

  it("sends to Teams webhook", async () => {
    const exporter = new WebhookExporter({
      teams: { webhookUrl: "https://outlook.office.com/webhook/xxx" },
    });

    await exporter.export([makeEvent()]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://outlook.office.com/webhook/xxx");
    const body = JSON.parse(init.body);
    // Default is adaptive card
    expect(body.type).toBe("message");
    expect(body.attachments).toBeDefined();
  });

  it("sends to multiple destinations in parallel", async () => {
    const exporter = new WebhookExporter({
      slack: { webhookUrl: "https://hooks.slack.com/services/T/B/xxx" },
      teams: { webhookUrl: "https://outlook.office.com/webhook/xxx" },
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });

    await exporter.export([makeEvent()]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("returns empty result for empty events array", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });

    const result = await exporter.export([]);
    expect(result.exported).toBe(0);
    expect(result.failed).toBe(0);
    expect(result.errors).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("healthCheck throws when no webhooks configured", async () => {
    const exporter = new WebhookExporter({});
    await expect(exporter.healthCheck()).rejects.toThrow("No webhooks configured");
  });

  it("healthCheck passes when webhooks are configured", async () => {
    const exporter = new WebhookExporter({
      webhooks: [{ url: "https://hooks.example.com/ingest" }],
    });
    await expect(exporter.healthCheck()).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// AlertingExporter
// ---------------------------------------------------------------------------

describe("AlertingExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = mockFetchOk();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("filters out allowed events (shouldAlert returns false)", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    const allowedEvent = makeAllowedEvent();
    const result = await exporter.export([allowedEvent]);

    expect(result.exported).toBe(0);
    expect(result.filtered).toBe(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("filters events below minSeverity (default: high)", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    const mediumEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "medium", reason: "blocked" },
    });
    const result = await exporter.export([mediumEvent]);

    expect(result.exported).toBe(0);
    expect(result.filtered).toBe(1);
  });

  it("respects custom minSeverity", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
      minSeverity: "medium",
    });

    const mediumEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "medium", reason: "blocked" },
    });
    const result = await exporter.export([mediumEvent]);

    expect(result.exported).toBe(1);
  });

  it("tracks filtered count correctly (T9 finding verification)", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    const lowEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "low", reason: "low" },
    });
    const mediumEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "medium", reason: "medium" },
    });
    const highEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "high" },
    });
    const criticalEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "critical", reason: "critical" },
    });
    const allowedEvent = makeAllowedEvent();

    const events = [lowEvent, mediumEvent, highEvent, criticalEvent, allowedEvent];
    const result = await exporter.export(events);

    // high + critical = 2 exported; low + medium + allowed = 3 filtered
    expect(result.exported).toBe(2);
    expect(result.filtered).toBe(3);
    expect(typeof result.filtered).toBe("number");
  });

  it("respects includeGuards filter", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
      includeGuards: ["secret_leak"],
    });

    const egressEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    const secretEvent = makeEvent({
      decision: { allowed: false, guard: "secret_leak", severity: "high", reason: "leak" },
    });

    const result = await exporter.export([egressEvent, secretEvent]);
    expect(result.exported).toBe(1);
    expect(result.filtered).toBe(1);
  });

  it("respects excludeGuards filter", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
      excludeGuards: ["egress"],
    });

    const egressEvent = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    const secretEvent = makeEvent({
      decision: { allowed: false, guard: "secret_leak", severity: "high", reason: "leak" },
    });

    const result = await exporter.export([egressEvent, secretEvent]);
    expect(result.exported).toBe(1);
    expect(result.filtered).toBe(1);
  });

  it("sends to PagerDuty with correct payload", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "pd-key-123" },
    });

    const event = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "critical", reason: "critical alert" },
    });
    const result = await exporter.export([event]);
    expect(result.exported).toBe(1);

    // PagerDuty uses HttpClient which uses fetch under the hood
    expect(fetchMock).toHaveBeenCalled();
    const [callUrl, callInit] = fetchMock.mock.calls[0];
    expect(callUrl.toString()).toContain("events.pagerduty.com");
    expect(callUrl.toString()).toContain("/v2/enqueue");

    const body = JSON.parse(callInit.body);
    expect(body.routing_key).toBe("pd-key-123");
    expect(body.event_action).toBe("trigger");
    expect(body.payload.summary).toContain("egress");
    expect(body.payload.severity).toBe("critical");
    expect(body.payload.source).toBe("clawdstrike");
  });

  it("sends to OpsGenie with correct payload", async () => {
    const exporter = new AlertingExporter({
      opsgenie: { apiKey: "og-key-456" },
      minSeverity: "high",
    });

    const event = makeEvent({
      decision: { allowed: false, guard: "secret_leak", severity: "high", reason: "secrets found" },
    });
    const result = await exporter.export([event]);
    expect(result.exported).toBe(1);

    expect(fetchMock).toHaveBeenCalled();
    const [callUrl, callInit] = fetchMock.mock.calls[0];
    expect(callUrl.toString()).toContain("api.opsgenie.com");
    expect(callUrl.toString()).toContain("/v2/alerts");

    const body = JSON.parse(callInit.body);
    expect(body.message).toContain("secret_leak");
    expect(body.source).toBe("clawdstrike");
    expect(body.priority).toBe("P2"); // high -> P2
    expect(body.tags).toContain("guard:secret_leak");
    expect(body.tags).toContain("severity:high");
    expect(callInit.headers.Authorization).toBe("GenieKey og-key-456");
  });

  it("sends to both PagerDuty and OpsGenie simultaneously", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "pd-key" },
      opsgenie: { apiKey: "og-key" },
    });

    const event = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    await exporter.export([event]);

    // Both should have been called
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("returns empty result for empty events", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    // When all events filtered out
    const allowedEvent = makeAllowedEvent();
    const result = await exporter.export([allowedEvent]);
    expect(result.exported).toBe(0);
    expect(result.filtered).toBe(1);
    expect(result.errors).toHaveLength(0);
  });

  it("shutdown calls super.shutdown to flush buffer", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    // Enqueue a high-severity blocked event
    const event = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    await exporter.enqueue(event);

    // Shutdown should flush the buffer (calls super.shutdown)
    await exporter.shutdown();

    // The event should have been exported via the PagerDuty client
    expect(fetchMock).toHaveBeenCalled();
  });

  it("healthCheck throws when no alerting targets configured", async () => {
    const exporter = new AlertingExporter({});
    await expect(exporter.healthCheck()).rejects.toThrow("No alerting targets configured");
  });

  it("healthCheck passes when targets configured", async () => {
    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });
    await expect(exporter.healthCheck()).resolves.toBeUndefined();
  });

  it("handles PagerDuty failure gracefully", async () => {
    vi.stubGlobal("fetch", mockFetchStatus(500, "internal error"));

    const exporter = new AlertingExporter({
      pagerduty: { routingKey: "test-key" },
    });

    const event = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
    });
    const result = await exporter.export([event]);
    expect(result.failed).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].retryable).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DatadogExporter
// ---------------------------------------------------------------------------

describe("DatadogExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = mockFetchOk();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sends logs with DD-API-KEY header", async () => {
    const exporter = new DatadogExporter({ apiKey: "dd-api-key-123" });

    const event = makeEvent();
    const result = await exporter.export([event]);

    expect(result.exported).toBe(1);
    expect(result.failed).toBe(0);

    // First call is logs, second is metrics
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [logsUrl, logsInit] = fetchMock.mock.calls[0];
    expect(logsUrl.toString()).toContain("http-intake.logs.datadoghq.com");
    expect(logsUrl.toString()).toContain("/api/v2/logs");
    expect(logsInit.headers["DD-API-KEY"]).toBe("dd-api-key-123");
  });

  it("transforms events to Datadog log format", async () => {
    const exporter = new DatadogExporter({
      apiKey: "dd-key",
      logs: { service: "my-service", source: "my-source" },
    });

    const event = makeEvent({
      session: { id: "sess-1", environment: "production", tenant_id: "t1" },
    });
    await exporter.export([event]);

    const [, logsInit] = fetchMock.mock.calls[0];
    const logs = JSON.parse(logsInit.body);
    expect(Array.isArray(logs)).toBe(true);
    expect(logs[0].service).toBe("my-service");
    expect(logs[0].ddsource).toBe("my-source");
    expect(logs[0].ddtags).toContain("guard:egress");
    expect(logs[0].ddtags).toContain("severity:high");
    expect(logs[0].ddtags).toContain("env:production");
    expect(logs[0].ddtags).toContain("tenant:t1");
    expect(logs[0].event).toBeDefined();
    expect(logs[0].message).toBe("blocked by guard");
  });

  it("sends metrics with correct series format", async () => {
    const exporter = new DatadogExporter({ apiKey: "dd-key" });

    const denied = makeEvent();
    const allowed = makeAllowedEvent();
    await exporter.export([denied, allowed]);

    const [metricsUrl, metricsInit] = fetchMock.mock.calls[1];
    expect(metricsUrl.toString()).toContain("api.datadoghq.com");
    expect(metricsUrl.toString()).toContain("/api/v1/series");

    const body = JSON.parse(metricsInit.body);
    expect(body.series).toHaveLength(3);

    const names = body.series.map((s: any) => s.metric);
    expect(names).toContain("clawdstrike.security.events.total");
    expect(names).toContain("clawdstrike.security.events.allowed");
    expect(names).toContain("clawdstrike.security.events.denied");

    const total = body.series.find((s: any) => s.metric.endsWith(".total"));
    expect(total.points[0][1]).toBe(2);
  });

  it("respects custom metrics prefix", async () => {
    const exporter = new DatadogExporter({
      apiKey: "dd-key",
      metrics: { prefix: "myapp" },
    });

    await exporter.export([makeEvent()]);

    const [, metricsInit] = fetchMock.mock.calls[1];
    const body = JSON.parse(metricsInit.body);
    expect(body.series[0].metric).toContain("myapp.");
  });

  it("skips metrics when disabled", async () => {
    const exporter = new DatadogExporter({
      apiKey: "dd-key",
      metrics: { enabled: false },
    });

    await exporter.export([makeEvent()]);

    // Only logs call, no metrics
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0];
    expect(url.toString()).toContain("logs");
  });

  it("uses correct site domain", async () => {
    const exporter = new DatadogExporter({
      apiKey: "dd-key",
      site: "datadoghq.eu",
    });

    await exporter.export([makeEvent()]);

    const [logsUrl] = fetchMock.mock.calls[0];
    expect(logsUrl.toString()).toContain("datadoghq.eu");

    const [metricsUrl] = fetchMock.mock.calls[1];
    expect(metricsUrl.toString()).toContain("datadoghq.eu");
  });

  it("returns empty result for empty events", async () => {
    const exporter = new DatadogExporter({ apiKey: "dd-key" });
    const result = await exporter.export([]);
    expect(result.exported).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps status correctly for denied/critical vs allowed events", async () => {
    const exporter = new DatadogExporter({ apiKey: "dd-key" });

    const criticalDenied = makeEvent({
      decision: { allowed: false, guard: "egress", severity: "critical", reason: "critical" },
    });
    await exporter.export([criticalDenied]);

    const [, logsInit] = fetchMock.mock.calls[0];
    const logs = JSON.parse(logsInit.body);
    expect(logs[0].status).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// ElasticExporter
// ---------------------------------------------------------------------------

describe("ElasticExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ errors: false }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sends events in NDJSON bulk format", async () => {
    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "security-events",
    });

    const event = makeEvent();
    const result = await exporter.export([event]);

    expect(result.exported).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toContain("elastic.example.com");
    expect(url.toString()).toContain("/_bulk");
    expect(init.headers["Content-Type"]).toBe("application/x-ndjson");

    // Body should be NDJSON: action line + document line per event, ending with \n
    const bodyStr = init.body as string;
    const lines = bodyStr.trim().split("\n");
    expect(lines).toHaveLength(2);

    const actionLine = JSON.parse(lines[0]);
    expect(actionLine.index._index).toBe("security-events");

    const docLine = JSON.parse(lines[1]);
    // ECS format
    expect(docLine["@timestamp"]).toBe(event.timestamp);
    expect(docLine.event.id).toBe(event.event_id);
  });

  it("uses ECS schema format", () => {
    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "test",
    });
    expect(exporter.schema).toBe(SchemaFormat.ECS);
  });

  it("sets ApiKey authorization header", async () => {
    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "test",
      auth: { apiKey: "my-elastic-api-key" },
    });

    await exporter.export([makeEvent()]);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("ApiKey my-elastic-api-key");
  });

  it("handles bulk response with partial errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            errors: true,
            items: [
              { index: { status: 201 } },
              { index: { status: 429, error: { type: "too_many_requests" } } },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      )
    );

    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "test",
    });

    const event1 = makeEvent();
    const event2 = makeEvent();
    const result = await exporter.export([event1, event2]);

    expect(result.exported).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].retryable).toBe(true); // 429 is retryable
  });

  it("handles bulk response with 500 errors as retryable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            errors: true,
            items: [{ index: { status: 503, error: { type: "unavailable" } } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      )
    );

    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "test",
    });

    const result = await exporter.export([makeEvent()]);
    expect(result.failed).toBe(1);
    expect(result.errors[0].retryable).toBe(true);
  });

  it("returns empty result for empty events", async () => {
    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "test",
    });

    const result = await exporter.export([]);
    expect(result.exported).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("handles multiple events in bulk format", async () => {
    const exporter = new ElasticExporter({
      baseUrl: "https://elastic.example.com",
      index: "events",
    });

    const events = [makeEvent(), makeEvent(), makeEvent()];
    const result = await exporter.export(events);

    expect(result.exported).toBe(3);
    const [, init] = fetchMock.mock.calls[0];
    const lines = (init.body as string).trim().split("\n");
    // 3 events * 2 lines each = 6
    expect(lines).toHaveLength(6);
  });
});

// ---------------------------------------------------------------------------
// SplunkExporter
// ---------------------------------------------------------------------------

describe("SplunkExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ text: "Success", code: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sends events to Splunk HEC endpoint", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "splunk-token-123",
      useAck: false,
      compression: false,
    });

    const event = makeEvent();
    const result = await exporter.export([event]);

    expect(result.exported).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toContain("splunk.example.com");
    expect(url.toString()).toContain("/services/collector/event");
    expect(init.headers.Authorization).toBe("Splunk splunk-token-123");
  });

  it("transforms events to Splunk HEC format", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      index: "security",
      sourceType: "clawdstrike:test",
      source: "test-source",
      useAck: false,
      compression: false,
    });

    const event = makeEvent();
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    const bodyStr = init.body as string;
    const splunkEvent = JSON.parse(bodyStr);

    expect(splunkEvent.index).toBe("security");
    expect(splunkEvent.sourcetype).toBe("clawdstrike:test");
    expect(splunkEvent.source).toBe("test-source");
    expect(typeof splunkEvent.time).toBe("number");
    expect(splunkEvent.event.event_id).toBe(event.event_id);
    expect(splunkEvent.event.decision.guard).toBe("egress");
    expect(splunkEvent.fields.severity).toBe("high");
    expect(splunkEvent.fields.guard).toBe("egress");
  });

  it("uses gzip compression by default", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      useAck: false,
      // compression defaults to true
    });

    await exporter.export([makeEvent()]);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["Content-Encoding"]).toBe("gzip");
    // Body should be a Buffer/Uint8Array (compressed)
    expect(init.body).toBeInstanceOf(Buffer);
  });

  it("sends X-Splunk-Request-Channel when ack is enabled", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      useAck: true,
      compression: false,
    });

    // Mock ack response for the ack poll
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ text: "Success", code: 0, ackId: 42 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ acks: { "42": true } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

    await exporter.export([makeEvent()]);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["X-Splunk-Request-Channel"]).toBeDefined();
  });

  it("returns empty result for empty events", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
    });

    const result = await exporter.export([]);
    expect(result.exported).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws on non-OK response", async () => {
    vi.stubGlobal("fetch", mockFetchStatus(503, "service unavailable"));

    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      useAck: false,
      compression: false,
    });

    await expect(exporter.export([makeEvent()])).rejects.toThrow("Splunk HEC HTTP 503");
  });

  it("throws on HEC error code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ text: "Invalid data format", code: 6 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      )
    );

    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      useAck: false,
      compression: false,
    });

    await expect(exporter.export([makeEvent()])).rejects.toThrow("Splunk HEC error code 6");
  });

  it("handles multiple events as newline-delimited JSON", async () => {
    const exporter = new SplunkExporter({
      hecUrl: "https://splunk.example.com:8088",
      hecToken: "token",
      useAck: false,
      compression: false,
    });

    const events = [makeEvent(), makeEvent()];
    await exporter.export(events);

    const [, init] = fetchMock.mock.calls[0];
    const bodyStr = init.body as string;
    const lines = bodyStr.split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
    // Each line is a valid JSON Splunk event
    for (const line of lines) {
      const parsed = JSON.parse(line);
      expect(parsed.event).toBeDefined();
      expect(parsed.sourcetype).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// SumoLogicExporter
// ---------------------------------------------------------------------------

describe("SumoLogicExporter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = mockFetchOk();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sends events with correct Sumo headers", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      sourceCategory: "security/test",
      sourceName: "test-source",
      sourceHost: "test-host",
      compression: false,
    });

    await exporter.export([makeEvent()]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://collectors.sumologic.com/receiver/v1/http/TOKEN");
    expect(init.headers["X-Sumo-Category"]).toBe("security/test");
    expect(init.headers["X-Sumo-Name"]).toBe("test-source");
    expect(init.headers["X-Sumo-Host"]).toBe("test-host");
  });

  it("sends JSON format by default", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      compression: false,
    });

    const event = makeEvent();
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["Content-Type"]).toBe("application/json");

    const body = init.body as string;
    const parsed = JSON.parse(body);
    expect(parsed.event_id).toBe(event.event_id);
    expect(parsed.decision.guard).toBe("egress");
  });

  it("supports text format", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      format: "text",
      compression: false,
    });

    const event = makeEvent();
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["Content-Type"]).toBe("text/plain");

    const body = init.body as string;
    expect(body).toContain("[HIGH]");
    expect(body).toContain("egress");
    expect(body).toContain("BLOCKED");
    expect(body).toContain(event.event_id);
  });

  it("supports key_value format", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      format: "key_value",
      compression: false,
    });

    const event = makeEvent();
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    const body = init.body as string;
    expect(body).toContain(`event_id=${event.event_id}`);
    expect(body).toContain("guard=egress");
    expect(body).toContain("severity=high");
    expect(body).toContain("allowed=false");
  });

  it("uses gzip compression by default", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
    });

    await exporter.export([makeEvent()]);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["Content-Encoding"]).toBe("gzip");
  });

  it("respects field exclusion", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      compression: false,
      fields: {
        includeAll: true,
        exclude: ["metadata", "labels"],
      },
    });

    const event = makeEvent({ metadata: { key: "val" }, labels: { team: "sec" } });
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    const parsed = JSON.parse(init.body as string);
    expect(parsed.metadata).toBeUndefined();
    expect(parsed.labels).toBeUndefined();
    expect(parsed.event_id).toBe(event.event_id);
  });

  it("respects field inclusion (selective fields)", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      compression: false,
      fields: {
        includeAll: false,
        include: ["event_id", "decision.guard", "decision.severity"],
      },
    });

    const event = makeEvent();
    await exporter.export([event]);

    const [, init] = fetchMock.mock.calls[0];
    const parsed = JSON.parse(init.body as string);
    expect(parsed.event_id).toBe(event.event_id);
    expect(parsed.decision.guard).toBe("egress");
    expect(parsed.decision.severity).toBe("high");
    // Other fields should NOT be present
    expect(parsed.agent).toBeUndefined();
    expect(parsed.session).toBeUndefined();
  });

  it("returns empty result for empty events", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
    });

    const result = await exporter.export([]);
    expect(result.exported).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("handles multiple events as newline-delimited", async () => {
    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      compression: false,
    });

    const events = [makeEvent(), makeEvent()];
    await exporter.export(events);

    const [, init] = fetchMock.mock.calls[0];
    const body = init.body as string;
    const lines = body.split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
  });

  it("throws on non-OK response", async () => {
    vi.stubGlobal("fetch", mockFetchStatus(403, "forbidden"));

    const exporter = new SumoLogicExporter({
      httpSourceUrl: "https://collectors.sumologic.com/receiver/v1/http/TOKEN",
      compression: false,
    });

    await expect(exporter.export([makeEvent()])).rejects.toThrow("Sumo HTTP 403");
  });
});
