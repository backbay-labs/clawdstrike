import { describe, it, expect } from "vitest";
import {
  redactEvidenceItem,
  redactEvidencePack,
  MAX_STRUCTURED_EVENT_SIZE,
  MAX_BYTE_SAMPLE_SIZE,
} from "../detection-workflow/evidence-redaction";
import type { EvidenceItem, EvidencePack } from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";

describe("redactEvidenceItem", () => {
  it("redacts sensitive keys from structured events", () => {
    const item: EvidenceItem = {
      id: "item-1",
      kind: "structured_event",
      format: "json",
      payload: {
        username: "admin",
        password: "s3cret",
        api_key: "sk-12345",
        data: "visible",
      },
      expected: "match",
    };

    const result = redactEvidenceItem(item);
    const payload = (result.item as { payload: Record<string, unknown> }).payload;
    expect(payload.username).toBe("admin");
    expect(payload.password).toBe("[REDACTED]");
    expect(payload.api_key).toBe("[REDACTED]");
    expect(payload.data).toBe("visible");
    expect(result.fieldsRedacted).toContain("password");
    expect(result.fieldsRedacted).toContain("api_key");
  });

  it("redacts nested sensitive keys", () => {
    const item: EvidenceItem = {
      id: "item-2",
      kind: "structured_event",
      format: "json",
      payload: {
        config: {
          access_token: "tok-123",
          endpoint: "https://api.example.com",
        },
      },
      expected: "match",
    };

    const result = redactEvidenceItem(item);
    const payload = (result.item as { payload: Record<string, unknown> }).payload;
    const config = payload.config as Record<string, unknown>;
    expect(config.access_token).toBe("[REDACTED]");
    expect(config.endpoint).toBe("https://api.example.com");
    expect(result.fieldsRedacted).toContain("config.access_token");
  });

  it("redacts sensitive keys in arrays", () => {
    const item: EvidenceItem = {
      id: "item-3",
      kind: "structured_event",
      format: "json",
      payload: {
        items: [
          { name: "ok", secret: "hidden" },
          { name: "visible", token: "hidden-too" },
        ],
      },
      expected: "match",
    };

    const result = redactEvidenceItem(item);
    const payload = (result.item as { payload: Record<string, unknown> }).payload;
    const items = payload.items as Record<string, unknown>[];
    expect(items[0].secret).toBe("[REDACTED]");
    expect(items[0].name).toBe("ok");
    expect(items[1].token).toBe("[REDACTED]");
    expect(items[1].name).toBe("visible");
  });

  it("marks oversized structured events", () => {
    const bigPayload: Record<string, unknown> = {};
    // Create a payload larger than 64KB
    bigPayload.data = "x".repeat(MAX_STRUCTURED_EVENT_SIZE + 1);

    const item: EvidenceItem = {
      id: "item-big",
      kind: "structured_event",
      format: "json",
      payload: bigPayload,
      expected: "match",
    };

    const result = redactEvidenceItem(item);
    expect(result.oversized).toBe(true);
  });

  it("marks oversized byte samples", () => {
    const item: EvidenceItem = {
      id: "item-bytes",
      kind: "bytes",
      encoding: "utf8",
      payload: "x".repeat(MAX_BYTE_SAMPLE_SIZE + 1),
      expected: "match",
    };

    const result = redactEvidenceItem(item);
    expect(result.oversized).toBe(true);
  });

  it("does not redact policy scenarios", () => {
    const item: EvidenceItem = {
      id: "item-scenario",
      kind: "policy_scenario",
      scenario: {
        id: "s1",
        name: "test",
        description: "test scenario",
        category: "benign",
        actionType: "file_access",
        payload: { password: "should-stay" },
      },
      expected: "allow",
    };

    const result = redactEvidenceItem(item);
    expect(result.fieldsRedacted).toHaveLength(0);
  });

  it("redacts OCSF events the same as structured events", () => {
    const item: EvidenceItem = {
      id: "item-ocsf",
      kind: "ocsf_event",
      payload: {
        class_uid: 1001,
        credentials: { api_key: "hidden" },
        message: "visible",
      },
      expected: "valid",
    };

    const result = redactEvidenceItem(item);
    const payload = (result.item as { payload: Record<string, unknown> }).payload;
    expect(payload.credentials).toBe("[REDACTED]");
    expect(payload.message).toBe("visible");
  });
});

describe("redactEvidencePack", () => {
  it("redacts all items in all datasets", () => {
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-1",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "p1",
            kind: "structured_event",
            format: "json",
            payload: { password: "hidden", data: "visible" },
            expected: "match",
          },
        ],
        negative: [
          {
            id: "n1",
            kind: "structured_event",
            format: "json",
            payload: { secret: "hidden", info: "ok" },
            expected: "no_match",
          },
        ],
      },
      redactionState: "clean",
    };

    const result = redactEvidencePack(pack);
    expect(result.totalFieldsRedacted).toBe(2);
    expect(result.pack.redactionState).toBe("redacted");

    const p1 = result.pack.datasets.positive[0] as { payload: Record<string, unknown> };
    expect(p1.payload.password).toBe("[REDACTED]");
    expect(p1.payload.data).toBe("visible");
  });

  it("reports oversized items", () => {
    const pack: EvidencePack = {
      id: "pack-2",
      documentId: "doc-2",
      fileType: "yara_rule",
      title: "Big Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "big-item",
            kind: "bytes",
            encoding: "utf8",
            payload: "x".repeat(MAX_BYTE_SAMPLE_SIZE + 1),
            expected: "match",
          },
        ],
      },
      redactionState: "clean",
    };

    const result = redactEvidencePack(pack);
    expect(result.oversizedItems).toContain("big-item");
  });

  it("preserves redactionState when nothing was redacted", () => {
    const pack: EvidencePack = {
      id: "pack-3",
      documentId: "doc-3",
      fileType: "clawdstrike_policy",
      title: "Clean Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "clean-item",
            kind: "structured_event",
            format: "json",
            payload: { name: "visible", count: 42 },
            expected: "match",
          },
        ],
      },
      redactionState: "clean",
    };

    const result = redactEvidencePack(pack);
    expect(result.totalFieldsRedacted).toBe(0);
    expect(result.pack.redactionState).toBe("clean");
  });
});
