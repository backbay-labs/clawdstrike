import { describe, expect, it } from "vitest";
import type {
  ProviderEvent,
  ProviderPayload,
  ProviderResponse,
  TrustAdapter,
} from "./adapter.js";
import type {
  ApprovalDecision,
  ApprovalRequest,
  OriginContext,
  ProvenanceConfidence,
  ProvenanceResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Mock adapter
// ---------------------------------------------------------------------------

class MockTestAdapter implements TrustAdapter {
  readonly provider = "slack" as const;

  async validate(event: ProviderEvent): Promise<ProvenanceResult> {
    const sig = event.headers["x-slack-signature"];
    if (sig === "valid-sig") {
      return {
        valid: true,
        confidence: "strong",
        provider: this.provider,
        details: { mechanism: "hmac-sha256" },
      };
    }
    return {
      valid: false,
      confidence: "unknown",
      provider: this.provider,
      error: "invalid signature",
    };
  }

  async normalize(event: ProviderEvent): Promise<OriginContext> {
    const body = event.body as Record<string, unknown>;
    return {
      provider: this.provider,
      tenantId: body["team_id"] as string | undefined,
      spaceId: body["channel_id"] as string | undefined,
      spaceType: "channel",
      threadId: body["thread_ts"] as string | undefined,
      actorId: body["user_id"] as string | undefined,
      actorType: "human",
      visibility: "internal",
      externalParticipants: false,
      tags: this.deriveTags({
        provider: this.provider,
        visibility: "internal",
        tags: [],
      }),
    };
  }

  async renderApprovalRequest(request: ApprovalRequest): Promise<ProviderPayload> {
    return {
      format: "slack-blocks",
      content: {
        blocks: [
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*Approval Required*\nTool: \`${request.toolName}\`\nReason: ${request.reason}`,
            },
          },
          {
            type: "actions",
            elements: [
              {
                type: "button",
                text: { type: "plain_text", text: "Approve" },
                action_id: `approve_${request.id}`,
                style: "primary",
              },
              {
                type: "button",
                text: { type: "plain_text", text: "Deny" },
                action_id: `deny_${request.id}`,
                style: "danger",
              },
            ],
          },
        ],
      },
    };
  }

  async consumeApprovalResponse(response: ProviderResponse): Promise<ApprovalDecision> {
    const body = response.body as Record<string, unknown>;
    const actionId = body["action_id"] as string;
    if (actionId?.startsWith("approve_")) {
      return {
        status: "approved",
        approvedBy: (body["user_id"] as string) ?? "unknown",
        scope: { ttlSeconds: 300, threadOnly: true },
      };
    }
    if (actionId?.startsWith("deny_")) {
      return {
        status: "denied",
        deniedBy: (body["user_id"] as string) ?? "unknown",
        reason: "Denied by operator",
      };
    }
    return { status: "expired" };
  }

  deriveTags(context: OriginContext): string[] {
    const tags: string[] = [`provider:${context.provider}`];
    if (context.visibility) {
      tags.push(`visibility:${context.visibility}`);
    }
    if (context.externalParticipants) {
      tags.push("external-participants");
    }
    if (context.spaceType) {
      tags.push(`space-type:${context.spaceType}`);
    }
    return tags;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<ProviderEvent> = {}): ProviderEvent {
  return {
    headers: { "x-slack-signature": "valid-sig" },
    body: {
      team_id: "T12345",
      channel_id: "C67890",
      user_id: "U11111",
      thread_ts: "1234567890.123456",
    },
    receivedAt: new Date("2026-03-07T00:00:00Z"),
    ...overrides,
  };
}

function makeApprovalRequest(): ApprovalRequest {
  return {
    id: "req-001",
    originContext: {
      provider: "slack",
      tenantId: "T12345",
      spaceId: "C67890",
      visibility: "internal",
      tags: [],
    },
    enclaveId: "enclave-default",
    toolName: "file_write",
    toolArgs: { path: "/etc/hosts" },
    reason: "Writing to sensitive system file",
    requestedBy: "U11111",
    requestedAt: "2026-03-07T00:00:00Z",
    expiresAt: "2026-03-07T00:05:00Z",
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TrustAdapter interface", () => {
  const adapter = new MockTestAdapter();

  it("satisfies the TrustAdapter interface", () => {
    // Compile-time check: if MockTestAdapter doesn't implement TrustAdapter,
    // this assignment would fail at the type level.
    const _a: TrustAdapter = adapter;
    expect(_a.provider).toBe("slack");
  });

  it("has a readonly provider property", () => {
    expect(adapter.provider).toBe("slack");
  });
});

describe("validate()", () => {
  const adapter = new MockTestAdapter();

  it("returns valid ProvenanceResult for valid signature", async () => {
    const event = makeEvent();
    const result = await adapter.validate(event);

    expect(result.valid).toBe(true);
    expect(result.confidence).toBe("strong");
    expect(result.provider).toBe("slack");
    expect(result.details).toEqual({ mechanism: "hmac-sha256" });
    expect(result.error).toBeUndefined();
  });

  it("returns invalid ProvenanceResult for bad signature", async () => {
    const event = makeEvent({
      headers: { "x-slack-signature": "bad-sig" },
    });
    const result = await adapter.validate(event);

    expect(result.valid).toBe(false);
    expect(result.confidence).toBe("unknown");
    expect(result.error).toBe("invalid signature");
  });

  it("returns invalid ProvenanceResult for missing signature", async () => {
    const event = makeEvent({ headers: {} });
    const result = await adapter.validate(event);

    expect(result.valid).toBe(false);
    expect(result.confidence).toBe("unknown");
  });
});

describe("normalize()", () => {
  const adapter = new MockTestAdapter();

  it("returns OriginContext with correct fields", async () => {
    const event = makeEvent();
    const ctx = await adapter.normalize(event);

    expect(ctx.provider).toBe("slack");
    expect(ctx.tenantId).toBe("T12345");
    expect(ctx.spaceId).toBe("C67890");
    expect(ctx.spaceType).toBe("channel");
    expect(ctx.threadId).toBe("1234567890.123456");
    expect(ctx.actorId).toBe("U11111");
    expect(ctx.actorType).toBe("human");
    expect(ctx.actorRole).toBeUndefined();
    expect(ctx.visibility).toBe("internal");
    expect(ctx.externalParticipants).toBe(false);
  });

  it("includes derived tags in the context", async () => {
    const event = makeEvent();
    const ctx = await adapter.normalize(event);

    expect(ctx.tags).toBeDefined();
    expect(ctx.tags).toContain("provider:slack");
    expect(ctx.tags).toContain("visibility:internal");
  });

  it("handles minimal event body", async () => {
    const event = makeEvent({ body: {} });
    const ctx = await adapter.normalize(event);

    expect(ctx.provider).toBe("slack");
    expect(ctx.tenantId).toBeUndefined();
    expect(ctx.spaceId).toBeUndefined();
  });
});

describe("deriveTags()", () => {
  const adapter = new MockTestAdapter();

  it("returns string array with provider tag", () => {
    const tags = adapter.deriveTags({ provider: "slack", tags: [] });
    expect(Array.isArray(tags)).toBe(true);
    expect(tags).toContain("provider:slack");
  });

  it("includes visibility tag when present", () => {
    const tags = adapter.deriveTags({
      provider: "slack",
      tags: [],
      visibility: "public",
    });
    expect(tags).toContain("visibility:public");
  });

  it("includes external-participants tag when true", () => {
    const tags = adapter.deriveTags({
      provider: "slack",
      tags: [],
      externalParticipants: true,
    });
    expect(tags).toContain("external-participants");
  });

  it("includes space-type tag when present", () => {
    const tags = adapter.deriveTags({
      provider: "github",
      tags: [],
      spaceType: "pull_request",
    });
    expect(tags).toContain("space-type:pull_request");
  });

  it("does not include absent optional tags", () => {
    const tags = adapter.deriveTags({ provider: "slack", tags: [] });
    expect(tags).not.toContain("external-participants");
    const hasVisibility = tags.some((t) => t.startsWith("visibility:"));
    expect(hasVisibility).toBe(false);
  });
});

describe("renderApprovalRequest()", () => {
  const adapter = new MockTestAdapter();

  it("returns a ProviderPayload with correct format", async () => {
    const payload = await adapter.renderApprovalRequest(makeApprovalRequest());

    expect(payload.format).toBe("slack-blocks");
    expect(payload.content).toBeDefined();
  });

  it("includes tool name in rendered content", async () => {
    const payload = await adapter.renderApprovalRequest(makeApprovalRequest());
    const json = JSON.stringify(payload.content);

    expect(json).toContain("file_write");
  });
});

describe("consumeApprovalResponse()", () => {
  const adapter = new MockTestAdapter();

  it("returns approved decision for approve action", async () => {
    const response: ProviderResponse = {
      headers: {},
      body: { action_id: "approve_req-001", user_id: "U99999" },
      receivedAt: new Date(),
    };
    const decision = await adapter.consumeApprovalResponse(response);

    expect(decision.status).toBe("approved");
    if (decision.status === "approved") {
      expect(decision.approvedBy).toBe("U99999");
      expect(decision.scope?.ttlSeconds).toBe(300);
      expect(decision.scope?.threadOnly).toBe(true);
    }
  });

  it("returns denied decision for deny action", async () => {
    const response: ProviderResponse = {
      headers: {},
      body: { action_id: "deny_req-001", user_id: "U99999" },
      receivedAt: new Date(),
    };
    const decision = await adapter.consumeApprovalResponse(response);

    expect(decision.status).toBe("denied");
    if (decision.status === "denied") {
      expect(decision.deniedBy).toBe("U99999");
      expect(decision.reason).toBe("Denied by operator");
    }
  });

  it("returns expired decision for unknown action", async () => {
    const response: ProviderResponse = {
      headers: {},
      body: { action_id: "unknown_action" },
      receivedAt: new Date(),
    };
    const decision = await adapter.consumeApprovalResponse(response);

    expect(decision.status).toBe("expired");
  });
});

describe("OriginContext type structure", () => {
  it("accepts a minimal OriginContext (provider only)", () => {
    const ctx: OriginContext = { provider: "slack", tags: [] };
    expect(ctx.provider).toBe("slack");
    expect(ctx.tenantId).toBeUndefined();
  });

  it("accepts a fully-populated OriginContext", () => {
    const ctx: OriginContext = {
      provider: "github",
      tenantId: "org-123",
      spaceId: "repo-456",
      spaceType: "pull_request",
      threadId: "pr-789",
      actorId: "user-abc",
      actorType: "human",
      actorRole: "maintainer",
      visibility: "internal",
      externalParticipants: false,
      tags: ["provider:github", "visibility:internal"],
      sensitivity: "confidential",
      provenanceConfidence: "strong",
      metadata: { installation_id: 12345 },
    };
    expect(ctx.provider).toBe("github");
    expect(ctx.spaceType).toBe("pull_request");
    expect(ctx.actorRole).toBe("maintainer");
    expect(ctx.tags).toHaveLength(2);
    expect(ctx.metadata?.["installation_id"]).toBe(12345);
  });

  it("accepts custom provider strings", () => {
    const ctx: OriginContext = { provider: "custom-provider", tags: [] };
    expect(ctx.provider).toBe("custom-provider");
  });

  it("accepts custom space type strings", () => {
    const ctx: OriginContext = {
      provider: "jira",
      spaceType: "epic",
      tags: [],
    };
    expect(ctx.spaceType).toBe("epic");
  });
});

describe("ProvenanceResult confidence levels", () => {
  const levels: ProvenanceConfidence[] = ["strong", "medium", "weak", "unknown"];

  for (const level of levels) {
    it(`accepts confidence level '${level}'`, () => {
      const result: ProvenanceResult = {
        valid: level !== "unknown",
        confidence: level,
        provider: "slack",
      };
      expect(result.confidence).toBe(level);
    });
  }

  it("includes optional details field", () => {
    const result: ProvenanceResult = {
      valid: true,
      confidence: "strong",
      provider: "github",
      details: { verified_at: "2026-03-07T00:00:00Z" },
    };
    expect(result.details?.["verified_at"]).toBe("2026-03-07T00:00:00Z");
  });

  it("includes optional error field on failure", () => {
    const result: ProvenanceResult = {
      valid: false,
      confidence: "unknown",
      provider: "slack",
      error: "HMAC mismatch",
    };
    expect(result.error).toBe("HMAC mismatch");
  });
});
