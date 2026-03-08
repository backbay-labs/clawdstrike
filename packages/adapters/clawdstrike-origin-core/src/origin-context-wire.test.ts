import { describe, expect, it } from "vitest";
import {
  normalizeOriginContext,
  toWireOriginContext,
} from "./origin-context-wire.js";
import type {
  OriginContext,
  OriginContextInput,
  OriginContextWire,
} from "./index.js";

describe("normalizeOriginContext()", () => {
  it("normalizes canonical snake_case wire payloads into camelCase", () => {
    const input: OriginContextWire = {
      provider: "slack",
      tenant_id: "T123",
      space_id: "C456",
      space_type: "channel",
      thread_id: "123.456",
      actor_id: "U789",
      actor_type: "human",
      actor_role: "member",
      visibility: "external_shared",
      external_participants: true,
      tags: ["provider:slack", "visibility:external_shared"],
      sensitivity: "confidential",
      provenance_confidence: "strong",
      metadata: { team_name: "backbay" },
    };

    const normalized = normalizeOriginContext(input);

    expect(normalized).toEqual<OriginContext>({
      provider: "slack",
      tenantId: "T123",
      spaceId: "C456",
      spaceType: "channel",
      threadId: "123.456",
      actorId: "U789",
      actorType: "human",
      actorRole: "member",
      visibility: "external_shared",
      externalParticipants: true,
      tags: ["provider:slack", "visibility:external_shared"],
      sensitivity: "confidential",
      provenanceConfidence: "strong",
      metadata: { team_name: "backbay" },
    });
  });

  it("prefers camelCase fields when mixed payloads contain both aliases", () => {
    const normalized = normalizeOriginContext({
      provider: "github",
      tenantId: "org-camel",
      tenant_id: "org-snake",
      actorRole: "maintainer",
      actor_role: "guest",
      externalParticipants: false,
      external_participants: true,
      tags: ["provider:github"],
    });

    expect(normalized.tenantId).toBe("org-camel");
    expect(normalized.actorRole).toBe("maintainer");
    expect(normalized.externalParticipants).toBe(false);
  });

  it("defaults missing tags to an empty array", () => {
    const normalized = normalizeOriginContext({
      provider: "teams",
      tenant_id: "tenant-1",
    });

    expect(normalized.tags).toEqual([]);
  });
});

describe("toWireOriginContext()", () => {
  it("serializes camelCase origin contexts to canonical snake_case", () => {
    const input: OriginContext = {
      provider: "slack",
      tenantId: "T123",
      spaceId: "C456",
      spaceType: "channel",
      threadId: "123.456",
      actorId: "U789",
      actorType: "human",
      actorRole: "admin",
      visibility: "internal",
      externalParticipants: false,
      tags: ["provider:slack"],
      sensitivity: "restricted",
      provenanceConfidence: "medium",
      metadata: { locale: "en-US" },
    };

    const wire = toWireOriginContext(input);

    expect(wire).toEqual<OriginContextWire>({
      provider: "slack",
      tenant_id: "T123",
      space_id: "C456",
      space_type: "channel",
      thread_id: "123.456",
      actor_id: "U789",
      actor_type: "human",
      actor_role: "admin",
      visibility: "internal",
      external_participants: false,
      tags: ["provider:slack"],
      sensitivity: "restricted",
      provenance_confidence: "medium",
      metadata: { locale: "en-US" },
    });
    expect("tenantId" in wire).toBe(false);
    expect("actorRole" in wire).toBe(false);
  });

  it("normalizes mixed input before serializing", () => {
    const input: OriginContextInput = {
      provider: "slack",
      tenantId: "camel",
      tenant_id: "snake",
      actor_role: "member",
      tags: ["provider:slack"],
    };

    const wire = toWireOriginContext(input);

    expect(wire.tenant_id).toBe("camel");
    expect(wire.actor_role).toBe("member");
    expect(wire.tags).toEqual(["provider:slack"]);
  });
});
