import { describe, expect, it } from "vitest";
import { PolicyEventFactory } from "./policy-event-factory.js";
import type { CuaEventData } from "./types.js";

describe("PolicyEventFactory", () => {
  it("infers event type from tool name", () => {
    const factory = new PolicyEventFactory();
    expect(factory.inferEventType("cat", {})).toBe("file_read");
    expect(factory.inferEventType("writeFile", {})).toBe("file_write");
    expect(factory.inferEventType("bash", {})).toBe("command_exec");
  });

  it("infers event type from parameters", () => {
    const factory = new PolicyEventFactory();

    expect(factory.inferEventType("unknown", { path: "/tmp/a" })).toBe("file_read");
    expect(factory.inferEventType("unknown", { path: "/tmp/a", content: "hi" })).toBe("file_write");
    expect(factory.inferEventType("unknown", { url: "https://example.com" })).toBe(
      "network_egress",
    );
    expect(factory.inferEventType("unknown", { cmd: "ls -la" })).toBe("command_exec");
    expect(factory.inferEventType("unknown", { foo: "bar" })).toBe("tool_call");
  });

  it("keeps string file-write content available for local policy evaluation", () => {
    const factory = new PolicyEventFactory();
    const event = factory.create("write_file", {
      path: "/repo/src/index.ts",
      content: "const token = 'MY_RAW_SECRET_1234567890';",
    });

    expect(event.eventType).toBe("file_write");
    expect(event.data.type).toBe("file");
    if (event.data.type === "file") {
      expect(event.data.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(event.data.content).toBe("const token = 'MY_RAW_SECRET_1234567890';");
    }
  });

  it("keeps base64 file-write content available for local policy evaluation", () => {
    const factory = new PolicyEventFactory();
    const rawContent = "binary bytes with MY_RAW_SECRET_1234567890";
    const contentBase64 = Buffer.from(rawContent, "utf8").toString("base64");
    const event = factory.create("write_file", {
      path: "/repo/blob.bin",
      contentBase64,
    });

    expect(event.eventType).toBe("file_write");
    expect(event.data.type).toBe("file");
    if (event.data.type === "file") {
      expect(event.data.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(event.data.contentBase64).toBe(contentBase64);
      expect(event.data.content).toBeUndefined();
    }
  });

  it("computes a file content hash from binary content without retaining raw bytes", () => {
    const factory = new PolicyEventFactory();
    const rawContent = Buffer.from("binary bytes with MY_RAW_SECRET_1234567890", "utf8");
    const event = factory.create("write_file", {
      path: "/repo/blob.bin",
      content: rawContent,
    });

    expect(event.eventType).toBe("file_write");
    expect(event.data.type).toBe("file");
    if (event.data.type === "file") {
      expect(event.data.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(event.data.contentBase64).toBe(rawContent.toString("base64"));
      expect(event.data.content).toBeUndefined();
    }
  });

  it("computes a patch hash from raw patch input", () => {
    const factory = new PolicyEventFactory();
    const patch = [
      "*** Begin Patch",
      "*** Update File: /repo/src/index.ts",
      "+const token = 'MY_RAW_SECRET_1234567890';",
      "*** End Patch",
    ].join("\n");

    const event = factory.create("apply_patch", {
      file: "/repo/src/index.ts",
      patch,
    });

    expect(event.eventType).toBe("patch_apply");
    expect(event.data.type).toBe("patch");
    if (event.data.type === "patch") {
      expect(event.data.patchHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(event.data.patchContent).toBe(patch);
    }
  });

  it("drops invalid numeric port suffixes when parsing network targets", () => {
    const factory = new PolicyEventFactory();

    const event = factory.create("fetch", { url: "api.example.com:0" });
    expect(event.eventType).toBe("network_egress");
    expect(event.data.type).toBe("network");

    if (event.data.type === "network") {
      expect(event.data.host).toBe("api.example.com");
      expect(event.data.port).toBe(443);
    }
  });

  it("rejects invalid explicit port overrides and keeps parsed/default port", () => {
    const factory = new PolicyEventFactory();

    const invalidOverrides = [0, -1, 65536, "0", "70000", "443abc", "abc"];
    for (const override of invalidOverrides) {
      const event = factory.create("fetch", { url: "api.example.com", port: override });
      expect(event.eventType).toBe("network_egress");
      expect(event.data.type).toBe("network");

      if (event.data.type === "network") {
        expect(event.data.host).toBe("api.example.com");
        expect(event.data.port).toBe(443);
      }
    }

    const valid = factory.create("fetch", { url: "api.example.com", port: "8080" });
    expect(valid.data.type).toBe("network");
    if (valid.data.type === "network") {
      expect(valid.data.port).toBe(8080);
    }
  });

  it("fails closed for hostless or scheme-only network targets", () => {
    const factory = new PolicyEventFactory();

    const fileEvent = factory.create("fetch", { url: "file:///tmp/a" });
    expect(fileEvent.eventType).toBe("network_egress");
    expect(fileEvent.data.type).toBe("network");

    if (fileEvent.data.type === "network") {
      expect(fileEvent.data.host).toBe("");
    }

    const mailtoEvent = factory.create("fetch", { url: "mailto:user@example.com" });
    expect(mailtoEvent.eventType).toBe("network_egress");
    expect(mailtoEvent.data.type).toBe("network");

    if (mailtoEvent.data.type === "network") {
      expect(mailtoEvent.data.host).toBe("");
    }

    const urnEvent = factory.create("fetch", { url: "urn:isbn:0451450523" });
    expect(urnEvent.eventType).toBe("network_egress");
    expect(urnEvent.data.type).toBe("network");

    if (urnEvent.data.type === "network") {
      expect(urnEvent.data.host).toBe("");
    }
  });

  it("CUA connect event creates correct structure", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaConnectEvent("sess-001");

    expect(event.eventType).toBe("remote.session.connect");
    expect(event.sessionId).toBe("sess-001");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("session.connect");
  });

  it("CUA reconnect event preserves continuity hash", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaReconnectEvent("sess-002", {
      continuityPrevSessionHash: "abc123deadbeef",
    });

    expect(event.eventType).toBe("remote.session.reconnect");
    expect(event.sessionId).toBe("sess-002");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("session.reconnect");
    expect(data.continuityPrevSessionHash).toBe("abc123deadbeef");
  });

  it("CUA input inject event preserves probe hash", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaInputInjectEvent("sess-003", {
      postconditionProbeHash: "probe-hash-456",
    });

    expect(event.eventType).toBe("input.inject");
    expect(event.sessionId).toBe("sess-003");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("input.inject");
    expect(data.postconditionProbeHash).toBe("probe-hash-456");
  });

  it("CUA clipboard event preserves direction", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaClipboardEvent("sess-004", "read");

    expect(event.eventType).toBe("remote.clipboard");
    expect(event.sessionId).toBe("sess-004");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("clipboard");
    expect(data.direction).toBe("read");
  });

  it("CUA file transfer event preserves direction", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaFileTransferEvent("sess-005", "upload");

    expect(event.eventType).toBe("remote.file_transfer");
    expect(event.sessionId).toBe("sess-005");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("file_transfer");
    expect(data.direction).toBe("upload");
  });

  it("CUA audio event emits remote.audio eventType", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaAudioEvent("sess-006");

    expect(event.eventType).toBe("remote.audio");
    expect(event.sessionId).toBe("sess-006");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("audio");
  });

  it("CUA drive mapping event emits remote.drive_mapping eventType", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaDriveMappingEvent("sess-007");

    expect(event.eventType).toBe("remote.drive_mapping");
    expect(event.sessionId).toBe("sess-007");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("drive_mapping");
  });

  it("CUA printing event emits remote.printing eventType", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaPrintingEvent("sess-008");

    expect(event.eventType).toBe("remote.printing");
    expect(event.sessionId).toBe("sess-008");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.cuaAction).toBe("printing");
  });

  it("CUA session connect event supports outbound direction metadata", () => {
    const factory = new PolicyEventFactory();
    const event = factory.createCuaConnectEvent("sess-009", { direction: "outbound" });

    expect(event.eventType).toBe("remote.session.connect");
    expect(event.data.type).toBe("cua");

    const data = event.data as CuaEventData;
    expect(data.direction).toBe("outbound");
  });
});
