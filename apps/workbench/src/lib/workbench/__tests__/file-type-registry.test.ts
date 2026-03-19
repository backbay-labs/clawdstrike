import { describe, expect, it } from "vitest";

import { detectFileType, FILE_TYPE_REGISTRY, getFileTypeByExtension } from "../file-type-registry";

describe("file-type-registry", () => {
  it("treats json extensions as ambiguous until content is inspected", () => {
    expect(getFileTypeByExtension("event.json")).toBeNull();
    expect(getFileTypeByExtension("policy.json")).toBeNull();
  });

  it("detects JSON policy exports as clawdstrike_policy", () => {
    const content = JSON.stringify({
      schema_version: "1.5.0",
      guards: {
        forbidden_path: {
          enabled: true,
        },
      },
    });

    expect(detectFileType("policy.json", content)).toBe("clawdstrike_policy");
  });

  it("detects structurally valid OCSF JSON as ocsf_event", () => {
    const content = JSON.stringify({
      class_uid: 2004,
      category_uid: 2,
      metadata: {
        version: "1.4.0",
      },
      finding_info: {
        title: "Suspicious event",
      },
    });

    expect(detectFileType("event.json", content)).toBe("ocsf_event");
  });

  it("does not classify arbitrary json files as ocsf_event", () => {
    const content = JSON.stringify({
      name: "fixture",
      version: "1.0.0",
    });

    expect(detectFileType("package.json", content)).toBe("clawdstrike_policy");
  });

  // Receipt / evidence file type tests
  describe("receipt file type", () => {
    it("detectFileType('agent.receipt', '...') returns 'receipt'", () => {
      expect(detectFileType("agent.receipt", "...")).toBe("receipt");
    });

    it("detectFileType('evidence.hush', '...') returns 'receipt'", () => {
      expect(detectFileType("evidence.hush", "...")).toBe("receipt");
    });

    it("getFileTypeByExtension('foo.receipt') returns 'receipt'", () => {
      expect(getFileTypeByExtension("foo.receipt")).toBe("receipt");
    });

    it("getFileTypeByExtension('foo.hush') returns 'receipt'", () => {
      expect(getFileTypeByExtension("foo.hush")).toBe("receipt");
    });

    it("FILE_TYPE_REGISTRY['receipt'] has iconColor '#7ee6f2', testable=false, extensions ['.receipt', '.hush']", () => {
      const descriptor = FILE_TYPE_REGISTRY["receipt"];
      expect(descriptor.iconColor).toBe("#7ee6f2");
      expect(descriptor.testable).toBe(false);
      expect(descriptor.extensions).toEqual([".receipt", ".hush"]);
    });
  });
});
