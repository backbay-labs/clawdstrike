import { describe, expect, it } from "vitest";

import { detectFileType, getFileTypeByExtension } from "../file-type-registry";

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
});
