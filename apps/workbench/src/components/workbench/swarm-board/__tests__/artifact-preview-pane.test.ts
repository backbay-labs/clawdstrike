import { describe, expect, it } from "vitest";
import {
  isMarkdownArtifact,
  normalizeArtifactPreviewContent,
} from "../artifact-preview-pane";

describe("artifact-preview-pane helpers", () => {
  it("detects markdown artifacts from file path", () => {
    expect(isMarkdownArtifact("/tmp/README.md")).toBe(true);
    expect(isMarkdownArtifact("/tmp/rule.yaml", "clawdstrike_policy")).toBe(
      false,
    );
  });

  it("pretty prints yaml artifacts", () => {
    expect(
      normalizeArtifactPreviewContent(
        "b: 2\na: 1\n",
        "/tmp/policy.yaml",
        "clawdstrike_policy",
      ),
    ).toBe("a: 1\nb: 2");
  });

  it("pretty prints json artifacts", () => {
    expect(
      normalizeArtifactPreviewContent('{"b":2,"a":1}', "/tmp/event.json"),
    ).toBe('{\n  "b": 2,\n  "a": 1\n}');
  });
});
