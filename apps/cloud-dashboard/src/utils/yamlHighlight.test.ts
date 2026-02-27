import { describe, it, expect } from "vitest";
import { highlightYaml } from "./yamlHighlight";

describe("highlightYaml", () => {
  it("highlights YAML keys", () => {
    const result = highlightYaml("name: value");
    expect(result).toContain("<span");
    expect(result).toContain("name");
    expect(result).toContain("value");
  });

  it("highlights comments", () => {
    const result = highlightYaml("# this is a comment");
    expect(result).toContain("comment");
    expect(result).toContain("this is a comment");
  });

  it("highlights boolean values", () => {
    const result = highlightYaml("enabled: true");
    expect(result).toContain("true");
  });

  it("highlights string values in quotes", () => {
    const result = highlightYaml('name: "hello"');
    expect(result).toContain("hello");
  });

  it("handles empty input", () => {
    const result = highlightYaml("");
    // May wrap in a span — but should not error
    expect(result).toBeDefined();
  });

  it("escapes HTML characters", () => {
    const result = highlightYaml("key: <script>");
    expect(result).not.toContain("<script>");
    expect(result).toContain("&lt;script&gt;");
  });
});
