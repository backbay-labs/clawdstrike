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

describe("adversarial XSS inputs", () => {
  it("escapes script injection", () => {
    const result = highlightYaml("<script>alert(1)</script>");
    expect(result).toContain("&lt;script&gt;");
    expect(result).not.toContain("<script>");
  });

  it("escapes attribute injection via double quotes", () => {
    const result = highlightYaml('" onmouseover="alert(1)"');
    // User-supplied quotes must be escaped; the output should contain &quot; for input quotes
    expect(result).toContain("&quot;");
    // The input's quotes must not survive as literal " in the text content
    // (strip HTML tags and check no unescaped quotes remain in text)
    const textContent = result.replace(/<[^>]*>/g, "");
    expect(textContent).not.toContain('"');
  });

  it("renders template injection as inert text", () => {
    const result = highlightYaml("{{constructor.constructor('alert(1)')()}}");
    // Strip the wrapper <span> tags from the highlighter, then verify no angle brackets remain in text
    const textContent = result.replace(/<[^>]*>/g, "");
    expect(textContent).not.toContain("<");
    expect(textContent).not.toContain(">");
    // The curly braces should pass through as-is
    expect(result).toContain("{{constructor");
  });

  it("prevents double-encoding by escaping ampersands first", () => {
    const result = highlightYaml("&amp;lt;script&amp;gt;");
    // The & in &amp; should be escaped to &amp;amp;
    expect(result).toContain("&amp;amp;");
    // Must not contain a literal < from double-decode
    expect(result).not.toContain("<script");
  });

  it("handles null bytes without bypassing escaping", () => {
    const result = highlightYaml("key: <\0script>alert(1)</\0script>");
    expect(result).not.toContain("<script>");
    expect(result).not.toContain("<\0script>");
    expect(result).toContain("&lt;");
  });

  it("escapes event handler injection in img tags", () => {
    const result = highlightYaml("<img src=x onerror=alert(1)>");
    expect(result).toContain("&lt;img");
    expect(result).not.toContain("<img");
  });

  it("escapes multi-line XSS attempts", () => {
    const input = [
      "name: safe",
      'value: "<img src=x',
      '  onerror=alert(1)>"',
      "other: <script>xss</script>",
    ].join("\n");
    const result = highlightYaml(input);
    expect(result).not.toContain("<img");
    expect(result).not.toContain("<script>");
    expect(result).toContain("&lt;script&gt;");
    expect(result).toContain("&lt;img");
  });
});
