import { describe, it, expect } from "vitest";

import { OutputSanitizer } from "../src/output-sanitizer";

describe("output sanitizer", () => {
  it("redacts known secrets", () => {
    const s = new OutputSanitizer();
    const key = "sk-" + "a".repeat(48);
    const r = s.sanitizeSync(`hello ${key} bye`);
    expect(r.redacted).toBe(true);
    expect(r.sanitized).not.toContain(key);
    expect(r.sanitized).toContain("[REDACTED:openai_api_key]");
  });

  it("supports allowlist exact strings", () => {
    const s = new OutputSanitizer({ allowlist: { exact: ["alice@example.com"] } });
    const r = s.sanitizeSync("alice@example.com");
    expect(r.redacted).toBe(false);
    expect(r.sanitized).toBe("alice@example.com");
  });

  it("supports denylist forced redaction", () => {
    const s = new OutputSanitizer({ denylist: { patterns: ["SECRET_PHRASE_123"] } });
    const r = s.sanitizeSync("ok SECRET_PHRASE_123 bye");
    expect(r.redacted).toBe(true);
    expect(r.sanitized).not.toContain("SECRET_PHRASE_123");
    expect(r.sanitized).toContain("[REDACTED:denylist]");
  });

  it("streaming redacts across chunk boundaries", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream();

    const key = "sk-" + "a".repeat(48);
    const out1 = stream.write(key.slice(0, 10));
    const out2 = stream.write(key.slice(10));
    const out3 = stream.flush();
    const combined = out1 + out2 + out3;

    expect(combined).not.toContain(key);
    expect(combined).toContain("[REDACTED:openai_api_key]");
  });

  it("streaming disabled sanitizes per-chunk without buffering", () => {
    const s = new OutputSanitizer({ streaming: { enabled: false } });
    const stream = s.createStream();

    const key = "sk-" + "a".repeat(48);
    const out1 = stream.write(`hello ${key} bye`);
    const out2 = stream.flush();
    const out3 = stream.end().sanitized;

    expect(out1).not.toContain(key);
    expect(out1).toContain("[REDACTED:openai_api_key]");
    expect(out2).toBe("");
    expect(out3).toBe("");
  });

  it("credit card detection requires luhn validity", () => {
    const s = new OutputSanitizer();
    const valid = "card=4111 1111 1111 1111";
    const invalid = "card=4111 1111 1111 1112";

    const rValid = s.sanitizeSync(valid);
    expect(rValid.redacted).toBe(true);
    expect(rValid.sanitized).not.toContain("4111 1111 1111 1111");

    const rInvalid = s.sanitizeSync(invalid);
    expect(rInvalid.redacted).toBe(false);
    expect(rInvalid.sanitized).toBe(invalid);
  });
});
