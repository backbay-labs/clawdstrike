import { describe, it, expect } from "vitest";

import { OutputSanitizer } from "../src/output-sanitizer";

// biome-ignore lint/suspicious/noExplicitAny: vitest global from setup.ts
const wasmAvailable = (globalThis as any).__WASM_AVAILABLE__ as boolean;

describe.skipIf(!wasmAvailable)("output sanitizer", () => {
  it("redacts known secrets", () => {
    const s = new OutputSanitizer();
    const key = "sk-" + "a".repeat(48);
    const r = s.sanitize(`hello ${key} bye`);
    expect(r.wasRedacted).toBe(true);
    expect(r.sanitized).not.toContain(key);
  });

  it("supports allowlist exact strings", () => {
    const s = new OutputSanitizer({ allowlist: { exact: ["alice@example.com"] } });
    const r = s.sanitize("alice@example.com");
    expect(r.wasRedacted).toBe(false);
    expect(r.sanitized).toBe("alice@example.com");
  });

  it("supports denylist forced redaction", () => {
    const s = new OutputSanitizer({ denylist: { patterns: ["SECRET_PHRASE_123"] } });
    const r = s.sanitize("ok SECRET_PHRASE_123 bye");
    expect(r.wasRedacted).toBe(true);
    expect(r.sanitized).not.toContain("SECRET_PHRASE_123");
  });

  it("does not hang on non-global denylist regexes", () => {
    const s = new OutputSanitizer({ denylist: { patterns: [/SECRET_PHRASE_123/] } });
    const r = s.sanitize("ok SECRET_PHRASE_123 bye");
    expect(r.wasRedacted).toBe(true);
    expect(r.sanitized).not.toContain("SECRET_PHRASE_123");
  });

  it("streaming buffers chunks and redacts on flush", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream();

    const key = "sk-" + "a".repeat(48);
    // Both writes go into the buffer (under default 50k bufferSize)
    expect(stream.write(key.slice(0, 10))).toBeNull();
    expect(stream.write(key.slice(10))).toBeNull();
    const result = stream.flush();

    expect(result.wasRedacted).toBe(true);
    expect(result.sanitized).not.toContain(key);
  });

  it("streaming flushes automatically when buffer fills", () => {
    const s = new OutputSanitizer();
    // Small buffer to force auto-flush
    const stream = s.createStream({ bufferSize: 20 });

    const key = "sk-" + "a".repeat(48);
    const r1 = stream.write(key);
    // Buffer exceeded 20 chars, should have auto-flushed
    expect(r1).not.toBeNull();
    expect(r1!.wasRedacted).toBe(true);
  });

  it("streaming does not duplicate overlap across auto-flush boundaries", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream({ bufferSize: 10, carryBytes: 3 });

    let out = "";
    const r1 = stream.write("abcdefghij");
    if (r1) out += r1.sanitized;

    const r2 = stream.write("klmnop");
    if (r2) out += r2.sanitized;

    out += stream.flush().sanitized;
    expect(out).toBe("abcdefghijklmnop");
  });

  it("streaming redacts secrets split across chunk boundaries", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream({ bufferSize: 20, carryBytes: 12 });

    const key = "sk-" + "a".repeat(48);
    let out = "";

    const r1 = stream.write(`hello ${key.slice(0, 16)}`);
    if (r1) out += r1.sanitized;

    const r2 = stream.write(`${key.slice(16)} bye`);
    if (r2) out += r2.sanitized;

    const final = stream.flush();
    out += final.sanitized;

    expect(out).not.toContain(key);
    expect(out).toContain("[REDACTED:openai_api_key]");
  });

  it("streaming does not leak delimiter-free secret prefixes across auto-flush boundaries", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream({ bufferSize: 20, carryBytes: 12 });

    const key = "sk-" + "a".repeat(48);
    let out = "";

    const r1 = stream.write(key.slice(0, 20));
    if (r1) out += r1.sanitized;

    const r2 = stream.write(key.slice(20));
    if (r2) out += r2.sanitized;

    out += stream.flush().sanitized;

    expect(out).not.toContain(key);
    expect(out).toContain("[REDACTED:openai_api_key]");
  });

  it("streaming flush returns sanitized result", () => {
    const s = new OutputSanitizer();
    const stream = s.createStream();

    const key = "sk-" + "a".repeat(48);
    stream.write(`hello ${key} bye`);
    const result = stream.flush();

    expect(result.wasRedacted).toBe(true);
    expect(result.sanitized).not.toContain(key);
  });

  it("credit card detection requires luhn validity", () => {
    const s = new OutputSanitizer();
    const valid = "card=4111 1111 1111 1111";
    const invalid = "card=4111 1111 1111 1112";

    const rValid = s.sanitize(valid);
    expect(rValid.wasRedacted).toBe(true);
    expect(rValid.sanitized).not.toContain("4111 1111 1111 1111");

    const rInvalid = s.sanitize(invalid);
    expect(rInvalid.wasRedacted).toBe(false);
    expect(rInvalid.sanitized).toBe(invalid);
  });
});
