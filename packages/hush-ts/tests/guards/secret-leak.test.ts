import { describe, it, expect } from "vitest";
import { SecretLeakGuard, SecretLeakConfig } from "../../src/guards/secret-leak";
import { GuardAction, GuardContext, Severity } from "../../src/guards/types";

describe("SecretLeakGuard", () => {
  it("has correct name", () => {
    const guard = new SecretLeakGuard();
    expect(guard.name).toBe("secret_leak");
  });

  it("handles custom output actions", () => {
    const guard = new SecretLeakGuard();

    expect(guard.handles(GuardAction.custom("output", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("bash_output", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("tool_result", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("response", {}))).toBe(true);
    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(false);
  });

  it("allows when no secrets configured", () => {
    const guard = new SecretLeakGuard();
    const action = GuardAction.custom("output", { content: "secret data" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("blocks when secret is found in output", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key-12345"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", {
      content: "Found: super-secret-key-12345",
    });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("Secret");
  });

  it("allows when secret not present", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key-12345"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", {
      content: "Normal output without secrets",
    });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("checks multiple content fields", () => {
    const config: SecretLeakConfig = {
      secrets: ["the-secret"],
    };
    const guard = new SecretLeakGuard(config);

    expect(
      guard.check(
        GuardAction.custom("output", { output: "the-secret leaked" }),
        new GuardContext()
      ).allowed
    ).toBe(false);

    expect(
      guard.check(
        GuardAction.custom("output", { result: "the-secret found" }),
        new GuardContext()
      ).allowed
    ).toBe(false);

    expect(
      guard.check(
        GuardAction.custom("output", { error: "the-secret in error" }),
        new GuardContext()
      ).allowed
    ).toBe(false);
  });

  it("provides secret hint in details", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "super-secret-key" });
    const result = guard.check(action, new GuardContext());

    expect(result.details?.secret_hint).toBe("supe...");
  });

  it("respects enabled flag", () => {
    const config: SecretLeakConfig = {
      secrets: ["secret"],
      enabled: false,
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "secret" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("ignores empty secrets", () => {
    const config: SecretLeakConfig = {
      secrets: ["", "  ", "valid-secret"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "valid-secret" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });

  it("matches regex patterns from config", () => {
    const config: SecretLeakConfig = {
      patterns: [{ name: "openai_key", pattern: "sk-[A-Za-z0-9]{10}", severity: "critical" }],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "token sk-ABC123DEF4 leaked" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.guard).toBe("secret_leak");
    expect(result.message).toContain("Secret pattern matched");
  });

  it("treats info-severity pattern matches as non-blocking", () => {
    const config: SecretLeakConfig = {
      patterns: [{ name: "informational", pattern: "sk-[A-Za-z0-9]{10}", severity: "info" }],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "token sk-ABC123DEF4 leaked" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
    expect(result.severity).toBe(Severity.INFO);
  });

  it("treats warning-severity pattern matches as warnings", () => {
    const config: SecretLeakConfig = {
      patterns: [{ name: "warn", pattern: "sk-[A-Za-z0-9]{10}", severity: "warning" }],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "token sk-ABC123DEF4 leaked" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
    expect(result.severity).toBe(Severity.WARNING);
    expect(result.message).toContain("Secret pattern matched");
  });

  it("supports inline regex flags in pattern definitions", () => {
    const config: SecretLeakConfig = {
      patterns: [{ name: "generic_api_key", pattern: "(?i)(api[_\\-]?key)\\s*[:=]\\s*[A-Za-z0-9]{8,}" }],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "API_KEY: ABCDEFGH12345678" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.guard).toBe("secret_leak");
  });
});
