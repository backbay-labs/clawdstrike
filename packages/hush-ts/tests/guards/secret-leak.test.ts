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
});
