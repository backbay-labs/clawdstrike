import { describe, it, expect } from "vitest";
import { ForbiddenPathGuard, ForbiddenPathConfig } from "../../src/guards/forbidden-path";
import { GuardAction, GuardContext, Severity } from "../../src/guards/types";

describe("ForbiddenPathGuard", () => {
  it("has correct name", () => {
    const guard = new ForbiddenPathGuard();
    expect(guard.name).toBe("forbidden_path");
  });

  it("handles file_access, file_write, patch actions", () => {
    const guard = new ForbiddenPathGuard();

    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(true);
    expect(guard.handles(GuardAction.fileWrite("/path", new Uint8Array()))).toBe(true);
    expect(guard.handles(GuardAction.patch("/path", "diff"))).toBe(true);
    expect(guard.handles(GuardAction.networkEgress("host", 80))).toBe(false);
  });

  it("blocks SSH key access by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.ssh/id_rsa");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("forbidden");
  });

  it("blocks AWS credentials by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.aws/credentials");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });

  it("blocks .env files by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/project/.env");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });

  it("allows non-sensitive paths", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/project/src/app.ts");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("uses custom patterns", () => {
    const config: ForbiddenPathConfig = {
      patterns: ["**/secrets/**", "**/private/**"],
    };
    const guard = new ForbiddenPathGuard(config);

    expect(guard.check(GuardAction.fileAccess("/data/secrets/key.json"), new GuardContext()).allowed).toBe(false);
    expect(guard.check(GuardAction.fileAccess("/data/public/key.json"), new GuardContext()).allowed).toBe(true);
  });

  it("respects exceptions", () => {
    const config: ForbiddenPathConfig = {
      patterns: ["**/.env", "**/.env.*"],
      exceptions: ["**/test/.env.test"],
    };
    const guard = new ForbiddenPathGuard(config);

    expect(guard.check(GuardAction.fileAccess("/project/.env"), new GuardContext()).allowed).toBe(false);
    expect(guard.check(GuardAction.fileAccess("/project/test/.env.test"), new GuardContext()).allowed).toBe(true);
  });

  it("includes details on block", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.ssh/id_rsa");
    const result = guard.check(action, new GuardContext());

    expect(result.details?.path).toBe("/home/user/.ssh/id_rsa");
    expect(result.details?.reason).toBe("matches_forbidden_pattern");
  });
});
