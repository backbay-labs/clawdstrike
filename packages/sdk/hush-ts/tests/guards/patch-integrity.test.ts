import { describe, expect, it } from "vitest";
import { PatchIntegrityGuard } from "../../src/guards/patch-integrity";
import { GuardAction, GuardContext, Severity } from "../../src/guards/types";

describe("PatchIntegrityGuard", () => {
  it("blocks disabling security using underscore variant", () => {
    const guard = new PatchIntegrityGuard();
    const action = GuardAction.patch(
      "/project/src/auth.ts",
      "+disable_security = true\n+const x = 1"
    );

    const result = guard.check(action, new GuardContext());
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
  });

  it("blocks disabling security using whitespace variant", () => {
    const guard = new PatchIntegrityGuard();
    const action = GuardAction.patch(
      "/project/src/auth.ts",
      "+disable security = true\n+const x = 1"
    );

    const result = guard.check(action, new GuardContext());
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
  });

  it("allows safe patches", () => {
    const guard = new PatchIntegrityGuard();
    const action = GuardAction.patch(
      "/project/src/app.ts",
      "+const greeting = 'hello'\n-const greeting = 'hi'"
    );

    const result = guard.check(action, new GuardContext());
    expect(result.allowed).toBe(true);
  });
});
