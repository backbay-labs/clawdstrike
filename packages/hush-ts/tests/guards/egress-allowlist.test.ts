import { describe, it, expect } from "vitest";
import { EgressAllowlistGuard, EgressAllowlistConfig } from "../../src/guards/egress-allowlist";
import { GuardAction, GuardContext, Severity } from "../../src/guards/types";

describe("EgressAllowlistGuard", () => {
  it("has correct name", () => {
    const guard = new EgressAllowlistGuard();
    expect(guard.name).toBe("egress_allowlist");
  });

  it("handles network_egress actions only", () => {
    const guard = new EgressAllowlistGuard();

    expect(guard.handles(GuardAction.networkEgress("host", 80))).toBe(true);
    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(false);
  });

  it("blocks by default with empty allowlist", () => {
    const guard = new EgressAllowlistGuard();
    const action = GuardAction.networkEgress("api.example.com", 443);
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.message).toContain("unlisted");
  });

  it("allows hosts in allowlist", () => {
    const config: EgressAllowlistConfig = {
      allow: ["api.example.com", "cdn.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("cdn.example.com", 80), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("other.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("supports wildcard subdomain patterns", () => {
    const config: EgressAllowlistConfig = {
      allow: ["*.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("sub.api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("example.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("supports subdomain matching", () => {
    const config: EgressAllowlistConfig = {
      allow: ["example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
  });

  it("block list takes precedence", () => {
    const config: EgressAllowlistConfig = {
      allow: ["*.example.com"],
      block: ["evil.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("evil.example.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("respects default action", () => {
    const config: EgressAllowlistConfig = {
      defaultAction: "allow",
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("any.host.com", 443), new GuardContext()).allowed).toBe(true);
  });

  it("includes details on block", () => {
    const guard = new EgressAllowlistGuard();
    const action = GuardAction.networkEgress("malicious.com", 8080);
    const result = guard.check(action, new GuardContext());

    expect(result.details?.host).toBe("malicious.com");
    expect(result.details?.port).toBe(8080);
  });
});
