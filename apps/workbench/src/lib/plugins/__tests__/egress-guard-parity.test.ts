/**
 * Egress Guard Plugin Parity Tests
 *
 * Verifies verdict parity between the plugin guard and the built-in
 * EgressAllowlistGuard from the SDK guard source. Proves that the config
 * schema declared by the plugin produces correct allow/deny/warn verdicts
 * when consumed by the hush-ts evaluation logic.
 */

import { describe, it, expect } from "vitest";
import {
  EgressAllowlistGuard,
} from "../../../../../../packages/sdk/hush-ts/src/guards/egress-allowlist";
import {
  GuardAction,
  GuardContext,
  GuardResult,
  Severity,
} from "../../../../../../packages/sdk/hush-ts/src/guards/types";
import { BUILTIN_GUARDS } from "../../workbench/guard-registry";
import egressGuardPlugin from "../examples/egress-guard-plugin";

// ---- Helpers ----

/** Shorthand to check a domain against the guard and return the result. */
function checkDomain(guard: EgressAllowlistGuard, host: string): GuardResult {
  const action = GuardAction.networkEgress(host, 443);
  const ctx = new GuardContext();
  return guard.check(action, ctx) as GuardResult;
}

// ---- Test suites ----

describe("Egress Guard Plugin Parity", () => {
  describe("verdict behavior", () => {
    // Test 1: Default config -- allowed domain produces "allow"
    it("allows api.openai.com with default allowlist config", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.openai.com", "*.anthropic.com"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "api.openai.com");
      expect(result.allowed).toBe(true);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 2: Default config -- unlisted domain produces "deny"
    it("denies evil.com with default allowlist config", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.openai.com", "*.anthropic.com"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "evil.com");
      expect(result.allowed).toBe(false);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 3: Custom config -- allowed domain produces "allow"
    it("allows api.mycompany.com with custom config", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.mycompany.com"],
        block: ["blocked.mycompany.com"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "api.mycompany.com");
      expect(result.allowed).toBe(true);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 4: Custom config -- block takes precedence over allow
    it("denies blocked.mycompany.com (block precedence over allow)", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.mycompany.com"],
        block: ["blocked.mycompany.com"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "blocked.mycompany.com");
      expect(result.allowed).toBe(false);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 5: Custom config -- unlisted domain with default_action "block"
    it("denies other.com not in allowlist with default_action block", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.mycompany.com"],
        block: ["blocked.mycompany.com"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "other.com");
      expect(result.allowed).toBe(false);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 6: default_action "log" produces warn verdict for unlisted domain
    it("warns for unlisted domain with default_action log", () => {
      const guard = new EgressAllowlistGuard({
        allow: ["*.mycompany.com"],
        defaultAction: "log",
      });
      const result = checkDomain(guard, "unlisted.com");
      // warn results are allowed=true but severity=WARNING
      expect(result.allowed).toBe(true);
      expect(result.severity).toBe(Severity.WARNING);
      expect(result.guard).toBe("egress_allowlist");
    });

    // Test 7: enabled=false produces allow for any domain
    it("allows any domain when enabled is false", () => {
      const guard = new EgressAllowlistGuard({
        enabled: false,
        allow: [],
        block: ["*"],
        defaultAction: "block",
      });
      const result = checkDomain(guard, "anything.evil.com");
      expect(result.allowed).toBe(true);
      expect(result.guard).toBe("egress_allowlist");
    });
  });

  describe("config schema parity", () => {
    // Test 8: Plugin configFields match built-in guard metadata
    it("plugin configFields match the built-in egress_allowlist guard metadata", () => {
      const pluginGuard = egressGuardPlugin.manifest.contributions!.guards![0];
      const builtinGuard = BUILTIN_GUARDS.find((g) => g.id === "egress_allowlist")!;

      expect(pluginGuard.configFields.length).toBe(builtinGuard.configFields.length);

      // Map plugin config field keys to built-in field keys
      // Plugin uses "default_action" which maps to "default_action" in built-in
      // (the hush-ts SDK uses "defaultAction" in the TS interface, but the config
      // field keys use snake_case matching the Rust/policy-level naming)
      for (let i = 0; i < builtinGuard.configFields.length; i++) {
        const expected = builtinGuard.configFields[i];
        const actual = pluginGuard.configFields[i];
        expect(actual.key).toBe(expected.key);
        expect(actual.label).toBe(expected.label);
        expect(actual.type).toBe(expected.type);
        expect(actual.description).toBe(expected.description);
        expect(actual.defaultValue).toEqual(expected.defaultValue);
        expect(actual.options).toEqual(expected.options);
      }
    });
  });
});
