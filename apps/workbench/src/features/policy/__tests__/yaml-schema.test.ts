import { describe, it, expect } from "vitest";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { BUILTIN_RULESETS } from "@/features/policy/builtin-rulesets";

// We cannot directly import the private functions (getCursorContext,
// resolveSchemaNode) because they are module-private. However, we CAN test
// the public completion source. To also cover the internal helpers we use
// a trick: we import the module and call its exported CompletionSource with
// a minimal CompletionContext mock.

import { policyYamlCompletionSource } from "@/features/policy/yaml-schema";


/** Build a minimal Text-like object from a raw string. */
function mockDoc(text: string) {
  const lines = text.split("\n");
  return {
    length: text.length,
    lineAt(pos: number) {
      let offset = 0;
      for (let i = 0; i < lines.length; i++) {
        const lineLen = lines[i].length + (i < lines.length - 1 ? 1 : 0); // +1 for \n
        if (pos < offset + lineLen || i === lines.length - 1) {
          return {
            from: offset,
            to: offset + lines[i].length,
            number: i + 1,
            text: lines[i],
          };
        }
        offset += lineLen;
      }
      // Fallback
      const last = lines.length - 1;
      return { from: text.length - lines[last].length, to: text.length, number: lines.length, text: lines[last] };
    },
    line(n: number) {
      let offset = 0;
      for (let i = 0; i < n - 1; i++) {
        offset += lines[i].length + 1;
      }
      return {
        from: offset,
        to: offset + lines[n - 1].length,
        number: n,
        text: lines[n - 1],
      };
    },
  };
}

/** Build a CompletionContext mock at a given position in the text. */
function makeCtx(text: string, pos: number, explicit = true) {
  const doc = mockDoc(text);
  return {
    state: { doc },
    pos,
    explicit,
    matchBefore(re: RegExp) {
      const line = doc.lineAt(pos);
      const before = line.text.slice(0, pos - line.from);
      const m = before.match(re);
      return m ? { from: pos - m[0].length, to: pos, text: m[0] } : null;
    },
  } as Parameters<typeof policyYamlCompletionSource>[0];
}

/** Our completion source is synchronous; cast away the Promise union for test convenience. */
function complete(text: string, pos: number, explicit = true) {
  return policyYamlCompletionSource(makeCtx(text, pos, explicit)) as
    | { from: number; options: { label: string; type?: string; detail?: string }[]; filter?: boolean }
    | null;
}


describe("policyYamlCompletionSource", () => {
  // ---- Top-level completions ----

  describe("top-level key completions", () => {
    it("offers top-level keys on an empty document", () => {
      const result = complete("", 0);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("version");
      expect(labels).toContain("guards");
      expect(labels).toContain("settings");
      expect(labels).toContain("extends");
      expect(labels).toContain("posture");
      expect(labels).toContain("origins");
    });

    it("offers top-level keys when cursor is on a blank line after existing keys", () => {
      const text = 'version: "1.2.0"\nname: "test"\n';
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("guards");
      expect(labels).toContain("description");
    });

    it("filters top-level keys by prefix", () => {
      const text = "gu";
      const pos = 2;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      // The result should include "guards" since it starts with "gu"
      // (filtering is done by CodeMirror, but the completions should be offered)
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("guards");
    });
  });

  // ---- Value completions ----

  describe("value completions for version", () => {
    it("offers schema version values after 'version: '", () => {
      const text = "version: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain('"1.4.0"');
      expect(labels).toContain('"1.2.0"');
      expect(labels).toContain('"1.1.0"');
    });

    it("offers schema version values for schema_version alias", () => {
      const text = "schema_version: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain('"1.2.0"');
    });
  });

  describe("value completions for extends", () => {
    it("offers built-in ruleset IDs after 'extends: '", () => {
      const text = "extends: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      for (const ruleset of BUILTIN_RULESETS) {
        expect(labels).toContain(`"${ruleset.id}"`);
      }
    });
  });

  // ---- Guards-level completions ----

  describe("guards-level completions", () => {
    it("offers guard IDs under 'guards:'", () => {
      const text = "guards:\n  ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      for (const guard of GUARD_REGISTRY) {
        expect(labels).toContain(guard.id);
      }
    });

    it("offers all 13 guard IDs", () => {
      const text = "guards:\n  ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      expect(result!.options.length).toBe(GUARD_REGISTRY.length);
    });
  });

  // ---- Guard config field completions ----

  describe("guard config field completions", () => {
    it("offers config fields under a specific guard (forbidden_path)", () => {
      const text = "guards:\n  forbidden_path:\n    ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("enabled");
      expect(labels).toContain("patterns");
      expect(labels).toContain("exceptions");
    });

    it("offers config fields for egress_allowlist", () => {
      const text = "guards:\n  egress_allowlist:\n    ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("enabled");
      expect(labels).toContain("allow");
      expect(labels).toContain("block");
      expect(labels).toContain("default_action");
    });

    it("offers config fields for shell_command guard", () => {
      const text = "guards:\n  shell_command:\n    ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("enabled");
      expect(labels).toContain("forbidden_patterns");
    });
  });

  // ---- Boolean value completions ----

  describe("boolean value completions", () => {
    it("offers true/false for 'enabled:' value position", () => {
      const text = "guards:\n  forbidden_path:\n    enabled: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("true");
      expect(labels).toContain("false");
    });

    it("offers true/false for fail_fast value position", () => {
      const text = "settings:\n  fail_fast: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("true");
      expect(labels).toContain("false");
    });

    it("offers true/false for verbose_logging", () => {
      const text = "settings:\n  verbose_logging: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("true");
      expect(labels).toContain("false");
    });

    it("offers booleans for keys ending in _enabled", () => {
      const text = "guards:\n  remote_desktop_side_channel:\n    clipboard_enabled: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("true");
      expect(labels).toContain("false");
    });
  });

  // ---- Select value completions ----

  describe("select value completions", () => {
    it("offers select options for egress default_action", () => {
      const text = "guards:\n  egress_allowlist:\n    default_action: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain('"allow"');
      expect(labels).toContain('"block"');
    });
  });

  // ---- Settings completions ----

  describe("settings-level completions", () => {
    it("offers settings keys under 'settings:'", () => {
      const text = "settings:\n  ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("fail_fast");
      expect(labels).toContain("verbose_logging");
      expect(labels).toContain("session_timeout_secs");
    });
  });

  // ---- Posture completions ----

  describe("posture-level completions", () => {
    it("offers posture keys under 'posture:'", () => {
      const text = "posture:\n  ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("initial");
      expect(labels).toContain("states");
      expect(labels).toContain("transitions");
    });

    it("offers posture state fields under dynamic state names", () => {
      const text = "posture:\n  states:\n    exploring:\n      ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const labels = result!.options.map((o) => o.label);
      expect(labels).toContain("description");
      expect(labels).toContain("capabilities");
      expect(labels).toContain("budgets");
    });
  });

  // ---- Non-explicit invocation ----

  describe("non-explicit invocation", () => {
    it("returns null when not explicit and no word prefix", () => {
      const text = "  ";
      const pos = text.length;
      const result = complete(text, pos, false);
      expect(result).toBeNull();
    });
  });

  // ---- Unknown / deep paths ----

  describe("unknown paths", () => {
    it("returns null for unknown top-level key values", () => {
      const text = "name: ";
      const pos = text.length;
      const result = complete(text, pos);
      // "name" doesn't have predefined value options
      expect(result).toBeNull();
    });

    it("returns null for deeply nested unknown path", () => {
      const text = "foo:\n  bar:\n    baz:\n      ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).toBeNull();
    });
  });

  // ---- Completion metadata ----

  describe("completion metadata", () => {
    it("top-level completions have type 'property'", () => {
      const result = complete("", 0);
      expect(result).not.toBeNull();
      for (const opt of result!.options) {
        expect(opt.type).toBe("property");
      }
    });

    it("guard guard completions have detail set to guard name", () => {
      const text = "guards:\n  ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const fpOption = result!.options.find((o) => o.label === "forbidden_path");
      expect(fpOption).toBeDefined();
      expect(fpOption!.detail).toBe("Forbidden Path");
    });

    it("version value completions have descriptive detail", () => {
      const text = "version: ";
      const pos = text.length;
      const result = complete(text, pos);
      expect(result).not.toBeNull();
      const latest = result!.options.find((o) => o.label === '"1.4.0"');
      expect(latest).toBeDefined();
      expect(latest!.detail).toContain("origins");
    });
  });
});
