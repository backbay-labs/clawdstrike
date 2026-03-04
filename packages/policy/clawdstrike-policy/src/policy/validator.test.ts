import { describe, expect, it } from "vitest";

import { validatePolicy } from "./validator.js";

describe("policy validator posture/version gating", () => {
  it("accepts policy v1.2.0 with posture and path_allowlist", () => {
    const lint = validatePolicy({
      version: "1.2.0",
      name: "test",
      guards: {
        path_allowlist: {
          enabled: true,
          file_access_allow: ["**/repo/**"],
          file_write_allow: ["**/repo/**"],
        },
      },
      posture: {
        initial: "work",
        states: {
          work: {
            capabilities: ["file_access", "file_write"],
            budgets: {
              file_writes: 10,
            },
          },
        },
      },
    });

    expect(lint.valid).toBe(true);
    expect(lint.errors).toEqual([]);
  });

  it("rejects posture for policy v1.1.0", () => {
    const lint = validatePolicy({
      version: "1.1.0",
      posture: {
        initial: "work",
        states: {
          work: {
            capabilities: ["file_access"],
          },
        },
      },
    });

    expect(lint.valid).toBe(false);
    expect(lint.errors).toContain("posture requires policy version 1.2.0");
  });

  it("rejects path_allowlist for policy v1.1.0", () => {
    const lint = validatePolicy({
      version: "1.1.0",
      guards: {
        path_allowlist: {
          enabled: true,
          file_access_allow: ["**/repo/**"],
        },
      },
    });

    expect(lint.valid).toBe(false);
    expect(lint.errors).toContain("path_allowlist requires policy version 1.2.0");
  });

  it("accepts policy v1.3.0 spider_sense template and manifest fields", () => {
    const lint = validatePolicy({
      version: "1.3.0",
      guards: {
        spider_sense: {
          llm_api_url: "https://api.openai.com/v1/chat/completions",
          llm_api_key: "test-key",
          llm_prompt_template_id: "spider_sense.deep_path.json_classifier",
          llm_prompt_template_version: "1.0.0",
          pattern_db_manifest_path: "/tmp/spider/manifest.json",
          pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json",
          async: {
            retry: {
              honor_retry_after: true,
              retry_after_cap_ms: 2000,
              honor_rate_limit_reset: true,
              rate_limit_reset_grace_ms: 250,
            },
          },
        },
      },
    });

    expect(lint.valid).toBe(true);
    expect(lint.errors).toEqual([]);
  });

  it("validates spider_sense async cache/circuit fields", () => {
    const lint = validatePolicy({
      version: "1.3.0",
      guards: {
        spider_sense: {
          async: {
            cache: {
              ttl_seconds: 0,
            },
            circuit_breaker: {
              failure_threshold: 0,
            },
          },
        },
      },
    });

    expect(lint.valid).toBe(false);
    expect(lint.errors).toContain("guards.spider_sense.async.cache.ttl_seconds must be >= 1");
    expect(lint.errors).toContain(
      "guards.spider_sense.async.circuit_breaker.failure_threshold must be >= 1",
    );
  });

  it("warns when 1.3 fields are used in v1.2.0 spider_sense", () => {
    const lint = validatePolicy({
      version: "1.2.0",
      guards: {
        spider_sense: {
          pattern_db_manifest_path: "/tmp/spider/manifest.json",
          pattern_db_manifest_trusted_keys: [{ key_id: "abc", public_key: "def" }],
        },
      },
    });

    expect(lint.valid).toBe(true);
    expect(lint.warnings.some((warning) => warning.includes("1.3.0 fields"))).toBe(true);
  });

  it("accepts reserved spider-sense custom guard package for migration", () => {
    const lint = validatePolicy({
      version: "1.3.0",
      guards: {
        custom: [
          {
            package: "clawdstrike-spider-sense",
            enabled: true,
            config: {
              pattern_db_path: "builtin:s2bench-v1",
            },
          },
        ],
      },
    });

    expect(lint.valid).toBe(true);
    expect(lint.errors).toEqual([]);
  });
});
