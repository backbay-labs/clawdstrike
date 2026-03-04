import { mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadPolicy, loadPolicyFromString, PolicyLoadError } from "./loader.js";

describe("loadPolicyFromString", () => {
  it("parses valid YAML policy", () => {
    const yaml = `
version: clawdstrike-v1.0
egress:
  mode: allowlist
  allowed_domains:
    - api.github.com
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.version).toBe("clawdstrike-v1.0");
    expect(policy.egress?.mode).toBe("allowlist");
    expect(policy.egress?.allowed_domains).toContain("api.github.com");
  });

  it("throws on invalid YAML", () => {
    const yaml = `{{{invalid`;
    expect(() => loadPolicyFromString(yaml)).toThrow();
  });

  it("accepts canonical policy schema and translates to OpenClaw shape", () => {
    const yaml = `
version: "1.3.0"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "~/.ssh"
  egress_allowlist:
    allow:
      - "api.github.com"
    block:
      - "evil.example"
    default_action: block
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions:
      - "remote.session.connect"
      - "input.inject"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: false
    file_transfer_enabled: true
    audio_enabled: false
    drive_mapping_enabled: false
    printing_enabled: false
    session_share_enabled: false
    max_transfer_size_bytes: 2048
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
    require_postcondition_probe: true
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.version).toBe("clawdstrike-v1.0");
    expect(policy.filesystem?.forbidden_paths).toContain("~/.ssh");
    expect(policy.egress?.allowed_domains).toContain("api.github.com");
    expect(policy.egress?.denied_domains).toContain("evil.example");
    expect(policy.guards?.computer_use?.mode).toBe("fail_closed");
    expect(policy.guards?.computer_use?.allowed_actions).toContain("input.inject");
    expect(policy.guards?.remote_desktop_side_channel?.clipboard_enabled).toBe(false);
    expect(policy.guards?.remote_desktop_side_channel?.max_transfer_size_bytes).toBe(2048);
    expect(policy.guards?.input_injection_capability?.allowed_input_types).toContain("keyboard");
    expect(policy.guards?.input_injection_capability?.require_postcondition_probe).toBe(true);
  });

  it("rejects canonical spider_sense boolean true because it is not executable in OpenClaw", () => {
    const yaml = `
version: "1.3.0"
name: "spider-sense-bool"
guards:
  spider_sense: true
`;

    expect(() => loadPolicyFromString(yaml)).toThrow(/spider_sense: true is not executable/i);
  });

  it("accepts canonical spider_sense boolean true when an enabled spider-sense custom guard exists", () => {
    const yaml = `
version: "1.3.0"
name: "spider-sense-bool-with-custom"
guards:
  spider_sense: true
  custom:
    - package: "clawdstrike-spider-sense"
      enabled: true
      config:
        embedding_api_url: "https://api.openai.com/v1/embeddings"
        embedding_api_key: "test-key"
        embedding_model: "text-embedding-3-small"
        pattern_db_path: "builtin:s2bench-v1"
        pattern_db_version: "s2bench-v1"
        pattern_db_checksum: "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73"
`;

    const policy = loadPolicyFromString(yaml);
    expect(policy.guards?.spider_sense).toBe(true);
    const custom = (policy.guards?.custom as Array<Record<string, unknown>>) ?? [];
    expect(custom.some((entry) => entry.package === "clawdstrike-spider-sense")).toBe(true);
  });

  it("translates canonical spider_sense object toggle", () => {
    const yaml = `
version: "1.3.0"
name: "spider-sense-object"
guards:
  spider_sense:
    enabled: false
`;

    const policy = loadPolicyFromString(yaml);
    expect(policy.guards?.spider_sense).toBe(false);
    expect(policy.guards?.custom).toBeUndefined();
  });

  it("translates canonical spider_sense object config into executable custom guard spec", () => {
    const yaml = `
version: "1.3.0"
name: "spider-sense-object-config"
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "\${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    pattern_db_path: "builtin:s2bench-v1"
    pattern_db_version: "s2bench-v1"
    pattern_db_checksum: "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73"
    async:
      timeout_ms: 1234
`;

    process.env.SPIDER_SENSE_EMBEDDING_KEY = "test-key";
    try {
      const policy = loadPolicyFromString(yaml);
      expect(policy.guards?.spider_sense).toBe(true);
      expect(Array.isArray(policy.guards?.custom)).toBe(true);
      const custom = (policy.guards?.custom as Array<Record<string, unknown>>)[0];
      expect(custom?.package).toBe("clawdstrike-spider-sense");
      expect(custom?.enabled).toBe(true);
      expect((custom?.config as Record<string, unknown>).pattern_db_path).toBe("builtin:s2bench-v1");
      expect((custom?.config as Record<string, unknown>).embedding_api_url).toBe(
        "https://api.openai.com/v1/embeddings",
      );
      expect((custom?.async as Record<string, unknown>).timeout_ms).toBe(1234);
    } finally {
      delete process.env.SPIDER_SENSE_EMBEDDING_KEY;
    }
  });

  it("deduplicates deprecated custom spider-sense when first-class config is present", () => {
    const yaml = `
version: "1.3.0"
name: "spider-sense-dedupe"
guards:
  custom:
    - package: "clawdstrike-spider-sense"
      enabled: true
      config:
        pattern_db_path: "builtin:legacy"
        embedding_api_url: "https://legacy.example/v1/embeddings"
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "vt-key"
  spider_sense:
    enabled: true
    pattern_db_path: "builtin:s2bench-v1"
    embedding_api_url: "https://api.openai.com/v1/embeddings"
`;

    const policy = loadPolicyFromString(yaml);
    const custom = (policy.guards?.custom as Array<Record<string, unknown>>) ?? [];
    const spiderSenseEntries = custom.filter((entry) => entry.package === "clawdstrike-spider-sense");
    expect(spiderSenseEntries).toHaveLength(1);
    expect((spiderSenseEntries[0]?.config as Record<string, unknown>).pattern_db_path).toBe(
      "builtin:s2bench-v1",
    );
    expect(custom.some((entry) => entry.package === "clawdstrike-virustotal")).toBe(true);
  });

  it("rejects legacy spider_sense object config because it is not executable", () => {
    const yaml = `
version: clawdstrike-v1.0
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
`;

    expect(() => loadPolicyFromString(yaml)).toThrow(/guards\.spider_sense object is not executable/i);
  });
});

describe("loadPolicy", () => {
  const testDir = join(tmpdir(), "clawdstrike-test-" + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("loads policy from file", () => {
    const policyPath = join(testDir, "policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
filesystem:
  forbidden_paths:
    - ~/.ssh
`,
    );
    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe("clawdstrike-v1.0");
    expect(policy.filesystem?.forbidden_paths).toContain("~/.ssh");
  });

  it("throws on missing file", () => {
    expect(() => loadPolicy("/nonexistent/policy.yaml")).toThrow(PolicyLoadError);
  });
});
