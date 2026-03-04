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
version: "1.2.0"
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

  it("translates canonical spider_sense boolean toggle", () => {
    const yaml = `
version: "1.2.0"
name: "spider-sense-bool"
guards:
  spider_sense: true
`;

    const policy = loadPolicyFromString(yaml);
    expect(policy.guards?.spider_sense).toBe(true);
  });

  it("translates canonical spider_sense object toggle", () => {
    const yaml = `
version: "1.2.0"
name: "spider-sense-object"
guards:
  spider_sense:
    enabled: false
`;

    const policy = loadPolicyFromString(yaml);
    expect(policy.guards?.spider_sense).toBe(false);
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
