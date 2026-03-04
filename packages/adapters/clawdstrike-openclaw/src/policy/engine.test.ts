import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PolicyEvent } from "../types.js";
import { PolicyEngine } from "./engine.js";

describe("PolicyEngine", () => {
  const testDir = join(tmpdir(), "clawdstrike-engine-test-" + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(testDir, { recursive: true, force: true });
  });

  it("denies forbidden file reads (deterministic)", async () => {
    const engine = new PolicyEngine({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "deterministic",
      logLevel: "error",
    });

    const event: PolicyEvent = {
      eventId: "t1",
      eventType: "file_read",
      timestamp: new Date().toISOString(),
      data: { type: "file", path: `${homedir()}/.ssh/id_rsa`, operation: "read" },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("forbidden_path");
  });

  it("skips spider_sense custom guard execution when spider_sense toggle is false", async () => {
    const policyPath = join(testDir, "spider-sense-toggle-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        patterns:
          - id: p1
            category: prompt_injection
            stage: perception
            label: ignore previous
            embedding: [1, 0, 0]
`,
    );

    const event: PolicyEvent = {
      eventId: "spider-sense-toggle-disabled",
      eventType: "custom",
      timestamp: new Date().toISOString(),
      data: {
        type: "custom",
        customType: "embedding_check",
        embedding: [1, 0, 0],
      },
    };

    const disabledEngine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: {
        forbidden_path: false,
        egress: false,
        secret_leak: false,
        patch_integrity: false,
        spider_sense: false,
      },
    });
    const disabledDecision = await disabledEngine.evaluate(event);
    expect(disabledDecision.status).toBe("allow");
  });

  it("skips spider_sense custom guard execution when policy guards.spider_sense is false", async () => {
    const policyPath = join(testDir, "spider-sense-policy-disabled.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  spider_sense: false
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        patterns:
          - id: p1
            category: prompt_injection
            stage: perception
            label: ignore previous
            embedding: [1, 0, 0]
`,
    );

    const event: PolicyEvent = {
      eventId: "spider-sense-policy-disabled",
      eventType: "custom",
      timestamp: new Date().toISOString(),
      data: {
        type: "custom",
        customType: "embedding_check",
        embedding: [1, 0, 0],
      },
    };

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: {
        forbidden_path: false,
        egress: false,
        secret_leak: false,
        patch_integrity: false,
        spider_sense: true,
      },
    });
    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("allow");
  });

  it("executes spider_sense custom guard when enabled", async () => {
    const policyPath = join(testDir, "spider-sense-enabled-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        patterns:
          - id: p1
            category: prompt_injection
            stage: perception
            label: ignore previous
            embedding: [1, 0, 0]
`,
    );

    const event: PolicyEvent = {
      eventId: "spider-sense-enabled",
      eventType: "custom",
      timestamp: new Date().toISOString(),
      data: {
        type: "custom",
        customType: "embedding_check",
        embedding: [1, 0, 0],
      },
    };

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: {
        forbidden_path: false,
        egress: false,
        secret_leak: false,
        patch_integrity: false,
        spider_sense: true,
      },
    });
    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("clawdstrike-spider-sense");
  });

  it("rejects malformed external spider_sense pattern DB entries at load time", () => {
    const patternDbPath = join(testDir, "spider-sense-patterns-invalid.json");
    writeFileSync(
      patternDbPath,
      JSON.stringify([
        {
          id: "bad-1",
          category: "prompt_injection",
          stage: "perception",
          label: "missing embedding",
        },
      ]),
    );

    const policyPath = join(testDir, "spider-sense-invalid-db-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        pattern_db_path: "${patternDbPath}"
`,
    );

    expect(
      () =>
        new PolicyEngine({
          policy: policyPath,
          mode: "deterministic",
          logLevel: "error",
          guards: {
            forbidden_path: false,
            egress: false,
            secret_leak: false,
            patch_integrity: false,
            spider_sense: true,
          },
        }),
    ).toThrow(/contains invalid entry at index 0/);
  });

  it("resolves relative spider_sense pattern_db_path from the policy file directory", async () => {
    const policyDir = join(testDir, "spider-sense-relative-db");
    const patternsDir = join(policyDir, "patterns");
    mkdirSync(patternsDir, { recursive: true });

    const patternDbPath = join(patternsDir, "db.json");
    writeFileSync(
      patternDbPath,
      JSON.stringify([
        {
          id: "p1",
          category: "prompt_injection",
          stage: "perception",
          label: "relative path pattern",
          embedding: [1, 0, 0],
        },
      ]),
    );

    const policyPath = join(policyDir, "policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        pattern_db_path: "./patterns/db.json"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: {
        forbidden_path: false,
        egress: false,
        secret_leak: false,
        patch_integrity: false,
        spider_sense: true,
      },
    });

    const decision = await engine.evaluate({
      eventId: "spider-sense-relative-db",
      eventType: "custom",
      timestamp: new Date().toISOString(),
      data: {
        type: "custom",
        customType: "embedding_check",
        embedding: [1, 0, 0],
      },
    });

    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("clawdstrike-spider-sense");
  });

  it("rejects malformed inline spider_sense patterns at load time", () => {
    const policyPath = join(testDir, "spider-sense-inline-invalid-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        patterns:
          - id: p1
            category: prompt_injection
            stage: perception
            label: valid pattern
            embedding: [1, 0, 0]
          - id: p2
            category: prompt_injection
            stage: perception
            label: invalid pattern
            embedding: ["bad", 0, 0]
`,
    );

    expect(
      () =>
        new PolicyEngine({
          policy: policyPath,
          mode: "deterministic",
          logLevel: "error",
          guards: {
            forbidden_path: false,
            egress: false,
            secret_leak: false,
            patch_integrity: false,
            spider_sense: true,
          },
        }),
    ).toThrow(/inline patterns contain invalid entry at index 1/i);
  });

  it("rejects spider_sense pattern DB entries with mixed embedding dimensions", () => {
    const patternDbPath = join(testDir, "spider-sense-patterns-dim-mismatch.json");
    writeFileSync(
      patternDbPath,
      JSON.stringify([
        {
          id: "p1",
          category: "prompt_injection",
          stage: "perception",
          label: "dim-3",
          embedding: [1, 0, 0],
        },
        {
          id: "p2",
          category: "prompt_injection",
          stage: "perception",
          label: "dim-2",
          embedding: [1, 0],
        },
      ]),
    );

    const policyPath = join(testDir, "spider-sense-db-dim-mismatch-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        pattern_db_path: "${patternDbPath}"
`,
    );

    expect(
      () =>
        new PolicyEngine({
          policy: policyPath,
          mode: "deterministic",
          logLevel: "error",
          guards: {
            forbidden_path: false,
            egress: false,
            secret_leak: false,
            patch_integrity: false,
            spider_sense: true,
          },
        }),
    ).toThrow(/embedding dimension mismatch/i);
  });

  it("rejects spider_sense runtime config with out-of-range similarity_threshold", () => {
    const policyPath = join(testDir, "spider-sense-threshold-out-of-range-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        similarity_threshold: 5
        patterns:
          - id: p1
            category: prompt_injection
            stage: perception
            label: valid pattern
            embedding: [1, 0, 0]
`,
    );

    expect(
      () =>
        new PolicyEngine({
          policy: policyPath,
          mode: "deterministic",
          logLevel: "error",
          guards: {
            forbidden_path: false,
            egress: false,
            secret_leak: false,
            patch_integrity: false,
            spider_sense: true,
          },
        }),
    ).toThrow(/similarity_threshold must be in \[0, 1\]/i);
  });

  it("fails closed with deny decision when spider_sense embedding provider returns non-2xx", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 503 }));

    const policyPath = join(testDir, "spider-sense-provider-failure-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        pattern_db_path: builtin:s2bench-v1
        embedding_api_url: https://api.example.test/v1/embeddings
        embedding_api_key: test-key
        embedding_model: text-embedding-3-small
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: {
        forbidden_path: false,
        egress: false,
        secret_leak: false,
        patch_integrity: false,
        spider_sense: true,
      },
    });
    const decision = await engine.evaluate({
      eventId: "spider-sense-provider-failure",
      eventType: "custom",
      timestamp: new Date().toISOString(),
      data: {
        type: "custom",
        customType: "embedding_check",
        payload: "no local embedding present",
      },
    });

    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("clawdstrike-spider-sense");
    expect(decision.reason).toMatch(/runtime error/i);
  });

  it("rejects external spider_sense pattern DB on checksum mismatch", () => {
    const patternDbPath = join(testDir, "spider-sense-patterns-checksum.json");
    const patternDbRaw = JSON.stringify([
      {
        id: "ok-1",
        category: "prompt_injection",
        stage: "perception",
        label: "known bad pattern",
        embedding: [0.9, 0.1, 0.0],
      },
    ]);
    writeFileSync(patternDbPath, patternDbRaw);
    const wrongChecksum = createHash("sha256")
      .update("tampered-content")
      .digest("hex")
      .toLowerCase();

    const policyPath = join(testDir, "spider-sense-bad-checksum-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: clawdstrike-v1.0
guards:
  custom:
    - package: clawdstrike-spider-sense
      enabled: true
      config:
        pattern_db_path: "${patternDbPath}"
        pattern_db_checksum: "${wrongChecksum}"
`,
    );

    expect(
      () =>
        new PolicyEngine({
          policy: policyPath,
          mode: "deterministic",
          logLevel: "error",
          guards: {
            forbidden_path: false,
            egress: false,
            secret_leak: false,
            patch_integrity: false,
            spider_sense: true,
          },
        }),
    ).toThrow(/checksum mismatch/i);
  });

  it("warns but allows in advisory mode", async () => {
    const engine = new PolicyEngine({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "advisory",
      logLevel: "error",
    });

    const event: PolicyEvent = {
      eventId: "t2",
      eventType: "file_read",
      timestamp: new Date().toISOString(),
      data: { type: "file", path: `${homedir()}/.ssh/id_rsa`, operation: "read" },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("warn");
  });

  it("blocks secret leaks in tool output", async () => {
    const engine = new PolicyEngine({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "deterministic",
      logLevel: "error",
    });

    const event: PolicyEvent = {
      eventId: "t3",
      eventType: "tool_call",
      timestamp: new Date().toISOString(),
      data: {
        type: "tool",
        toolName: "api_call",
        parameters: {},
        result: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("secret_leak");
  });

  it("enforces allowed_write_roots for output-style command flags", async () => {
    const policyPath = join(testDir, "policy.yaml");
    writeFileSync(
      policyPath,
      `
extends: clawdstrike:ai-agent-minimal
filesystem:
  allowed_write_roots:
    - /tmp/allowed
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
      guards: { patch_integrity: false },
    });

    const base: Omit<PolicyEvent, "eventId" | "eventType" | "data"> = {
      timestamp: new Date().toISOString(),
    };

    const denyEq: PolicyEvent = {
      ...base,
      eventId: "t4",
      eventType: "command_exec",
      data: { type: "command", command: "tool", args: ["--output=/tmp/disallowed/out.txt"] },
    };
    const decisionEq = await engine.evaluate(denyEq);
    expect(decisionEq.status).toBe("deny");
    expect(decisionEq.reason).toContain("Write path not in allowed roots");

    const denySpace: PolicyEvent = {
      ...base,
      eventId: "t5",
      eventType: "command_exec",
      data: { type: "command", command: "tool", args: ["--log-file", "/tmp/disallowed/log.txt"] },
    };
    const decisionSpace = await engine.evaluate(denySpace);
    expect(decisionSpace.status).toBe("deny");
    expect(decisionSpace.reason).toContain("Write path not in allowed roots");
  });

  it("fails closed for CUA events when computer_use guard config is missing", async () => {
    const engine = new PolicyEngine({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "deterministic",
      logLevel: "error",
    });

    const event: PolicyEvent = {
      eventId: "cua-missing-1",
      eventType: "input.inject",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "input.inject",
        input_type: "keyboard",
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("computer_use");
  });

  it("warns on computer_use allowlist misses in guardrail mode", async () => {
    const policyPath = join(testDir, "cua-guardrail-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
      - "input.inject"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: true
    session_share_enabled: true
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const allowedEvent: PolicyEvent = {
      eventId: "cua-guardrail-allow",
      eventType: "input.inject",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "input.inject",
        input_type: "keyboard",
      },
    };
    const allowedDecision = await engine.evaluate(allowedEvent);
    expect(allowedDecision.status).toBe("allow");

    const deniedEvent: PolicyEvent = {
      eventId: "cua-guardrail-deny",
      eventType: "remote.session.disconnect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.disconnect",
      },
    };
    const warnedDecision = await engine.evaluate(deniedEvent);
    expect(warnedDecision.status).toBe("warn");
    expect(warnedDecision.guard).toBe("computer_use");
  });

  it("denies computer_use allowlist misses in fail_closed mode", async () => {
    const policyPath = join(testDir, "cua-fail-closed-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions:
      - "remote.session.connect"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const deniedEvent: PolicyEvent = {
      eventId: "cua-fail-closed-deny",
      eventType: "remote.session.disconnect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.disconnect",
      },
    };

    const deniedDecision = await engine.evaluate(deniedEvent);
    expect(deniedDecision.status).toBe("deny");
    expect(deniedDecision.guard).toBe("computer_use");
  });

  it("enforces egress policy on CUA connect with destination metadata", async () => {
    const policyPath = join(testDir, "cua-connect-egress-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  egress_allowlist:
    enabled: true
    default_action: block
    allow:
      - "*.example.com"
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const allowedConnect: PolicyEvent = {
      eventId: "cua-connect-egress-allow",
      eventType: "remote.session.connect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.connect",
        direction: "outbound",
        host: "desk.example.com",
        port: 443,
        url: "https://desk.example.com/session",
      },
    };
    const allowedDecision = await engine.evaluate(allowedConnect);
    expect(allowedDecision.status).toBe("allow");

    const deniedConnect: PolicyEvent = {
      eventId: "cua-connect-egress-deny",
      eventType: "remote.session.connect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.connect",
        direction: "outbound",
        host: "evil.invalid",
        port: 443,
        url: "https://evil.invalid/session",
      },
    };
    const deniedDecision = await engine.evaluate(deniedConnect);
    expect(deniedDecision.status).toBe("deny");
    expect(deniedDecision.guard).toBe("egress");
  });

  it("fails closed for CUA connect when egress guard cannot evaluate destination", async () => {
    const policyPath = join(testDir, "cua-connect-metadata-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  egress_allowlist:
    enabled: true
    default_action: block
    allow:
      - "*.example.com"
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const missingDestination: PolicyEvent = {
      eventId: "cua-connect-metadata-deny",
      eventType: "remote.session.connect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.connect",
        direction: "outbound",
      },
    };
    const decision = await engine.evaluate(missingDestination);
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("egress");
    expect(decision.reason).toContain("missing destination");
  });

  it("returns warn in observe mode when CUA action is outside allowed_actions", async () => {
    const policyPath = join(testDir, "cua-observe-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions:
      - "remote.session.connect"
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const event: PolicyEvent = {
      eventId: "cua-observe-warn",
      eventType: "remote.session.disconnect",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "session.disconnect",
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe("warn");
    expect(decision.guard).toBe("computer_use");
  });

  it("enforces input_injection_capability fail-closed checks", async () => {
    const policyPath = join(testDir, "cua-input-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "input.inject"
  input_injection_capability:
    enabled: true
    allowed_input_types:
      - "keyboard"
    require_postcondition_probe: true
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const missingInputType: PolicyEvent = {
      eventId: "cua-input-missing-type",
      eventType: "input.inject",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "input.inject",
        postconditionProbeHash: "probe-1",
      },
    };
    const missingTypeDecision = await engine.evaluate(missingInputType);
    expect(missingTypeDecision.status).toBe("deny");
    expect(missingTypeDecision.guard).toBe("input_injection_capability");

    const missingProbe: PolicyEvent = {
      eventId: "cua-input-missing-probe",
      eventType: "input.inject",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "input.inject",
        input_type: "keyboard",
      },
    };
    const missingProbeDecision = await engine.evaluate(missingProbe);
    expect(missingProbeDecision.status).toBe("deny");
    expect(missingProbeDecision.guard).toBe("input_injection_capability");
  });

  it("enforces remote_desktop_side_channel channel toggles and transfer size limits", async () => {
    const policyPath = join(testDir, "cua-side-channel-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.clipboard"
      - "remote.file_transfer"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: false
    file_transfer_enabled: true
    max_transfer_size_bytes: 100
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const clipboardEvent: PolicyEvent = {
      eventId: "cua-clipboard-deny",
      eventType: "remote.clipboard",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "clipboard",
        direction: "read",
      },
    };
    const clipboardDecision = await engine.evaluate(clipboardEvent);
    expect(clipboardDecision.status).toBe("deny");
    expect(clipboardDecision.guard).toBe("remote_desktop_side_channel");

    const transferEvent: PolicyEvent = {
      eventId: "cua-transfer-deny",
      eventType: "remote.file_transfer",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "file_transfer",
        direction: "upload",
        transfer_size: 101,
      },
    };
    const transferDecision = await engine.evaluate(transferEvent);
    expect(transferDecision.status).toBe("deny");
    expect(transferDecision.guard).toBe("remote_desktop_side_channel");

    const transferMissingSize: PolicyEvent = {
      eventId: "cua-transfer-missing-size",
      eventType: "remote.file_transfer",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "file_transfer",
        direction: "upload",
      },
    };
    const missingSizeDecision = await engine.evaluate(transferMissingSize);
    expect(missingSizeDecision.status).toBe("deny");
    expect(missingSizeDecision.guard).toBe("remote_desktop_side_channel");
  });

  it("enforces file transfer caps fail-closed when max_transfer_size_bytes is configured", async () => {
    const policyPath = join(testDir, "cua-side-channel-zero-cap-policy.yaml");
    writeFileSync(
      policyPath,
      `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.file_transfer"
  remote_desktop_side_channel:
    enabled: true
    file_transfer_enabled: true
    max_transfer_size_bytes: 0
`,
    );

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: "deterministic",
      logLevel: "error",
    });

    const overLimitEvent: PolicyEvent = {
      eventId: "cua-transfer-zero-cap-over-limit",
      eventType: "remote.file_transfer",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "file_transfer",
        direction: "upload",
        transfer_size: 1,
      },
    };
    const overLimitDecision = await engine.evaluate(overLimitEvent);
    expect(overLimitDecision.status).toBe("deny");
    expect(overLimitDecision.guard).toBe("remote_desktop_side_channel");

    const exactlyZeroEvent: PolicyEvent = {
      eventId: "cua-transfer-zero-cap-zero-size",
      eventType: "remote.file_transfer",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "file_transfer",
        direction: "upload",
        transfer_size: 0,
      },
    };
    const exactlyZeroDecision = await engine.evaluate(exactlyZeroEvent);
    expect(exactlyZeroDecision.status).toBe("allow");

    const missingSizeEvent: PolicyEvent = {
      eventId: "cua-transfer-zero-cap-missing-size",
      eventType: "remote.file_transfer",
      timestamp: new Date().toISOString(),
      data: {
        type: "cua",
        cuaAction: "file_transfer",
        direction: "upload",
      },
    };
    const missingSizeDecision = await engine.evaluate(missingSizeEvent);
    expect(missingSizeDecision.status).toBe("deny");
    expect(missingSizeDecision.guard).toBe("remote_desktop_side_channel");
  });
});
