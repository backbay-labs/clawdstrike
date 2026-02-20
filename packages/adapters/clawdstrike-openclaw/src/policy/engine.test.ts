import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';

import { PolicyEngine } from './engine.js';
import type { PolicyEvent } from '../types.js';

describe('PolicyEngine', () => {
  const testDir = join(tmpdir(), 'clawdstrike-engine-test-' + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('denies forbidden file reads (deterministic)', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't1',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: { type: 'file', path: `${homedir()}/.ssh/id_rsa`, operation: 'read' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('forbidden_path');
  });

  it('warns but allows in advisory mode', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'advisory',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't2',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: { type: 'file', path: `${homedir()}/.ssh/id_rsa`, operation: 'read' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('warn');
  });

  it('blocks secret leaks in tool output', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't3',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: { type: 'tool', toolName: 'api_call', parameters: {}, result: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('secret_leak');
  });

  it('enforces allowed_write_roots for output-style command flags', async () => {
    const policyPath = join(testDir, 'policy.yaml');
    writeFileSync(policyPath, `
extends: clawdstrike:ai-agent-minimal
filesystem:
  allowed_write_roots:
    - /tmp/allowed
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
      guards: { patch_integrity: false },
    });

    const base: Omit<PolicyEvent, 'eventId' | 'eventType' | 'data'> = {
      timestamp: new Date().toISOString(),
    };

    const denyEq: PolicyEvent = {
      ...base,
      eventId: 't4',
      eventType: 'command_exec',
      data: { type: 'command', command: 'tool', args: ['--output=/tmp/disallowed/out.txt'] },
    };
    const decisionEq = await engine.evaluate(denyEq);
    expect(decisionEq.status).toBe('deny');
    expect(decisionEq.reason).toContain('Write path not in allowed roots');

    const denySpace: PolicyEvent = {
      ...base,
      eventId: 't5',
      eventType: 'command_exec',
      data: { type: 'command', command: 'tool', args: ['--log-file', '/tmp/disallowed/log.txt'] },
    };
    const decisionSpace = await engine.evaluate(denySpace);
    expect(decisionSpace.status).toBe('deny');
    expect(decisionSpace.reason).toContain('Write path not in allowed roots');
  });

  it('fails closed for CUA events when computer_use guard config is missing', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'cua-missing-1',
      eventType: 'input.inject',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'input.inject',
        input_type: 'keyboard',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('computer_use');
  });

  it('warns on computer_use allowlist misses in guardrail mode', async () => {
    const policyPath = join(testDir, 'cua-guardrail-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const allowedEvent: PolicyEvent = {
      eventId: 'cua-guardrail-allow',
      eventType: 'input.inject',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'input.inject',
        input_type: 'keyboard',
      },
    };
    const allowedDecision = await engine.evaluate(allowedEvent);
    expect(allowedDecision.status).toBe('allow');

    const deniedEvent: PolicyEvent = {
      eventId: 'cua-guardrail-deny',
      eventType: 'remote.session.disconnect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.disconnect',
      },
    };
    const warnedDecision = await engine.evaluate(deniedEvent);
    expect(warnedDecision.status).toBe('warn');
    expect(warnedDecision.guard).toBe('computer_use');
  });

  it('denies computer_use allowlist misses in fail_closed mode', async () => {
    const policyPath = join(testDir, 'cua-fail-closed-policy.yaml');
    writeFileSync(policyPath, `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions:
      - "remote.session.connect"
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const deniedEvent: PolicyEvent = {
      eventId: 'cua-fail-closed-deny',
      eventType: 'remote.session.disconnect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.disconnect',
      },
    };

    const deniedDecision = await engine.evaluate(deniedEvent);
    expect(deniedDecision.status).toBe('deny');
    expect(deniedDecision.guard).toBe('computer_use');
  });

  it('enforces egress policy on CUA connect with destination metadata', async () => {
    const policyPath = join(testDir, 'cua-connect-egress-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const allowedConnect: PolicyEvent = {
      eventId: 'cua-connect-egress-allow',
      eventType: 'remote.session.connect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.connect',
        direction: 'outbound',
        host: 'desk.example.com',
        port: 443,
        url: 'https://desk.example.com/session',
      },
    };
    const allowedDecision = await engine.evaluate(allowedConnect);
    expect(allowedDecision.status).toBe('allow');

    const deniedConnect: PolicyEvent = {
      eventId: 'cua-connect-egress-deny',
      eventType: 'remote.session.connect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.connect',
        direction: 'outbound',
        host: 'evil.invalid',
        port: 443,
        url: 'https://evil.invalid/session',
      },
    };
    const deniedDecision = await engine.evaluate(deniedConnect);
    expect(deniedDecision.status).toBe('deny');
    expect(deniedDecision.guard).toBe('egress');
  });

  it('fails closed for CUA connect when egress guard cannot evaluate destination', async () => {
    const policyPath = join(testDir, 'cua-connect-metadata-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const missingDestination: PolicyEvent = {
      eventId: 'cua-connect-metadata-deny',
      eventType: 'remote.session.connect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.connect',
        direction: 'outbound',
      },
    };
    const decision = await engine.evaluate(missingDestination);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('egress');
    expect(decision.reason).toContain('missing destination');
  });

  it('returns warn in observe mode when CUA action is outside allowed_actions', async () => {
    const policyPath = join(testDir, 'cua-observe-policy.yaml');
    writeFileSync(policyPath, `
version: "1.2.0"
guards:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions:
      - "remote.session.connect"
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'cua-observe-warn',
      eventType: 'remote.session.disconnect',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'session.disconnect',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('warn');
    expect(decision.guard).toBe('computer_use');
  });

  it('enforces input_injection_capability fail-closed checks', async () => {
    const policyPath = join(testDir, 'cua-input-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const missingInputType: PolicyEvent = {
      eventId: 'cua-input-missing-type',
      eventType: 'input.inject',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'input.inject',
        postconditionProbeHash: 'probe-1',
      },
    };
    const missingTypeDecision = await engine.evaluate(missingInputType);
    expect(missingTypeDecision.status).toBe('deny');
    expect(missingTypeDecision.guard).toBe('input_injection_capability');

    const missingProbe: PolicyEvent = {
      eventId: 'cua-input-missing-probe',
      eventType: 'input.inject',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'input.inject',
        input_type: 'keyboard',
      },
    };
    const missingProbeDecision = await engine.evaluate(missingProbe);
    expect(missingProbeDecision.status).toBe('deny');
    expect(missingProbeDecision.guard).toBe('input_injection_capability');
  });

  it('enforces remote_desktop_side_channel channel toggles and transfer size limits', async () => {
    const policyPath = join(testDir, 'cua-side-channel-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const clipboardEvent: PolicyEvent = {
      eventId: 'cua-clipboard-deny',
      eventType: 'remote.clipboard',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'clipboard',
        direction: 'read',
      },
    };
    const clipboardDecision = await engine.evaluate(clipboardEvent);
    expect(clipboardDecision.status).toBe('deny');
    expect(clipboardDecision.guard).toBe('remote_desktop_side_channel');

    const transferEvent: PolicyEvent = {
      eventId: 'cua-transfer-deny',
      eventType: 'remote.file_transfer',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'file_transfer',
        direction: 'upload',
        transfer_size: 101,
      },
    };
    const transferDecision = await engine.evaluate(transferEvent);
    expect(transferDecision.status).toBe('deny');
    expect(transferDecision.guard).toBe('remote_desktop_side_channel');

    const transferMissingSize: PolicyEvent = {
      eventId: 'cua-transfer-missing-size',
      eventType: 'remote.file_transfer',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'file_transfer',
        direction: 'upload',
      },
    };
    const missingSizeDecision = await engine.evaluate(transferMissingSize);
    expect(missingSizeDecision.status).toBe('deny');
    expect(missingSizeDecision.guard).toBe('remote_desktop_side_channel');
  });

  it('enforces file transfer caps fail-closed when max_transfer_size_bytes is configured', async () => {
    const policyPath = join(testDir, 'cua-side-channel-zero-cap-policy.yaml');
    writeFileSync(policyPath, `
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
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
    });

    const overLimitEvent: PolicyEvent = {
      eventId: 'cua-transfer-zero-cap-over-limit',
      eventType: 'remote.file_transfer',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'file_transfer',
        direction: 'upload',
        transfer_size: 1,
      },
    };
    const overLimitDecision = await engine.evaluate(overLimitEvent);
    expect(overLimitDecision.status).toBe('deny');
    expect(overLimitDecision.guard).toBe('remote_desktop_side_channel');

    const exactlyZeroEvent: PolicyEvent = {
      eventId: 'cua-transfer-zero-cap-zero-size',
      eventType: 'remote.file_transfer',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'file_transfer',
        direction: 'upload',
        transfer_size: 0,
      },
    };
    const exactlyZeroDecision = await engine.evaluate(exactlyZeroEvent);
    expect(exactlyZeroDecision.status).toBe('allow');

    const missingSizeEvent: PolicyEvent = {
      eventId: 'cua-transfer-zero-cap-missing-size',
      eventType: 'remote.file_transfer',
      timestamp: new Date().toISOString(),
      data: {
        type: 'cua',
        cuaAction: 'file_transfer',
        direction: 'upload',
      },
    };
    const missingSizeDecision = await engine.evaluate(missingSizeEvent);
    expect(missingSizeDecision.status).toBe('deny');
    expect(missingSizeDecision.guard).toBe('remote_desktop_side_channel');
  });
});
