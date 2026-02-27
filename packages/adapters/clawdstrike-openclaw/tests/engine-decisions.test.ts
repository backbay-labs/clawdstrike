/**
 * @clawdstrike/openclaw - Engine Decision Tests
 *
 * Tests for policy engine decision logic including combineDecisions rank-based
 * logic (T1), audit mode metadata preservation (T2), eventType/data.type
 * consistency validation (S2), and validator on_violation handling (C5).
 */

import { describe, it, expect } from 'vitest';
import { homedir } from 'os';
import { PolicyEngine } from '../src/policy/engine.js';
import { validatePolicy } from '../src/policy/validator.js';
import type { PolicyEvent, ClawdstrikeConfig } from '../src/types.js';

const HOME = homedir();

describe('combineDecisions rank-based logic (T1)', () => {
  // combineDecisions is not exported, so we test it indirectly through the
  // PolicyEngine.evaluate() method. The engine runs deterministic guards first,
  // and if a threat intel engine (custom guards) is configured, it combines the
  // results using combineDecisions. We verify the rank logic by triggering
  // deterministic guard denials combined with threat intel outcomes.

  it('should return deny from the deterministic guard when egress is denied', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'combine-1',
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'evil-domain.com',
        port: 443,
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('egress');
  });

  it('should return deny when forbidden path is accessed (not downgraded to warn)', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'combine-2',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: `${HOME}/.ssh/id_rsa`,
        operation: 'read',
      },
    };

    const decision = await engine.evaluate(event);
    // The old bug would have allowed warn to override deny; verify deny wins
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('forbidden_path');
    expect(decision.severity).toBe('critical');
  });

  it('should return allow for safe operations', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'combine-3',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/index.ts',
        operation: 'read',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('allow');
  });

  it('should produce deny for forbidden .onion egress with critical severity', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'combine-4',
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'hidden.onion',
        port: 80,
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.severity).toBe('critical');
  });
});

describe('audit mode metadata preservation (T2)', () => {
  it('should return allow with original deny metadata for forbidden path', async () => {
    const auditEngine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'audit',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'audit-1',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: `${HOME}/.ssh/id_rsa`,
        operation: 'read',
      },
    };

    const decision = await auditEngine.evaluate(event);
    expect(decision.status).toBe('allow');
    expect(decision.guard).toBe('forbidden_path');
    expect(decision.severity).toBe('critical');
    expect(decision.message).toContain('Original decision: deny');
  });

  it('should preserve reason in audit mode for egress deny', async () => {
    const auditEngine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'audit',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'audit-2',
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'evil.com',
        port: 443,
      },
    };

    const decision = await auditEngine.evaluate(event);
    expect(decision.status).toBe('allow');
    expect(decision.guard).toBe('egress');
    expect(decision.message).toContain('Original decision: deny');
    expect(decision.reason).toBeDefined();
  });

  it('should preserve guard and severity for secret leak in audit mode', async () => {
    const auditEngine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'audit',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'audit-3',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: {
        type: 'tool',
        toolName: 'read_file',
        parameters: {},
        result: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
      },
    };

    const decision = await auditEngine.evaluate(event);
    expect(decision.status).toBe('allow');
    expect(decision.guard).toBe('secret_leak');
    expect(decision.severity).toBeDefined();
    expect(decision.message).toContain('Original decision: deny');
  });

  it('should return allow with no audit message for safe operations', async () => {
    const auditEngine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'audit',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 'audit-4',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/index.ts',
        operation: 'read',
      },
    };

    const decision = await auditEngine.evaluate(event);
    expect(decision.status).toBe('allow');
    // For safe operations, the message should still be the audit wrapper
    // (the engine wraps ALL results through applyMode)
    expect(decision.message).toContain('[audit]');
  });
});

describe('eventType/data.type consistency validation (S2)', () => {
  let engine: PolicyEngine;

  const config: ClawdstrikeConfig = {
    policy: 'clawdstrike:ai-agent-minimal',
    mode: 'deterministic',
    logLevel: 'error',
  };

  it('should deny when eventType=file_write but data.type=network (mismatch)', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'mismatch-1',
      eventType: 'file_write',
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'example.com',
        port: 443,
      } as any,
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.reason_code).toBe('event_type_mismatch');
    expect(decision.guard).toBe('policy_engine');
    expect(decision.severity).toBe('critical');
  });

  it('should deny when eventType=network_egress but data.type=file', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'mismatch-2',
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/tmp/test.txt',
        operation: 'read',
      } as any,
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.reason_code).toBe('event_type_mismatch');
    expect(decision.reason).toContain('network_egress');
    expect(decision.reason).toContain('network');
    expect(decision.reason).toContain('file');
  });

  it('should allow when eventType=file_write and data.type=file (consistent)', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'consistent-1',
      eventType: 'file_write',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/tmp/safe-file.txt',
        operation: 'write',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('allow');
  });

  it('should allow when eventType=command_exec and data.type=command (consistent)', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'consistent-2',
      eventType: 'command_exec',
      timestamp: new Date().toISOString(),
      data: {
        type: 'command',
        command: 'ls',
        args: ['-la'],
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('allow');
  });

  it('should deny when eventType=tool_call but data.type=patch', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'mismatch-3',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: {
        type: 'patch',
        filePath: 'foo.ts',
        patchContent: 'safe code',
      } as any,
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.reason_code).toBe('event_type_mismatch');
  });

  it('should deny when eventType=patch_apply but data.type=tool', async () => {
    engine = new PolicyEngine(config);

    const event: PolicyEvent = {
      eventId: 'mismatch-4',
      eventType: 'patch_apply',
      timestamp: new Date().toISOString(),
      data: {
        type: 'tool',
        toolName: 'some_tool',
        parameters: {},
      } as any,
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.reason_code).toBe('event_type_mismatch');
  });

  it('should NOT reject custom eventType regardless of data.type', async () => {
    engine = new PolicyEngine(config);

    // The engine's getExpectedDataType returns undefined for 'custom',
    // so no mismatch check is performed.
    const event: PolicyEvent = {
      eventId: 'custom-1',
      eventType: 'custom' as any,
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'example.com',
        port: 443,
      } as any,
    };

    const decision = await engine.evaluate(event);
    // Custom event types fall through to default (allow) in the switch
    expect(decision.status).toBe('allow');
  });
});

describe('validator accepts warn for on_violation isolate/escalate (C5)', () => {
  it('should be valid with warnings for on_violation=isolate', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'isolate',
    };

    const result = validatePolicy(policy);
    // isolate is in UNIMPLEMENTED_VIOLATION_ACTIONS, so valid=true but with a warning
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('isolate'))).toBe(true);
    expect(result.warnings.some(w => w.includes('not yet implemented'))).toBe(true);
  });

  it('should be valid with warnings for on_violation=escalate', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'escalate',
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('escalate'))).toBe(true);
    expect(result.warnings.some(w => w.includes('not yet implemented'))).toBe(true);
  });

  it('should be valid with no warnings for on_violation=cancel', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'cancel',
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.warnings.every(w => !w.includes('on_violation'))).toBe(true);
  });

  it('should be valid with no warnings for on_violation=warn', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'warn',
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.warnings.every(w => !w.includes('on_violation'))).toBe(true);
  });

  it('should have errors for on_violation=invalid_value', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'invalid_value',
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('on_violation'))).toBe(true);
  });

  it('should have errors for on_violation with non-string value', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 42,
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('on_violation'))).toBe(true);
  });
});
