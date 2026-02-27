/**
 * @clawdstrike/openclaw - Fail-Closed Behavior Tests (T8)
 *
 * Tests that the PolicyEngine produces deny decisions when guards throw
 * exceptions. The design philosophy is "fail closed": errors during
 * evaluation deny access rather than silently allowing.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { PolicyEngine } from '../src/policy/engine.js';
import { ForbiddenPathGuard, EgressGuard, SecretLeakGuard, PatchIntegrityGuard } from '../src/guards/index.js';
import type { PolicyEvent, ClawdstrikeConfig } from '../src/types.js';

const baseConfig: ClawdstrikeConfig = {
  policy: 'clawdstrike:ai-agent-minimal',
  mode: 'deterministic',
  logLevel: 'error',
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Fail-closed guard evaluation (T8)', () => {
  it('should deny when ForbiddenPathGuard.checkSync throws', async () => {
    vi.spyOn(ForbiddenPathGuard.prototype, 'checkSync').mockImplementation(() => {
      throw new Error('Simulated guard failure');
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-1',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/index.ts',
        operation: 'read',
      },
    };

    // The engine should catch the exception and deny, not bubble the error
    // or silently allow. This is the fail-closed contract.
    let decision;
    try {
      decision = await engine.evaluate(event);
    } catch {
      // If the engine lets the exception propagate, that also counts as
      // fail-closed (the operation cannot proceed). But the engine should
      // ideally catch and return deny.
    }

    // Either the engine threw (operation blocked) or returned deny
    if (decision) {
      expect(decision.status).toBe('deny');
    }
    // If an exception was thrown, the test passes because the tool call
    // would not have been allowed to proceed
  });

  it('should deny when EgressGuard.checkSync throws', async () => {
    vi.spyOn(EgressGuard.prototype, 'checkSync').mockImplementation(() => {
      throw new Error('Simulated egress guard failure');
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-2',
      eventType: 'network_egress',
      timestamp: new Date().toISOString(),
      data: {
        type: 'network',
        host: 'api.github.com',
        port: 443,
      },
    };

    let decision;
    try {
      decision = await engine.evaluate(event);
    } catch {
      // Exception propagation also blocks the operation (fail-closed)
    }

    if (decision) {
      expect(decision.status).toBe('deny');
    }
  });

  it('should deny when SecretLeakGuard.checkSync throws', async () => {
    vi.spyOn(SecretLeakGuard.prototype, 'checkSync').mockImplementation(() => {
      throw new Error('Simulated secret leak guard failure');
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-3',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: {
        type: 'tool',
        toolName: 'safe_tool',
        parameters: {},
        result: 'Normal content',
      },
    };

    let decision;
    try {
      decision = await engine.evaluate(event);
    } catch {
      // Exception propagation also blocks the operation (fail-closed)
    }

    if (decision) {
      expect(decision.status).toBe('deny');
    }
  });

  it('should deny when PatchIntegrityGuard.checkSync throws', async () => {
    vi.spyOn(PatchIntegrityGuard.prototype, 'checkSync').mockImplementation(() => {
      throw new Error('Simulated patch integrity guard failure');
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-4',
      eventType: 'patch_apply',
      timestamp: new Date().toISOString(),
      data: {
        type: 'patch',
        filePath: 'safe.ts',
        patchContent: 'const x = 1;',
      },
    };

    let decision;
    try {
      decision = await engine.evaluate(event);
    } catch {
      // Exception propagation also blocks the operation (fail-closed)
    }

    if (decision) {
      expect(decision.status).toBe('deny');
    }
  });

  it('should never return allow when a guard throws (fail-closed invariant)', async () => {
    // This is the critical invariant: a guard error must never result in allow.
    // Test with a normally-allowed event to make sure the exception turns it
    // into a deny.

    vi.spyOn(ForbiddenPathGuard.prototype, 'checkSync').mockImplementation(() => {
      throw new Error('Unexpected guard crash');
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-invariant',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/safe-file.ts',
        operation: 'read',
      },
    };

    let gotAllow = false;
    try {
      const decision = await engine.evaluate(event);
      if (decision.status === 'allow') {
        gotAllow = true;
      }
    } catch {
      // Exception means the operation was blocked — correct behavior
    }

    expect(gotAllow).toBe(false);
  });

  it('should handle the case where checkSync returns undefined (defensive)', async () => {
    // Some edge cases might cause a guard to return undefined instead of
    // a proper result. The engine should treat this as a failure.
    vi.spyOn(ForbiddenPathGuard.prototype, 'checkSync').mockImplementation(() => {
      return undefined as any;
    });

    const engine = new PolicyEngine(baseConfig);

    const event: PolicyEvent = {
      eventId: 'fail-closed-undefined',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/safe-file.ts',
        operation: 'read',
      },
    };

    let decision;
    try {
      decision = await engine.evaluate(event);
    } catch {
      // Exception means fail-closed was triggered
    }

    // The engine should either throw or return deny, never allow
    if (decision) {
      expect(decision.status).not.toBe('allow');
    }
  });
});
