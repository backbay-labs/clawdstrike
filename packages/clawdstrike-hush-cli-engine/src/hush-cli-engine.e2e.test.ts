import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

import type { PolicyEvent } from '@clawdstrike/adapter-core';
import { createHushCliEngine } from './hush-cli-engine.js';

const describeE2E = process.env.HUSH_E2E === '1' ? describe : describe.skip;

describeE2E('hush-cli-engine (e2e)', () => {
  it('evaluates via real hush binary', async () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(__dirname, '../../..');

    const engine = createHushCliEngine({
      hushPath: process.env.HUSH_PATH ?? 'hush',
      policyRef:
        process.env.HUSH_POLICY_REF ?? path.join(repoRoot, 'rulesets/permissive.yaml'),
      timeoutMs: 10_000,
    });

    const event: PolicyEvent = {
      eventId: 'evt-e2e',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: { type: 'tool', toolName: 'e2e', parameters: { ok: true } },
      metadata: { source: 'vitest' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.reason).not.toBe('engine_error');
    expect(typeof decision.allowed).toBe('boolean');
    expect(typeof decision.denied).toBe('boolean');
    expect(typeof decision.warn).toBe('boolean');
  });
});

