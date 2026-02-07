import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, it, expect } from 'vitest';

import type { PolicyEvent } from '@clawdstrike/adapter-core';
import { createHushCliEngine } from './hush-cli-engine.js';

const describeE2E = hasRunnableHush(process.env.HUSH_PATH ?? 'hush') ? describe : describe.skip;

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
    expect(['allow', 'warn', 'deny']).toContain(decision.status);
  });

  it('matches fixture decisions (default ruleset)', async () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(__dirname, '../../..');

    const engine = createHushCliEngine({
      hushPath: process.env.HUSH_PATH ?? 'hush',
      policyRef: 'default',
      timeoutMs: 10_000,
    });

    const eventsPath = path.join(repoRoot, 'fixtures/policy-events/v1/events.jsonl');
    const expectedPath = path.join(
      repoRoot,
      'fixtures/policy-events/v1/expected/default.decisions.json',
    );

    const expectedJson = JSON.parse(fs.readFileSync(expectedPath, 'utf8')) as any;
    const expectedById = new Map<string, any>();
    for (const r of expectedJson?.results ?? []) {
      if (r && typeof r.eventId === 'string') {
        expectedById.set(r.eventId, r.decision);
      }
    }

    const lines = fs
      .readFileSync(eventsPath, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

    for (const line of lines) {
      const event = JSON.parse(line) as PolicyEvent;
      const expected = expectedById.get(event.eventId);
      if (!expected) {
        throw new Error(`missing expected decision for eventId=${event.eventId}`);
      }

      const actual = await engine.evaluate(event);
      expect(normalizeDecision(actual)).toEqual(normalizeDecision(expected));
    }
  });
});

function normalizeDecision(value: any): any {
  const out: any = { status: toStatus(value) };

  for (const k of ['reason', 'guard', 'severity', 'message'] as const) {
    const v = value?.[k];
    if (v === null || v === undefined) continue;
    out[k] = v;
  }

  return out;
}

function toStatus(value: any): 'allow' | 'warn' | 'deny' {
  if (value?.status === 'allow' || value?.status === 'warn' || value?.status === 'deny') {
    return value.status;
  }

  if (value?.denied === true) {
    return 'deny';
  }

  if (value?.warn === true) {
    return 'warn';
  }

  return 'allow';
}

function hasRunnableHush(hushPath: string): boolean {
  const result = spawnSync(hushPath, ['--version'], {
    stdio: 'ignore',
    timeout: 5_000,
  });
  return result.status === 0;
}
