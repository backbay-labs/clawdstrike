import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';

import { AsyncGuardRuntime } from './async/runtime.js';
import type { GuardResult, Severity } from './async/types.js';
import type { Policy } from './policy/schema.js';
import { loadPolicyFromFile } from './policy/loader.js';
import { validatePolicy } from './policy/validator.js';
import { buildAsyncGuards } from './guards/registry.js';

export interface PolicyEngineOptions {
  policyRef: string;
  resolve?: boolean;
}

export function createPolicyEngine(options: PolicyEngineOptions): PolicyEngineLike {
  const policy = loadPolicyFromFile(options.policyRef, { resolve: options.resolve !== false });
  return createPolicyEngineFromPolicy(policy);
}

export function createPolicyEngineFromPolicy(policy: Policy): PolicyEngineLike {
  const lint = validatePolicy(policy);
  if (!lint.valid) {
    const msg = lint.errors.join('; ') || 'policy validation failed';
    throw new Error(msg);
  }

  const guards = buildAsyncGuards(policy);
  const runtime = new AsyncGuardRuntime();

  return createEngineInstance(runtime, guards);
}

function createEngineInstance(
  runtime: AsyncGuardRuntime,
  guards: ReturnType<typeof buildAsyncGuards>,
): PolicyEngineLike {
  return {
    async evaluate(event: PolicyEvent): Promise<Decision> {
      const perGuard = await runtime.evaluateAsyncGuards(guards, event);
      const overall = aggregateOverall(perGuard);
      return decisionFromOverall(overall);
    },
  };
}

function decisionFromOverall(overall: GuardResult): Decision {
  const denied = !overall.allowed;
  const warn = overall.allowed && overall.severity === 'medium';

  const out: Decision = {
    allowed: overall.allowed,
    denied,
    warn,
  };

  // Align with hush JSON: omit guard/severity for plain allow.
  if (denied || warn) {
    out.guard = overall.guard;
    out.severity = overall.severity as any;
  }

  out.message = overall.message;
  return out;
}

function aggregateOverall(results: GuardResult[]): GuardResult {
  if (results.length === 0) {
    return { allowed: true, guard: 'engine', severity: 'low', message: 'Allowed' };
  }

  let best = results[0]!;
  for (let i = 1; i < results.length; i++) {
    const r = results[i]!;

    const bestBlocks = !best.allowed;
    const rBlocks = !r.allowed;

    if (rBlocks && !bestBlocks) {
      best = r;
      continue;
    }

    if (rBlocks === bestBlocks && severityOrd(r.severity) > severityOrd(best.severity)) {
      best = r;
    }
  }

  return best;
}

function severityOrd(s: Severity): number {
  switch (s) {
    case 'low':
      return 0;
    case 'medium':
      return 1;
    case 'high':
      return 2;
    case 'critical':
      return 3;
  }
}
