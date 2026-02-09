import type { Decision, DecisionStatus, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';

import { AsyncGuardRuntime } from './async/runtime.js';
import type { GuardResult, Severity } from './async/types.js';
import type { CustomGuard, CustomGuardRegistry } from './custom-registry.js';
import { resolvePlaceholders } from './policy/placeholders.js';
import type { Policy } from './policy/schema.js';
import { loadPolicyFromFile } from './policy/loader.js';
import { validatePolicy } from './policy/validator.js';
import { buildAsyncGuards } from './guards/registry.js';

export interface PolicyEngineOptions {
  policyRef: string;
  resolve?: boolean;
  customGuardRegistry?: CustomGuardRegistry;
}

export interface PolicyEngineFromPolicyOptions {
  customGuardRegistry?: CustomGuardRegistry;
}

export function createPolicyEngine(options: PolicyEngineOptions): PolicyEngineLike {
  const policy = loadPolicyFromFile(options.policyRef, { resolve: options.resolve !== false });
  return createPolicyEngineFromPolicy(policy, { customGuardRegistry: options.customGuardRegistry });
}

export function createPolicyEngineFromPolicy(
  policy: Policy,
  options: PolicyEngineFromPolicyOptions = {},
): PolicyEngineLike {
  const lint = validatePolicy(policy);
  if (!lint.valid) {
    const msg = lint.errors.join('; ') || 'policy validation failed';
    throw new Error(msg);
  }

  const customGuards = buildCustomGuardsFromPolicy(policy, options.customGuardRegistry);
  const guards = buildAsyncGuards(policy);
  const runtime = new AsyncGuardRuntime();
  const failFast = policy.settings?.fail_fast === true;

  return createEngineInstance(runtime, guards, customGuards, failFast);
}

function createEngineInstance(
  runtime: AsyncGuardRuntime,
  guards: ReturnType<typeof buildAsyncGuards>,
  customGuards: CustomGuard[],
  failFast: boolean,
): PolicyEngineLike {
  return {
    async evaluate(event: PolicyEvent): Promise<Decision> {
      const perGuard: GuardResult[] = [];

      const customResults = await evaluateCustomGuards(customGuards, event, failFast);
      perGuard.push(...customResults);

      // If we've already denied locally, don't run async guards (avoids unnecessary network calls).
      if (customResults.every((r) => r.allowed)) {
        const asyncResults = await runtime.evaluateAsyncGuards(guards, event);
        perGuard.push(...asyncResults);
      }

      const overall = aggregateOverall(perGuard);
      return decisionFromOverall(overall);
    },
  };
}

function buildCustomGuardsFromPolicy(policy: Policy, registry: CustomGuardRegistry | undefined): CustomGuard[] {
  const specs = Array.isArray((policy as any).custom_guards) ? ((policy as any).custom_guards as unknown[]) : [];
  if (specs.length === 0) return [];

  if (!registry) {
    const firstId = isPlainObject(specs[0]) ? String((specs[0] as any).id ?? '') : '';
    const suffix = firstId ? ` ${firstId}` : '';
    throw new Error(`Policy requires custom guard${suffix} but no CustomGuardRegistry was provided`);
  }

  const out: CustomGuard[] = [];
  for (const spec of specs) {
    if (!isPlainObject(spec)) continue;
    if ((spec as any).enabled === false) continue;
    const id = String((spec as any).id ?? '');
    const rawConfig = isPlainObject((spec as any).config) ? ((spec as any).config as Record<string, unknown>) : {};
    const config = resolvePlaceholders(rawConfig) as Record<string, unknown>;
    out.push(registry.build(id, config));
  }

  return out;
}

async function evaluateCustomGuards(guards: CustomGuard[], event: PolicyEvent, failFast: boolean): Promise<GuardResult[]> {
  const out: GuardResult[] = [];

  for (const guard of guards) {
    let handles = false;
    try {
      handles = guard.handles(event);
    } catch (err) {
      out.push(customGuardError(guard.name, err));
      if (failFast) break;
      continue;
    }

    if (!handles) continue;

    try {
      const res = await guard.check(event);
      out.push(normalizeCustomGuardResult(guard.name, res));
    } catch (err) {
      out.push(customGuardError(guard.name, err));
    }

    if (failFast && out.length > 0 && out[out.length - 1]!.allowed === false) {
      break;
    }
  }

  return out;
}

function normalizeCustomGuardResult(guardName: string, value: unknown): GuardResult {
  if (!isPlainObject(value)) {
    return {
      allowed: false,
      guard: guardName,
      severity: 'high',
      message: 'Invalid custom guard result (expected object)',
    };
  }

  const allowed = (value as any).allowed;
  const severity = (value as any).severity;
  const message = (value as any).message;
  const details = (value as any).details;

  if (typeof allowed !== 'boolean') {
    return { allowed: false, guard: guardName, severity: 'high', message: 'Invalid custom guard result (allowed)' };
  }

  const sev = isSeverity(severity) ? severity : allowed ? 'low' : 'high';
  const msg = typeof message === 'string' && message.trim() !== '' ? message : allowed ? 'Allowed' : 'Denied';

  const out: GuardResult = { allowed, guard: guardName, severity: sev, message: msg };
  if (isPlainObject(details)) {
    out.details = details as Record<string, unknown>;
  }

  return out;
}

function customGuardError(guardName: string, err: unknown): GuardResult {
  const message = err instanceof Error ? err.message : String(err);
  return { allowed: false, guard: guardName, severity: 'high', message: `Custom guard error: ${message}` };
}

function decisionFromOverall(overall: GuardResult): Decision {
  const status: DecisionStatus = overall.allowed
    ? overall.severity === 'medium'
      ? 'warn'
      : 'allow'
    : 'deny';

  const out: Decision = { status };

  // Align with hush JSON: omit guard/severity for plain allow.
  if (status !== 'allow') {
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

function isSeverity(value: unknown): value is Severity {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical';
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
