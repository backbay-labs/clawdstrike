import { homedir } from 'node:os';
import path from 'node:path';

import type { PolicyEngineLike as CanonicalPolicyEngineLike, PolicyEvent as CanonicalPolicyEvent } from '@clawdstrike/adapter-core';
import { createPolicyEngineFromPolicy, type Policy as CanonicalPolicy } from '@clawdstrike/policy';

import { mergeConfig } from '../config.js';
import { EgressGuard, ForbiddenPathGuard, PatchIntegrityGuard, SecretLeakGuard } from '../guards/index.js';
import type { Decision, EvaluationMode, ClawdstrikeConfig, Policy, PolicyEvent, Severity } from '../types.js';
import { sanitizeOutputText } from '../sanitizer/output-sanitizer.js';

import { loadPolicy } from './loader.js';
import { validatePolicy } from './validator.js';

function expandHome(p: string): string {
  return p.replace(/^~(?=\/|$)/, homedir());
}

function normalizePathForPrefix(p: string): string {
  return path.resolve(expandHome(p));
}

export class PolicyEngine {
  private readonly config: Required<ClawdstrikeConfig>;
  private readonly policy: Policy;
  private readonly forbiddenPathGuard: ForbiddenPathGuard;
  private readonly egressGuard: EgressGuard;
  private readonly secretLeakGuard: SecretLeakGuard;
  private readonly patchIntegrityGuard: PatchIntegrityGuard;
  private readonly threatIntelEngine: CanonicalPolicyEngineLike | null;

  constructor(config: ClawdstrikeConfig = {}) {
    this.config = mergeConfig(config);
    this.policy = loadPolicy(this.config.policy);
    this.forbiddenPathGuard = new ForbiddenPathGuard();
    this.egressGuard = new EgressGuard();
    this.secretLeakGuard = new SecretLeakGuard();
    this.patchIntegrityGuard = new PatchIntegrityGuard();
    this.threatIntelEngine = buildThreatIntelEngine(this.policy);
  }

  enabledGuards(): string[] {
    const g = this.config.guards;
    const enabled: string[] = [];
    if (g.forbidden_path) enabled.push('forbidden_path');
    if (g.egress) enabled.push('egress');
    if (g.secret_leak) enabled.push('secret_leak');
    if (g.patch_integrity) enabled.push('patch_integrity');
    if (g.mcp_tool) enabled.push('mcp_tool');
    return enabled;
  }

  getPolicy(): Policy {
    return this.policy;
  }

  async lintPolicy(policyRef: string): Promise<{ valid: boolean; errors: string[]; warnings: string[] }> {
    try {
      const policy = loadPolicy(policyRef);
      return validatePolicy(policy);
    } catch (err) {
      return { valid: false, errors: [String(err)], warnings: [] };
    }
  }

  redactSecrets(content: string): string {
    return this.secretLeakGuard.redact(content);
  }

  sanitizeOutput(content: string): string {
    // 1) Secrets (high-confidence tokens).
    const secretsRedacted = this.secretLeakGuard.redact(content);
    // 2) PII (emails/phones/SSN/CC, etc).
    return sanitizeOutputText(secretsRedacted).sanitized;
  }

  async evaluate(event: PolicyEvent): Promise<Decision> {
    const base = this.evaluateDeterministic(event);

    // Fail fast on deterministic violations to avoid unnecessary external calls.
    if (base.status === 'deny' || base.status === 'warn') {
      return this.applyMode(base, this.config.mode);
    }

    if (this.threatIntelEngine) {
      const ti = await this.threatIntelEngine.evaluate(toCanonicalEvent(event));
      const tiApplied = this.applyOnViolation(ti as Decision);
      const combined = combineDecisions(base, tiApplied);
      return this.applyMode(combined, this.config.mode);
    }

    return this.applyMode(base, this.config.mode);
  }

  private applyMode(result: Decision, mode: EvaluationMode): Decision {
    if (mode === 'audit') {
      return { status: 'allow' };
    }

    if (mode === 'advisory' && result.status === 'deny') {
      return {
        status: 'warn',
        reason: result.reason,
        guard: result.guard,
        severity: result.severity,
        message: result.reason,
      };
    }

    return result;
  }

  private evaluateDeterministic(event: PolicyEvent): Decision {
    const allowed: Decision = { status: 'allow' };

    switch (event.eventType) {
      case 'file_read':
      case 'file_write':
        return this.checkFilesystem(event);
      case 'network_egress':
        return this.checkEgress(event);
      case 'command_exec':
        return this.checkExecution(event);
      case 'tool_call':
        return this.checkToolCall(event);
      case 'patch_apply':
        return this.checkPatch(event);
      default:
        return allowed;
    }
  }

  private checkFilesystem(event: PolicyEvent): Decision {
    if (!this.config.guards.forbidden_path) {
      return { status: 'allow' };
    }

    // First, enforce forbidden path patterns.
    const forbidden = this.forbiddenPathGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(forbidden);
    if (mapped.status === 'deny' || mapped.status === 'warn') {
      return this.applyOnViolation(mapped);
    }

    // Then, enforce write roots if configured.
    if (event.eventType === 'file_write' && event.data.type === 'file') {
      const allowedWriteRoots = this.policy.filesystem?.allowed_write_roots;
      if (allowedWriteRoots && allowedWriteRoots.length > 0) {
        const filePath = normalizePathForPrefix(event.data.path);
        const ok = allowedWriteRoots.some((root) => {
          const rootPath = normalizePathForPrefix(root);
          return filePath === rootPath || filePath.startsWith(rootPath + path.sep);
        });
        if (!ok) {
          return this.applyOnViolation({
            status: 'deny',
            reason: 'Write path not in allowed roots',
            guard: 'forbidden_path',
            severity: 'high',
          });
        }
      }
    }

    return { status: 'allow' };
  }

  private checkEgress(event: PolicyEvent): Decision {
    if (!this.config.guards.egress) {
      return { status: 'allow' };
    }

    const res = this.egressGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkExecution(event: PolicyEvent): Decision {
    if (!this.config.guards.patch_integrity) {
      return { status: 'allow' };
    }

    const res = this.patchIntegrityGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkToolCall(event: PolicyEvent): Decision {
    // Optional tool allow/deny list.
    if (event.data.type === 'tool') {
      const tools = this.policy.tools;
      const toolName = event.data.toolName.toLowerCase();

      const deniedTools = tools?.denied?.map((x) => x.toLowerCase()) ?? [];
      if (deniedTools.includes(toolName)) {
        return this.applyOnViolation({
          status: 'deny',
          reason: `Tool '${event.data.toolName}' is denied by policy`,
          guard: 'mcp_tool',
          severity: 'high',
        });
      }

      const allowedTools = tools?.allowed?.map((x) => x.toLowerCase()) ?? [];
      if (allowedTools.length > 0 && !allowedTools.includes(toolName)) {
        return this.applyOnViolation({
          status: 'deny',
          reason: `Tool '${event.data.toolName}' is not in allowed tool list`,
          guard: 'mcp_tool',
          severity: 'high',
        });
      }
    }

    if (!this.config.guards.secret_leak) {
      return { status: 'allow' };
    }

    const res = this.secretLeakGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkPatch(event: PolicyEvent): Decision {
    if (this.config.guards.patch_integrity) {
      const r1 = this.patchIntegrityGuard.checkSync(event, this.policy);
      const mapped1 = this.guardResultToDecision(r1);
      const applied1 = this.applyOnViolation(mapped1);
      if (applied1.status === 'deny' || applied1.status === 'warn') return applied1;
    }

    if (this.config.guards.secret_leak) {
      const r2 = this.secretLeakGuard.checkSync(event, this.policy);
      const mapped2 = this.guardResultToDecision(r2);
      const applied2 = this.applyOnViolation(mapped2);
      if (applied2.status === 'deny' || applied2.status === 'warn') return applied2;
    }

    return { status: 'allow' };
  }

  private applyOnViolation(decision: Decision): Decision {
    const action = this.policy.on_violation;
    if (decision.status !== 'deny') return decision;

    if (action === 'warn') {
      return {
        status: 'warn',
        reason: decision.reason,
        guard: decision.guard,
        severity: decision.severity,
        message: decision.reason,
      };
    }

    return decision;
  }

  private guardResultToDecision(result: { status: 'allow' | 'deny' | 'warn'; reason?: string; severity?: Severity; guard: string }): Decision {
    if (result.status === 'allow') return { status: 'allow' };
    if (result.status === 'warn') {
      return { status: 'warn', reason: result.reason, guard: result.guard, message: result.reason };
    }
    return { status: 'deny', reason: result.reason, guard: result.guard, severity: result.severity };
  }
}

function buildThreatIntelEngine(policy: Policy): CanonicalPolicyEngineLike | null {
  const custom = policy.guards?.custom;
  if (!Array.isArray(custom) || custom.length === 0) {
    return null;
  }

  // The openclaw Policy types `custom` as `unknown`; the canonical Policy
  // expects `CustomGuardSpec[]`. We've validated it's an array above.
  // GuardConfigs has an index signature so `unknown[]` is assignable.
  const canonicalPolicy: CanonicalPolicy = {
    version: '1.1.0',
    guards: { custom },
  };

  return createPolicyEngineFromPolicy(canonicalPolicy);
}

function toCanonicalEvent(event: PolicyEvent): CanonicalPolicyEvent {
  // OpenClaw events are compatible with adapter-core's PolicyEvent shape. Keep the
  // raw eventId/timestamp/metadata for audit trails.
  return event as unknown as CanonicalPolicyEvent;
}

function combineDecisions(base: Decision, next: Decision): Decision {
  if (next.status === 'deny' || next.status === 'warn') return next;
  return base;
}
