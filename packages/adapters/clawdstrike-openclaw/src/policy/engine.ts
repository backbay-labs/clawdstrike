import { homedir } from 'node:os';
import path from 'node:path';

import type { PolicyEngineLike as CanonicalPolicyEngineLike, PolicyEvent as CanonicalPolicyEvent } from '@clawdstrike/adapter-core';
import { createPolicyEngineFromPolicy, type Policy as CanonicalPolicy } from '@clawdstrike/policy';

import { mergeConfig } from '../config.js';
import { EgressGuard, ForbiddenPathGuard, PatchIntegrityGuard, SecretLeakGuard } from '../guards/index.js';
import type { Decision, EvaluationMode, ClawdstrikeConfig, Policy, PolicyEvent } from '../types.js';
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
    const baseDenied = base.status === 'deny' || base.denied;
    const baseWarn = base.status === 'warn' || base.warn;
    if (baseDenied || baseWarn) {
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
      return { status: 'allow', allowed: true, denied: false, warn: false };
    }

    const isDenied = result.status === 'deny' || result.denied;
    if (mode === 'advisory' && isDenied) {
      return {
        status: 'warn',
        allowed: true,
        denied: false,
        warn: true,
        reason: result.reason,
        guard: result.guard,
        severity: result.severity,
        message: result.reason,
      };
    }

    return result;
  }

  private evaluateDeterministic(event: PolicyEvent): Decision {
    const allowed: Decision = { status: 'allow', allowed: true, denied: false, warn: false };

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
      return { status: 'allow', allowed: true, denied: false, warn: false };
    }

    // First, enforce forbidden path patterns.
    const forbidden = this.forbiddenPathGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(forbidden);
    const mappedDenied = mapped.status === 'deny' || mapped.denied;
    const mappedWarn = mapped.status === 'warn' || mapped.warn;
    if (mappedDenied || mappedWarn) {
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
            allowed: false,
            denied: true,
            warn: false,
            reason: 'Write path not in allowed roots',
            guard: 'forbidden_path',
            severity: 'high',
          });
        }
      }
    }

    return { status: 'allow', allowed: true, denied: false, warn: false };
  }

  private checkEgress(event: PolicyEvent): Decision {
    if (!this.config.guards.egress) {
      return { status: 'allow', allowed: true, denied: false, warn: false };
    }

    const res = this.egressGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkExecution(event: PolicyEvent): Decision {
    if (!this.config.guards.patch_integrity) {
      return { status: 'allow', allowed: true, denied: false, warn: false };
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

      const denied = tools?.denied?.map((x) => x.toLowerCase()) ?? [];
      if (denied.includes(toolName)) {
        return this.applyOnViolation({
          status: 'deny',
          allowed: false,
          denied: true,
          warn: false,
          reason: `Tool '${event.data.toolName}' is denied by policy`,
          guard: 'mcp_tool',
          severity: 'high',
        });
      }

      const allowed = tools?.allowed?.map((x) => x.toLowerCase()) ?? [];
      if (allowed.length > 0 && !allowed.includes(toolName)) {
        return this.applyOnViolation({
          status: 'deny',
          allowed: false,
          denied: true,
          warn: false,
          reason: `Tool '${event.data.toolName}' is not in allowed tool list`,
          guard: 'mcp_tool',
          severity: 'high',
        });
      }
    }

    if (!this.config.guards.secret_leak) {
      return { status: 'allow', allowed: true, denied: false, warn: false };
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
      const applied1Denied = applied1.status === 'deny' || applied1.denied;
      const applied1Warn = applied1.status === 'warn' || applied1.warn;
      if (applied1Denied || applied1Warn) return applied1;
    }

    if (this.config.guards.secret_leak) {
      const r2 = this.secretLeakGuard.checkSync(event, this.policy);
      const mapped2 = this.guardResultToDecision(r2);
      const applied2 = this.applyOnViolation(mapped2);
      const applied2Denied = applied2.status === 'deny' || applied2.denied;
      const applied2Warn = applied2.status === 'warn' || applied2.warn;
      if (applied2Denied || applied2Warn) return applied2;
    }

    return { status: 'allow', allowed: true, denied: false, warn: false };
  }

  private applyOnViolation(decision: Decision): Decision {
    const action = this.policy.on_violation;
    const isDenied = decision.status === 'deny' || decision.denied;
    if (!isDenied) return decision;

    if (action === 'warn') {
      return {
        status: 'warn',
        allowed: true,
        denied: false,
        warn: true,
        reason: decision.reason,
        guard: decision.guard,
        severity: decision.severity,
        message: decision.reason,
      };
    }

    return decision;
  }

  private guardResultToDecision(result: { status: 'allow' | 'deny' | 'warn'; reason?: string; severity?: any; guard: string }): Decision {
    if (result.status === 'allow') return { status: 'allow', allowed: true, denied: false, warn: false };
    if (result.status === 'warn') {
      return { status: 'warn', allowed: true, denied: false, warn: true, reason: result.reason, guard: result.guard, message: result.reason };
    }
    return { status: 'deny', allowed: false, denied: true, warn: false, reason: result.reason, guard: result.guard, severity: result.severity };
  }
}

function buildThreatIntelEngine(policy: Policy): CanonicalPolicyEngineLike | null {
  const custom = (policy.guards as any)?.custom;
  if (!Array.isArray(custom) || custom.length === 0) {
    return null;
  }

  const canonicalPolicy: CanonicalPolicy = {
    version: '1.1.0',
    guards: { custom },
  };

  return createPolicyEngineFromPolicy(canonicalPolicy as any);
}

function toCanonicalEvent(event: PolicyEvent): CanonicalPolicyEvent {
  // OpenClaw events are compatible with adapter-core's PolicyEvent shape. Keep the
  // raw eventId/timestamp/metadata for audit trails.
  return event as unknown as CanonicalPolicyEvent;
}

function combineDecisions(base: Decision, next: Decision): Decision {
  const nextDenied = next.status === 'deny' || next.denied;
  const nextWarn = next.status === 'warn' || next.warn;
  if (nextDenied || nextWarn) return next;
  return base;
}
