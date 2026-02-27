import { homedir } from 'node:os';
import path from 'node:path';

import type { PolicyEngineLike as CanonicalPolicyEngineLike } from '@clawdstrike/adapter-core';
import { parseNetworkTarget } from '@clawdstrike/adapter-core';
import { createPolicyEngineFromPolicy, type Policy as CanonicalPolicy } from '@clawdstrike/policy';

import { mergeConfig } from '../config.js';
import { EgressGuard, ForbiddenPathGuard, PatchIntegrityGuard, SecretLeakGuard } from '../guards/index.js';
import type { CuaEventData, Decision, EvaluationMode, ClawdstrikeConfig, Policy, PolicyEvent, Severity } from '../types.js';
import { sanitizeOutputText } from '../sanitizer/output-sanitizer.js';

import { loadPolicy } from './loader.js';
import { validatePolicy } from './validator.js';

function expandHome(p: string): string {
  return p.replace(/^~(?=\/|$)/, homedir());
}

function normalizePathForPrefix(p: string): string {
  return path.resolve(expandHome(p));
}

function cleanPathToken(t: string): string {
  return t.trim().replace(/^[("'`]+/, '').replace(/[)"'`;,\]}]+$/, '');
}

function isRedirectionOp(t: string): boolean {
  return t === '>' || t === '>>' || t === '1>' || t === '1>>' || t === '2>' || t === '2>>' || t === '<' || t === '<<';
}

function splitInlineRedirection(t: string): string | null {
  // Support forms like ">/path", "2>>/path", "<input".
  const m = t.match(/^(?:\d)?(?:>>|>)\s*(.+)$/);
  if (m?.[1]) return m[1];
  const mi = t.match(/^(?:<<|<)\s*(.+)$/);
  if (mi?.[1]) return mi[1];
  return null;
}

function looksLikePathToken(t: string): boolean {
  if (!t) return false;
  if (t.includes('://')) return false;
  if (t.startsWith('/') || t.startsWith('~') || t.startsWith('./') || t.startsWith('../')) return true;
  if (t === '.env' || t.startsWith('.env.')) return true;
  if (t.includes('/.ssh/') || t.includes('/.aws/') || t.includes('/.gnupg/') || t.includes('/.kube/')) return true;
  return false;
}

const WRITE_PATH_FLAG_NAMES = new Set([
  // Common output flags
  'o',
  'out',
  'output',
  'outfile',
  'output-file',
  // Common log file flags
  'log-file',
  'logfile',
  'log-path',
  'logpath',
]);

function isWritePathFlagToken(t: string): boolean {
  if (!t) return false;
  if (!t.startsWith('-')) return false;
  const normalized = t.replace(/^-+/, '').toLowerCase().replace(/_/g, '-');
  return WRITE_PATH_FLAG_NAMES.has(normalized);
}

function extractCommandPathCandidates(command: string, args: string[]): { reads: string[]; writes: string[] } {
  const tokens = [command, ...args].map((t) => String(t ?? '')).filter(Boolean);
  const reads: string[] = [];
  const writes: string[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    // Redirection operators: treat as write/read targets.
    if (isRedirectionOp(t)) {
      const next = tokens[i + 1];
      if (typeof next === 'string' && next.length > 0) {
        const cleaned = cleanPathToken(next);
        if (cleaned) {
          if (t.startsWith('>') || t === '>' || t === '>>' || t === '1>' || t === '1>>' || t === '2>' || t === '2>>') {
            writes.push(cleaned);
          } else {
            reads.push(cleaned);
          }
        }
      }
      continue;
    }

    const inline = splitInlineRedirection(t);
    if (inline) {
      const cleaned = cleanPathToken(inline);
      if (cleaned) {
        if (t.includes('>')) writes.push(cleaned);
        else reads.push(cleaned);
      }
      continue;
    }

    // Flags like --output /path or -o /path (write targets)
    if (isWritePathFlagToken(t)) {
      const next = tokens[i + 1];
      if (typeof next === 'string' && next.length > 0) {
        const cleaned = cleanPathToken(next);
        if (looksLikePathToken(cleaned)) {
          writes.push(cleaned);
          i += 1;
          continue;
        }
      }
    }

    // Flags like --output=/path
    const eq = t.indexOf('=');
    if (eq > 0) {
      const lhs = t.slice(0, eq);
      const rhs = cleanPathToken(t.slice(eq + 1));
      if (looksLikePathToken(rhs)) {
        if (isWritePathFlagToken(lhs)) writes.push(rhs);
        else reads.push(rhs);
      }
    }

    const cleanedToken = cleanPathToken(t);
    if (looksLikePathToken(cleanedToken)) {
      reads.push(cleanedToken);
    }
  }

  const uniq = (xs: string[]) => Array.from(new Set(xs.filter(Boolean)));
  return { reads: uniq(reads), writes: uniq(writes) };
}

const POLICY_REASON_CODES = {
  POLICY_DENY: 'ADC_POLICY_DENY',
  POLICY_WARN: 'ADC_POLICY_WARN',
  GUARD_ERROR: 'ADC_GUARD_ERROR',
  CUA_MALFORMED_EVENT: 'OCLAW_CUA_MALFORMED_EVENT',
  CUA_COMPUTER_USE_CONFIG_MISSING: 'OCLAW_CUA_COMPUTER_USE_CONFIG_MISSING',
  CUA_COMPUTER_USE_DISABLED: 'OCLAW_CUA_COMPUTER_USE_DISABLED',
  CUA_ACTION_NOT_ALLOWED: 'OCLAW_CUA_ACTION_NOT_ALLOWED',
  CUA_MODE_UNSUPPORTED: 'OCLAW_CUA_MODE_UNSUPPORTED',
  CUA_CONNECT_METADATA_MISSING: 'OCLAW_CUA_CONNECT_METADATA_MISSING',
  CUA_SIDE_CHANNEL_CONFIG_MISSING: 'OCLAW_CUA_SIDE_CHANNEL_CONFIG_MISSING',
  CUA_SIDE_CHANNEL_DISABLED: 'OCLAW_CUA_SIDE_CHANNEL_DISABLED',
  CUA_SIDE_CHANNEL_POLICY_DENY: 'OCLAW_CUA_SIDE_CHANNEL_POLICY_DENY',
  CUA_TRANSFER_SIZE_CONFIG_INVALID: 'OCLAW_CUA_TRANSFER_SIZE_CONFIG_INVALID',
  CUA_TRANSFER_SIZE_MISSING: 'OCLAW_CUA_TRANSFER_SIZE_MISSING',
  CUA_TRANSFER_SIZE_EXCEEDED: 'OCLAW_CUA_TRANSFER_SIZE_EXCEEDED',
  CUA_INPUT_CONFIG_MISSING: 'OCLAW_CUA_INPUT_CONFIG_MISSING',
  CUA_INPUT_DISABLED: 'OCLAW_CUA_INPUT_DISABLED',
  CUA_INPUT_TYPE_MISSING: 'OCLAW_CUA_INPUT_TYPE_MISSING',
  CUA_INPUT_TYPE_NOT_ALLOWED: 'OCLAW_CUA_INPUT_TYPE_NOT_ALLOWED',
  CUA_POSTCONDITION_PROBE_REQUIRED: 'OCLAW_CUA_POSTCONDITION_PROBE_REQUIRED',
  FILESYSTEM_WRITE_ROOT_DENY: 'OCLAW_FILESYSTEM_WRITE_ROOT_DENY',
  TOOL_DENIED: 'OCLAW_TOOL_DENIED',
  TOOL_NOT_ALLOWLISTED: 'OCLAW_TOOL_NOT_ALLOWLISTED',
} as const;

function denyDecision(reason_code: string, reason: string, guard?: string, severity: Severity = 'high'): Decision {
  return {
    status: 'deny',
    reason_code,
    reason,
    message: reason,
    ...(guard !== undefined && { guard }),
    ...(severity !== undefined && { severity }),
  };
}

function warnDecision(reason_code: string, reason: string, guard?: string, severity: Severity = 'medium'): Decision {
  return {
    status: 'warn',
    reason_code,
    reason,
    message: reason,
    ...(guard !== undefined && { guard }),
    ...(severity !== undefined && { severity }),
  };
}

function ensureReasonCode(decision: Decision): Decision {
  if (decision.status === 'allow') return decision;
  if (typeof decision.reason_code === 'string' && decision.reason_code.trim().length > 0) return decision;
  return {
    ...decision,
    reason_code: decision.status === 'warn' ? POLICY_REASON_CODES.POLICY_WARN : POLICY_REASON_CODES.GUARD_ERROR,
  };
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
      const ti = await this.threatIntelEngine.evaluate(event);
      const tiApplied = this.applyOnViolation(ti as Decision);
      const combined = combineDecisions(base, tiApplied);
      return this.applyMode(combined, this.config.mode);
    }

    return this.applyMode(base, this.config.mode);
  }

  private applyMode(result: Decision, mode: EvaluationMode): Decision {
    if (mode === 'audit') {
      return {
        status: 'allow',
        reason_code: result.reason_code,
        reason: result.reason,
        message: `[audit] Original decision: ${result.status} — ${result.message ?? result.reason ?? 'no reason'}`,
        guard: result.guard,
        severity: result.severity,
      };
    }

    if (mode === 'advisory' && result.status === 'deny') {
      return ensureReasonCode(
        warnDecision(
          result.reason_code,
          result.reason ?? result.message ?? 'policy deny converted to advisory warning',
          result.guard,
          result.severity ?? 'medium',
        ),
      );
    }

    return ensureReasonCode(result);
  }

  private getExpectedDataType(eventType: PolicyEvent['eventType']): string | undefined {
    switch (eventType) {
      case 'file_read':
      case 'file_write':
        return 'file';
      case 'command_exec':
        return 'command';
      case 'network_egress':
        return 'network';
      case 'tool_call':
        return 'tool';
      case 'patch_apply':
        return 'patch';
      case 'secret_access':
        return 'secret';
      case 'custom':
        return undefined;
      default:
        // CUA event types (starting with 'remote.' or 'input.')
        if (eventType.startsWith('remote.') || eventType.startsWith('input.')) {
          return 'cua';
        }
        return undefined;
    }
  }

  private evaluateDeterministic(event: PolicyEvent): Decision {
    const allowed: Decision = { status: 'allow' };

    // Validate eventType/data.type consistency to prevent guard bypass
    const expectedDataType = this.getExpectedDataType(event.eventType);
    if (expectedDataType && event.data.type !== expectedDataType) {
      return {
        status: 'deny',
        reason_code: 'event_type_mismatch',
        reason: `Event type "${event.eventType}" requires data.type "${expectedDataType}" but got "${event.data.type}"`,
        guard: 'policy_engine',
        severity: 'critical' as const,
      };
    }

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
      case 'remote.session.connect':
      case 'remote.session.disconnect':
      case 'remote.session.reconnect':
      case 'input.inject':
      case 'remote.clipboard':
      case 'remote.file_transfer':
      case 'remote.audio':
      case 'remote.drive_mapping':
      case 'remote.printing':
      case 'remote.session_share':
        return this.checkCua(event);
      default:
        return allowed;
    }
  }

  private checkCua(event: PolicyEvent): Decision {
    if (event.data.type !== 'cua') {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_MALFORMED_EVENT,
          `Malformed CUA event payload for ${event.eventType}: data.type must be 'cua'`,
          'computer_use',
          'high',
        ),
      );
    }
    const cuaData = event.data;

    const connectEgressDecision = this.checkCuaConnectEgress(event, cuaData);
    if (connectEgressDecision.status === 'deny' || connectEgressDecision.status === 'warn') {
      return connectEgressDecision;
    }

    const computerUse = this.policy.guards?.computer_use;
    if (!computerUse) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_COMPUTER_USE_CONFIG_MISSING,
          `CUA action '${event.eventType}' denied: missing guards.computer_use policy config`,
          'computer_use',
          'high',
        ),
      );
    }

    if (computerUse.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_COMPUTER_USE_DISABLED,
          `CUA action '${event.eventType}' denied: computer_use guard is disabled`,
          'computer_use',
          'high',
        ),
      );
    }

    const mode = computerUse.mode ?? 'guardrail';
    const allowedActions = normalizeStringList(computerUse.allowed_actions);
    const actionAllowed = allowedActions.length === 0 || allowedActions.includes(event.eventType);

    if (!actionAllowed) {
      const reason = `CUA action '${event.eventType}' is not listed in guards.computer_use.allowed_actions`;
      if (mode === 'observe' || mode === 'guardrail') {
        return warnDecision(
          POLICY_REASON_CODES.CUA_ACTION_NOT_ALLOWED,
          reason,
          'computer_use',
          'medium',
        );
      }
      if (mode !== 'fail_closed') {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_MODE_UNSUPPORTED,
            `CUA action '${event.eventType}' denied: unsupported computer_use mode '${mode}'`,
            'computer_use',
            'high',
          ),
        );
      }

      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_ACTION_NOT_ALLOWED,
          reason,
          'computer_use',
          'high',
        ),
      );
    }

    const sideChannelDecision = this.checkRemoteDesktopSideChannel(event, cuaData);
    if (sideChannelDecision.status === 'deny' || sideChannelDecision.status === 'warn') {
      return sideChannelDecision;
    }

    const inputDecision = this.checkInputInjectionCapability(event, cuaData);
    if (inputDecision.status === 'deny' || inputDecision.status === 'warn') {
      return inputDecision;
    }

    return { status: 'allow' };
  }

  private checkCuaConnectEgress(event: PolicyEvent, data: CuaEventData): Decision {
    if (event.eventType !== 'remote.session.connect') {
      return { status: 'allow' };
    }

    if (!this.config.guards.egress) {
      return { status: 'allow' };
    }

    const target = extractCuaNetworkTarget(data);
    if (!target) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_CONNECT_METADATA_MISSING,
          "CUA connect action denied: missing destination host/url metadata required for egress evaluation",
          'egress',
          'high',
        ),
      );
    }

    const egressEvent: PolicyEvent = {
      eventId: `${event.eventId}:cua-connect-egress`,
      eventType: 'network_egress',
      timestamp: event.timestamp,
      sessionId: event.sessionId,
      data: {
        type: 'network',
        host: target.host,
        port: target.port,
        ...(target.protocol ? { protocol: target.protocol } : {}),
        ...(target.url ? { url: target.url } : {}),
      },
      metadata: {
        ...(event.metadata ?? {}),
        derivedFrom: event.eventType,
      },
    };

    return this.checkEgress(egressEvent);
  }

  private checkRemoteDesktopSideChannel(event: PolicyEvent, data: CuaEventData): Decision {
    const sideChannelFlag = eventTypeToSideChannelFlag(event.eventType);
    if (!sideChannelFlag) {
      return { status: 'allow' };
    }

    const cfg = this.policy.guards?.remote_desktop_side_channel;
    if (!cfg) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_CONFIG_MISSING,
          `CUA side-channel action '${event.eventType}' denied: missing guards.remote_desktop_side_channel policy config`,
          'remote_desktop_side_channel',
          'high',
        ),
      );
    }

    if (cfg.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_DISABLED,
          `CUA side-channel action '${event.eventType}' denied: remote_desktop_side_channel guard is disabled`,
          'remote_desktop_side_channel',
          'high',
        ),
      );
    }

    if (cfg[sideChannelFlag] === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_POLICY_DENY,
          `CUA side-channel action '${event.eventType}' denied by policy`,
          'remote_desktop_side_channel',
          'high',
        ),
      );
    }

    if (event.eventType === 'remote.file_transfer') {
      const maxBytes = cfg.max_transfer_size_bytes;
      if (maxBytes !== undefined) {
        if (typeof maxBytes !== 'number' || !Number.isFinite(maxBytes) || maxBytes < 0) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_CONFIG_INVALID,
              `CUA file transfer denied: invalid max_transfer_size_bytes '${String(maxBytes)}'`,
              'remote_desktop_side_channel',
              'high',
            ),
          );
        }

        const transferSize = extractTransferSize(data);
        if (transferSize === null) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_MISSING,
              'CUA file transfer denied: missing required transfer_size metadata',
              'remote_desktop_side_channel',
              'high',
            ),
          );
        }

        if (transferSize > maxBytes) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_EXCEEDED,
              `CUA file transfer size ${transferSize} exceeds max_transfer_size_bytes ${maxBytes}`,
              'remote_desktop_side_channel',
              'high',
            ),
          );
        }
      }
    }

    return { status: 'allow' };
  }

  private checkInputInjectionCapability(event: PolicyEvent, data: CuaEventData): Decision {
    if (event.eventType !== 'input.inject') {
      return { status: 'allow' };
    }

    const cfg = this.policy.guards?.input_injection_capability;
    if (!cfg) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_INPUT_CONFIG_MISSING,
          `CUA input action '${event.eventType}' denied: missing guards.input_injection_capability policy config`,
          'input_injection_capability',
          'high',
        ),
      );
    }

    if (cfg.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_INPUT_DISABLED,
          `CUA input action '${event.eventType}' denied: input_injection_capability guard is disabled`,
          'input_injection_capability',
          'high',
        ),
      );
    }

    const allowedInputTypes = normalizeStringList(cfg.allowed_input_types);
    const inputType = extractInputType(data);
    if (allowedInputTypes.length > 0) {
      if (!inputType) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_INPUT_TYPE_MISSING,
            "CUA input action denied: missing required 'input_type'",
            'input_injection_capability',
            'high',
          ),
        );
      }

      if (!allowedInputTypes.includes(inputType)) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_INPUT_TYPE_NOT_ALLOWED,
            `CUA input action denied: input_type '${inputType}' is not allowed`,
            'input_injection_capability',
            'high',
          ),
        );
      }
    }

    if (cfg.require_postcondition_probe === true) {
      const probeHash = data.postconditionProbeHash;
      if (typeof probeHash !== 'string' || probeHash.trim().length === 0) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_POSTCONDITION_PROBE_REQUIRED,
            'CUA input action denied: postcondition probe hash is required',
            'input_injection_capability',
            'high',
          ),
        );
      }
    }

    return { status: 'allow' };
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
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.FILESYSTEM_WRITE_ROOT_DENY,
              'Write path not in allowed roots',
              'forbidden_path',
              'high',
            ),
          );
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
    // Defense in depth: shell/command execution can still touch the filesystem.
    // Best-effort extract path-like tokens (including redirections) and run them through the
    // filesystem policy checks (forbidden paths + allowed write roots).
    if (this.config.guards.forbidden_path && event.data.type === 'command') {
      const { reads, writes } = extractCommandPathCandidates(event.data.command, event.data.args);

      const maxChecks = 64;
      let checks = 0;

      // Check likely writes first so allowed_write_roots is enforced.
      for (const p of writes) {
        if (checks++ >= maxChecks) break;
        const synthetic: PolicyEvent = {
          eventId: `${event.eventId}:cmdwrite:${checks}`,
          eventType: 'file_write',
          timestamp: event.timestamp,
          sessionId: event.sessionId,
          data: { type: 'file', path: p, operation: 'write' },
          metadata: { ...event.metadata, derivedFrom: 'command_exec' },
        };
        const d = this.checkFilesystem(synthetic);
        if (d.status === 'deny' || d.status === 'warn') return d;
      }

      for (const p of reads) {
        if (checks++ >= maxChecks) break;
        const synthetic: PolicyEvent = {
          eventId: `${event.eventId}:cmdread:${checks}`,
          eventType: 'file_read',
          timestamp: event.timestamp,
          sessionId: event.sessionId,
          data: { type: 'file', path: p, operation: 'read' },
          metadata: { ...event.metadata, derivedFrom: 'command_exec' },
        };
        const d = this.checkFilesystem(synthetic);
        if (d.status === 'deny' || d.status === 'warn') return d;
      }
    }

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
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.TOOL_DENIED,
            `Tool '${event.data.toolName}' is denied by policy`,
            'mcp_tool',
            'high',
          ),
        );
      }

      const allowedTools = tools?.allowed?.map((x) => x.toLowerCase()) ?? [];
      if (allowedTools.length > 0 && !allowedTools.includes(toolName)) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.TOOL_NOT_ALLOWLISTED,
            `Tool '${event.data.toolName}' is not in allowed tool list`,
            'mcp_tool',
            'high',
          ),
        );
      }
    }

    // Also check forbidden paths in tool parameters (defense in depth).
    if (this.config.guards.forbidden_path && event.data.type === 'tool') {
      const params = event.data.parameters ?? {};
      const pathKeys = ['path', 'file', 'file_path', 'filepath', 'filename', 'target'];
      for (const key of pathKeys) {
        const val = params[key];
        if (typeof val === 'string' && val.length > 0) {
          const pathEvent: PolicyEvent = {
            ...event,
            eventType: 'file_write',
            data: { type: 'file', path: val, operation: 'write' },
          };
          const pathCheck = this.forbiddenPathGuard.checkSync(pathEvent, this.policy);
          const pathDecision = this.guardResultToDecision(pathCheck);
          if (pathDecision.status === 'deny' || pathDecision.status === 'warn') {
            return this.applyOnViolation(pathDecision);
          }
        }
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
      return warnDecision(
        decision.reason_code,
        decision.reason ?? decision.message ?? 'Policy violation downgraded to warning',
        decision.guard,
        decision.severity ?? 'medium',
      );
    }

    if (action && action !== 'cancel') {
      console.warn(`[clawdstrike] Unhandled on_violation action: "${action}" — treating as deny`);
    }

    return decision;
  }

  private guardResultToDecision(result: { status: 'allow' | 'deny' | 'warn'; reason?: string; severity?: Severity; guard: string }): Decision {
    if (result.status === 'allow') return { status: 'allow' };
    if (result.status === 'warn') {
      return warnDecision(
        POLICY_REASON_CODES.POLICY_WARN,
        result.reason ?? `${result.guard} returned warning`,
        result.guard,
        'medium',
      );
    }
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      result.reason ?? `${result.guard} denied request`,
      result.guard,
      result.severity ?? 'high',
    );
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

function combineDecisions(base: Decision, next: Decision): Decision {
  const rank: Record<string, number> = { deny: 2, warn: 1, allow: 0 };
  const baseRank = rank[base.status] ?? 0;
  const nextRank = rank[next.status] ?? 0;
  if (nextRank > baseRank) return next;
  if (nextRank === baseRank && nextRank > 0 && next.reason) {
    // On ties for non-allow decisions, merge the reasons
    return {
      ...base,
      message: base.message
        ? `${base.message}; ${next.message ?? next.reason}`
        : next.message ?? next.reason,
    };
  }
  return base;
}

function normalizeStringList(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const out: string[] = [];
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const normalized = value.trim();
    if (normalized.length > 0) out.push(normalized);
  }
  return out;
}

function extractInputType(data: CuaEventData): string | null {
  const candidates = [data.input_type, data.inputType];
  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      const normalized = candidate.trim().toLowerCase();
      if (normalized.length > 0) return normalized;
    }
  }
  return null;
}

function extractTransferSize(data: CuaEventData): number | null {
  const candidates = [
    data.transfer_size,
    data.transferSize,
    data.size_bytes,
    data.sizeBytes,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'number' && Number.isFinite(candidate) && candidate >= 0) {
      return candidate;
    }
    if (typeof candidate === 'string') {
      const parsed = Number.parseInt(candidate, 10);
      if (Number.isFinite(parsed) && parsed >= 0) {
        return parsed;
      }
    }
  }

  return null;
}

function parsePort(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^[0-9]+$/.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) return parsed;
    }
  }
  return null;
}

function firstNonEmptyString(values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

type CuaNetworkTarget = {
  host: string;
  port: number;
  protocol?: string;
  url?: string;
};

function extractCuaNetworkTarget(data: CuaEventData): CuaNetworkTarget | null {
  const url = firstNonEmptyString([
    data.url,
    data.endpoint,
    data.href,
    data.target_url,
    data.targetUrl,
  ]);
  const parsed = parseNetworkTarget(url ?? '', { emptyPort: 'default' });

  const host = firstNonEmptyString([
    data.host,
    data.hostname,
    data.remote_host,
    data.remoteHost,
    data.destination_host,
    data.destinationHost,
    parsed.host,
  ])?.toLowerCase();
  if (!host) {
    return null;
  }

  const protocol = firstNonEmptyString([data.protocol, data.scheme])?.toLowerCase();
  const explicitPort = parsePort(
    data.port
      ?? data.remote_port
      ?? data.remotePort
      ?? data.destination_port
      ?? data.destinationPort,
  );
  const port = explicitPort ?? (parsed.host ? parsed.port : protocol === 'http' ? 80 : 443);

  return {
    host,
    port,
    ...(protocol ? { protocol } : {}),
    ...(url ? { url } : {}),
  };
}

type SideChannelFlag =
  | 'clipboard_enabled'
  | 'file_transfer_enabled'
  | 'audio_enabled'
  | 'drive_mapping_enabled'
  | 'printing_enabled'
  | 'session_share_enabled';

function eventTypeToSideChannelFlag(eventType: PolicyEvent['eventType']): SideChannelFlag | null {
  switch (eventType) {
    case 'remote.clipboard':
      return 'clipboard_enabled';
    case 'remote.file_transfer':
      return 'file_transfer_enabled';
    case 'remote.audio':
      return 'audio_enabled';
    case 'remote.drive_mapping':
      return 'drive_mapping_enabled';
    case 'remote.printing':
      return 'printing_enabled';
    case 'remote.session_share':
      return 'session_share_enabled';
    default:
      return null;
  }
}
