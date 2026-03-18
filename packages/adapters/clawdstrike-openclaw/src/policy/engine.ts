import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

import type { PolicyEngineLike as CanonicalPolicyEngineLike } from "@clawdstrike/adapter-core";
import { parseNetworkTarget } from "@clawdstrike/adapter-core";
import { type Policy as CanonicalPolicy, createPolicyEngineFromPolicy } from "@clawdstrike/policy";

import { mergeConfig, resolveBuiltinPolicy, type ResolvedClawdstrikeConfig } from "../config.js";
import {
  EgressGuard,
  ForbiddenPathGuard,
  PatchIntegrityGuard,
  SecretLeakGuard,
} from "../guards/index.js";
import { sanitizeOutputText } from "../sanitizer/output-sanitizer.js";
import type {
  ClawdstrikeConfig,
  CuaEventData,
  Decision,
  EvaluationMode,
  Policy,
  PolicyEvent,
  Severity,
} from "../types.js";

import { loadPolicy } from "./loader.js";
import { validatePolicy } from "./validator.js";

function expandHome(p: string): string {
  return p.replace(/^~(?=\/|$)/, homedir());
}

function normalizePathForPrefix(p: string): string {
  return path.resolve(expandHome(p));
}

function cleanPathToken(t: string): string {
  return t
    .trim()
    .replace(/^[("'`]+/, "")
    .replace(/[)"'`;,\]}]+$/, "");
}

function isRedirectionOp(t: string): boolean {
  return (
    t === ">" ||
    t === ">>" ||
    t === "1>" ||
    t === "1>>" ||
    t === "2>" ||
    t === "2>>" ||
    t === "<" ||
    t === "<<"
  );
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
  if (t.includes("://")) return false;
  if (t.startsWith("/") || t.startsWith("~") || t.startsWith("./") || t.startsWith("../"))
    return true;
  if (t === ".env" || t.startsWith(".env.")) return true;
  if (
    t.includes("/.ssh/") ||
    t.includes("/.aws/") ||
    t.includes("/.gnupg/") ||
    t.includes("/.kube/")
  )
    return true;
  return false;
}

const WRITE_PATH_FLAG_NAMES = new Set([
  // Common output flags
  "o",
  "out",
  "output",
  "outfile",
  "output-file",
  // Common log file flags
  "log-file",
  "logfile",
  "log-path",
  "logpath",
]);

function isWritePathFlagToken(t: string): boolean {
  if (!t) return false;
  if (!t.startsWith("-")) return false;
  const normalized = t.replace(/^-+/, "").toLowerCase().replace(/_/g, "-");
  return WRITE_PATH_FLAG_NAMES.has(normalized);
}

function extractCommandPathCandidates(
  command: string,
  args: string[],
): { reads: string[]; writes: string[] } {
  const tokens = [command, ...args].map((t) => String(t ?? "")).filter(Boolean);
  const reads: string[] = [];
  const writes: string[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    // Redirection operators: treat as write/read targets.
    if (isRedirectionOp(t)) {
      const next = tokens[i + 1];
      if (typeof next === "string" && next.length > 0) {
        const cleaned = cleanPathToken(next);
        if (cleaned) {
          if (
            t.startsWith(">") ||
            t === ">" ||
            t === ">>" ||
            t === "1>" ||
            t === "1>>" ||
            t === "2>" ||
            t === "2>>"
          ) {
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
        if (t.includes(">")) writes.push(cleaned);
        else reads.push(cleaned);
      }
      continue;
    }

    // Flags like --output /path or -o /path (write targets)
    if (isWritePathFlagToken(t)) {
      const next = tokens[i + 1];
      if (typeof next === "string" && next.length > 0) {
        const cleaned = cleanPathToken(next);
        if (looksLikePathToken(cleaned)) {
          writes.push(cleaned);
          i += 1;
          continue;
        }
      }
    }

    // Flags like --output=/path
    const eq = t.indexOf("=");
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
  POLICY_DENY: "ADC_POLICY_DENY",
  POLICY_WARN: "ADC_POLICY_WARN",
  GUARD_ERROR: "ADC_GUARD_ERROR",
  CUA_MALFORMED_EVENT: "OCLAW_CUA_MALFORMED_EVENT",
  CUA_COMPUTER_USE_CONFIG_MISSING: "OCLAW_CUA_COMPUTER_USE_CONFIG_MISSING",
  CUA_COMPUTER_USE_DISABLED: "OCLAW_CUA_COMPUTER_USE_DISABLED",
  CUA_ACTION_NOT_ALLOWED: "OCLAW_CUA_ACTION_NOT_ALLOWED",
  CUA_MODE_UNSUPPORTED: "OCLAW_CUA_MODE_UNSUPPORTED",
  CUA_CONNECT_METADATA_MISSING: "OCLAW_CUA_CONNECT_METADATA_MISSING",
  CUA_SIDE_CHANNEL_CONFIG_MISSING: "OCLAW_CUA_SIDE_CHANNEL_CONFIG_MISSING",
  CUA_SIDE_CHANNEL_DISABLED: "OCLAW_CUA_SIDE_CHANNEL_DISABLED",
  CUA_SIDE_CHANNEL_POLICY_DENY: "OCLAW_CUA_SIDE_CHANNEL_POLICY_DENY",
  CUA_TRANSFER_SIZE_CONFIG_INVALID: "OCLAW_CUA_TRANSFER_SIZE_CONFIG_INVALID",
  CUA_TRANSFER_SIZE_MISSING: "OCLAW_CUA_TRANSFER_SIZE_MISSING",
  CUA_TRANSFER_SIZE_EXCEEDED: "OCLAW_CUA_TRANSFER_SIZE_EXCEEDED",
  CUA_INPUT_CONFIG_MISSING: "OCLAW_CUA_INPUT_CONFIG_MISSING",
  CUA_INPUT_DISABLED: "OCLAW_CUA_INPUT_DISABLED",
  CUA_INPUT_TYPE_MISSING: "OCLAW_CUA_INPUT_TYPE_MISSING",
  CUA_INPUT_TYPE_NOT_ALLOWED: "OCLAW_CUA_INPUT_TYPE_NOT_ALLOWED",
  CUA_POSTCONDITION_PROBE_REQUIRED: "OCLAW_CUA_POSTCONDITION_PROBE_REQUIRED",
  FILESYSTEM_WRITE_ROOT_DENY: "OCLAW_FILESYSTEM_WRITE_ROOT_DENY",
  TOOL_DENIED: "OCLAW_TOOL_DENIED",
  TOOL_NOT_ALLOWLISTED: "OCLAW_TOOL_NOT_ALLOWLISTED",
} as const;

function denyDecision(
  reason_code: string,
  reason: string,
  guard?: string,
  severity: Severity = "high",
): Decision {
  return {
    status: "deny",
    reason_code,
    reason,
    message: reason,
    ...(guard !== undefined && { guard }),
    ...(severity !== undefined && { severity }),
  };
}

function warnDecision(
  reason_code: string,
  reason: string,
  guard?: string,
  severity: Severity = "medium",
): Decision {
  return {
    status: "warn",
    reason_code,
    reason,
    message: reason,
    ...(guard !== undefined && { guard }),
    ...(severity !== undefined && { severity }),
  };
}

function ensureReasonCode(decision: Decision): Decision {
  if (decision.status === "allow") return decision;
  if (typeof decision.reason_code === "string" && decision.reason_code.trim().length > 0)
    return decision;
  return {
    ...decision,
    reason_code:
      decision.status === "warn"
        ? POLICY_REASON_CODES.POLICY_WARN
        : POLICY_REASON_CODES.GUARD_ERROR,
  };
}

export class PolicyEngine {
  private readonly config: ResolvedClawdstrikeConfig;
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
    this.threatIntelEngine = buildThreatIntelEngine(
      this.policy,
      this.config.guards,
      policyBaseDirFromRef(this.config.policy),
    );
  }

  enabledGuards(): string[] {
    const g = this.config.guards;
    const enabled: string[] = [];
    if (g.forbidden_path) enabled.push("forbidden_path");
    if (g.egress) enabled.push("egress");
    if (g.secret_leak) enabled.push("secret_leak");
    if (g.patch_integrity) enabled.push("patch_integrity");
    if (g.mcp_tool) enabled.push("mcp_tool");
    if (g.spider_sense) enabled.push("spider_sense");
    return enabled;
  }

  getPolicy(): Policy {
    return this.policy;
  }

  async lintPolicy(
    policyRef: string,
  ): Promise<{ valid: boolean; errors: string[]; warnings: string[] }> {
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

  evaluateSync(event: PolicyEvent): Decision {
    return this.applyMode(this.evaluateDeterministic(event), this.config.mode);
  }

  hasAsyncGuards(): boolean {
    return this.threatIntelEngine !== null;
  }

  async evaluateAsyncGuards(event: PolicyEvent): Promise<Decision> {
    if (!this.threatIntelEngine) {
      return { status: "allow" };
    }

    const threatIntelDecision = await this.threatIntelEngine.evaluate(event);
    const applied = this.applyOnViolation(threatIntelDecision as Decision);
    return this.applyMode(applied, this.config.mode);
  }

  async evaluate(event: PolicyEvent): Promise<Decision> {
    const base = this.evaluateDeterministic(event);

    // Fail fast on deterministic violations to avoid unnecessary external calls.
    if (base.status === "deny" || base.status === "warn") {
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
    if (mode === "audit") {
      return {
        status: "allow",
        reason_code: result.reason_code,
        reason: result.reason,
        message: `[audit] Original decision: ${result.status} — ${result.message ?? result.reason ?? "no reason"}`,
        guard: result.guard,
        severity: result.severity,
      };
    }

    if (mode === "advisory" && result.status === "deny") {
      return ensureReasonCode(
        warnDecision(
          result.reason_code,
          result.reason ?? result.message ?? "policy deny converted to advisory warning",
          result.guard,
          result.severity ?? "medium",
        ),
      );
    }

    return ensureReasonCode(result);
  }

  private getExpectedDataType(eventType: PolicyEvent["eventType"]): string | undefined {
    switch (eventType) {
      case "file_read":
      case "file_write":
        return "file";
      case "command_exec":
        return "command";
      case "network_egress":
        return "network";
      case "tool_call":
        return "tool";
      case "patch_apply":
        return "patch";
      case "secret_access":
        return "secret";
      case "custom":
        return undefined;
      default:
        // CUA event types (starting with 'remote.' or 'input.')
        if (eventType.startsWith("remote.") || eventType.startsWith("input.")) {
          return "cua";
        }
        return undefined;
    }
  }

  private evaluateDeterministic(event: PolicyEvent): Decision {
    const allowed: Decision = { status: "allow" };

    // Validate eventType/data.type consistency to prevent guard bypass
    const expectedDataType = this.getExpectedDataType(event.eventType);
    if (expectedDataType && event.data.type !== expectedDataType) {
      return {
        status: "deny",
        reason_code: "event_type_mismatch",
        reason: `Event type "${event.eventType}" requires data.type "${expectedDataType}" but got "${event.data.type}"`,
        guard: "policy_engine",
        severity: "critical" as const,
      };
    }

    switch (event.eventType) {
      case "file_read":
      case "file_write":
        return this.checkFilesystem(event);
      case "network_egress":
        return this.checkEgress(event);
      case "command_exec":
        return this.checkExecution(event);
      case "tool_call":
        return this.checkToolCall(event);
      case "patch_apply":
        return this.checkPatch(event);
      case "remote.session.connect":
      case "remote.session.disconnect":
      case "remote.session.reconnect":
      case "input.inject":
      case "remote.clipboard":
      case "remote.file_transfer":
      case "remote.audio":
      case "remote.drive_mapping":
      case "remote.printing":
      case "remote.session_share":
        return this.checkCua(event);
      default:
        return allowed;
    }
  }

  private checkCua(event: PolicyEvent): Decision {
    if (event.data.type !== "cua") {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_MALFORMED_EVENT,
          `Malformed CUA event payload for ${event.eventType}: data.type must be 'cua'`,
          "computer_use",
          "high",
        ),
      );
    }
    const cuaData = event.data;

    const connectEgressDecision = this.checkCuaConnectEgress(event, cuaData);
    if (connectEgressDecision.status === "deny" || connectEgressDecision.status === "warn") {
      return connectEgressDecision;
    }

    const computerUse = this.policy.guards?.computer_use;
    if (!computerUse) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_COMPUTER_USE_CONFIG_MISSING,
          `CUA action '${event.eventType}' denied: missing guards.computer_use policy config`,
          "computer_use",
          "high",
        ),
      );
    }

    if (computerUse.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_COMPUTER_USE_DISABLED,
          `CUA action '${event.eventType}' denied: computer_use guard is disabled`,
          "computer_use",
          "high",
        ),
      );
    }

    const mode = computerUse.mode ?? "guardrail";
    const allowedActions = normalizeStringList(computerUse.allowed_actions);
    const actionAllowed = allowedActions.length === 0 || allowedActions.includes(event.eventType);

    if (!actionAllowed) {
      const reason = `CUA action '${event.eventType}' is not listed in guards.computer_use.allowed_actions`;
      if (mode === "observe" || mode === "guardrail") {
        return warnDecision(
          POLICY_REASON_CODES.CUA_ACTION_NOT_ALLOWED,
          reason,
          "computer_use",
          "medium",
        );
      }
      if (mode !== "fail_closed") {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_MODE_UNSUPPORTED,
            `CUA action '${event.eventType}' denied: unsupported computer_use mode '${mode}'`,
            "computer_use",
            "high",
          ),
        );
      }

      return this.applyOnViolation(
        denyDecision(POLICY_REASON_CODES.CUA_ACTION_NOT_ALLOWED, reason, "computer_use", "high"),
      );
    }

    const sideChannelDecision = this.checkRemoteDesktopSideChannel(event, cuaData);
    if (sideChannelDecision.status === "deny" || sideChannelDecision.status === "warn") {
      return sideChannelDecision;
    }

    const inputDecision = this.checkInputInjectionCapability(event, cuaData);
    if (inputDecision.status === "deny" || inputDecision.status === "warn") {
      return inputDecision;
    }

    return { status: "allow" };
  }

  private checkCuaConnectEgress(event: PolicyEvent, data: CuaEventData): Decision {
    if (event.eventType !== "remote.session.connect") {
      return { status: "allow" };
    }

    if (!this.config.guards.egress) {
      return { status: "allow" };
    }

    const target = extractCuaNetworkTarget(data);
    if (!target) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_CONNECT_METADATA_MISSING,
          "CUA connect action denied: missing destination host/url metadata required for egress evaluation",
          "egress",
          "high",
        ),
      );
    }

    const egressEvent: PolicyEvent = {
      eventId: `${event.eventId}:cua-connect-egress`,
      eventType: "network_egress",
      timestamp: event.timestamp,
      sessionId: event.sessionId,
      data: {
        type: "network",
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
      return { status: "allow" };
    }

    const cfg = this.policy.guards?.remote_desktop_side_channel;
    if (!cfg) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_CONFIG_MISSING,
          `CUA side-channel action '${event.eventType}' denied: missing guards.remote_desktop_side_channel policy config`,
          "remote_desktop_side_channel",
          "high",
        ),
      );
    }

    if (cfg.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_DISABLED,
          `CUA side-channel action '${event.eventType}' denied: remote_desktop_side_channel guard is disabled`,
          "remote_desktop_side_channel",
          "high",
        ),
      );
    }

    if (cfg[sideChannelFlag] === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_SIDE_CHANNEL_POLICY_DENY,
          `CUA side-channel action '${event.eventType}' denied by policy`,
          "remote_desktop_side_channel",
          "high",
        ),
      );
    }

    if (event.eventType === "remote.file_transfer") {
      const maxBytes = cfg.max_transfer_size_bytes;
      if (maxBytes !== undefined) {
        if (typeof maxBytes !== "number" || !Number.isFinite(maxBytes) || maxBytes < 0) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_CONFIG_INVALID,
              `CUA file transfer denied: invalid max_transfer_size_bytes '${String(maxBytes)}'`,
              "remote_desktop_side_channel",
              "high",
            ),
          );
        }

        const transferSize = extractTransferSize(data);
        if (transferSize === null) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_MISSING,
              "CUA file transfer denied: missing required transfer_size metadata",
              "remote_desktop_side_channel",
              "high",
            ),
          );
        }

        if (transferSize > maxBytes) {
          return this.applyOnViolation(
            denyDecision(
              POLICY_REASON_CODES.CUA_TRANSFER_SIZE_EXCEEDED,
              `CUA file transfer size ${transferSize} exceeds max_transfer_size_bytes ${maxBytes}`,
              "remote_desktop_side_channel",
              "high",
            ),
          );
        }
      }
    }

    return { status: "allow" };
  }

  private checkInputInjectionCapability(event: PolicyEvent, data: CuaEventData): Decision {
    if (event.eventType !== "input.inject") {
      return { status: "allow" };
    }

    const cfg = this.policy.guards?.input_injection_capability;
    if (!cfg) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_INPUT_CONFIG_MISSING,
          `CUA input action '${event.eventType}' denied: missing guards.input_injection_capability policy config`,
          "input_injection_capability",
          "high",
        ),
      );
    }

    if (cfg.enabled === false) {
      return this.applyOnViolation(
        denyDecision(
          POLICY_REASON_CODES.CUA_INPUT_DISABLED,
          `CUA input action '${event.eventType}' denied: input_injection_capability guard is disabled`,
          "input_injection_capability",
          "high",
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
            "input_injection_capability",
            "high",
          ),
        );
      }

      if (!allowedInputTypes.includes(inputType)) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_INPUT_TYPE_NOT_ALLOWED,
            `CUA input action denied: input_type '${inputType}' is not allowed`,
            "input_injection_capability",
            "high",
          ),
        );
      }
    }

    if (cfg.require_postcondition_probe === true) {
      const probeHash = data.postconditionProbeHash;
      if (typeof probeHash !== "string" || probeHash.trim().length === 0) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.CUA_POSTCONDITION_PROBE_REQUIRED,
            "CUA input action denied: postcondition probe hash is required",
            "input_injection_capability",
            "high",
          ),
        );
      }
    }

    return { status: "allow" };
  }

  private checkFilesystem(event: PolicyEvent): Decision {
    if (!this.config.guards.forbidden_path) {
      return { status: "allow" };
    }

    // First, enforce forbidden path patterns.
    const forbidden = this.forbiddenPathGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(forbidden);
    if (mapped.status === "deny" || mapped.status === "warn") {
      return this.applyOnViolation(mapped);
    }

    // Then, enforce write roots if configured.
    if (event.eventType === "file_write" && event.data.type === "file") {
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
              "Write path not in allowed roots",
              "forbidden_path",
              "high",
            ),
          );
        }
      }
    }

    return { status: "allow" };
  }

  private checkEgress(event: PolicyEvent): Decision {
    if (!this.config.guards.egress) {
      return { status: "allow" };
    }

    const res = this.egressGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkExecution(event: PolicyEvent): Decision {
    // Defense in depth: shell/command execution can still touch the filesystem.
    // Best-effort extract path-like tokens (including redirections) and run them through the
    // filesystem policy checks (forbidden paths + allowed write roots).
    if (this.config.guards.forbidden_path && event.data.type === "command") {
      const { reads, writes } = extractCommandPathCandidates(event.data.command, event.data.args);

      const maxChecks = 64;
      let checks = 0;

      // Check likely writes first so allowed_write_roots is enforced.
      for (const p of writes) {
        if (checks++ >= maxChecks) break;
        const synthetic: PolicyEvent = {
          eventId: `${event.eventId}:cmdwrite:${checks}`,
          eventType: "file_write",
          timestamp: event.timestamp,
          sessionId: event.sessionId,
          data: { type: "file", path: p, operation: "write" },
          metadata: { ...event.metadata, derivedFrom: "command_exec" },
        };
        const d = this.checkFilesystem(synthetic);
        if (d.status === "deny" || d.status === "warn") return d;
      }

      for (const p of reads) {
        if (checks++ >= maxChecks) break;
        const synthetic: PolicyEvent = {
          eventId: `${event.eventId}:cmdread:${checks}`,
          eventType: "file_read",
          timestamp: event.timestamp,
          sessionId: event.sessionId,
          data: { type: "file", path: p, operation: "read" },
          metadata: { ...event.metadata, derivedFrom: "command_exec" },
        };
        const d = this.checkFilesystem(synthetic);
        if (d.status === "deny" || d.status === "warn") return d;
      }
    }

    if (!this.config.guards.patch_integrity) {
      return { status: "allow" };
    }

    const res = this.patchIntegrityGuard.checkSync(event, this.policy);
    const mapped = this.guardResultToDecision(res);
    return this.applyOnViolation(mapped);
  }

  private checkToolCall(event: PolicyEvent): Decision {
    // Optional tool allow/deny list.
    if (event.data.type === "tool") {
      const tools = this.policy.tools;
      const toolName = event.data.toolName.toLowerCase();

      const deniedTools = tools?.denied?.map((x) => x.toLowerCase()) ?? [];
      if (deniedTools.includes(toolName)) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.TOOL_DENIED,
            `Tool '${event.data.toolName}' is denied by policy`,
            "mcp_tool",
            "high",
          ),
        );
      }

      const allowedTools = tools?.allowed?.map((x) => x.toLowerCase()) ?? [];
      if (allowedTools.length > 0 && !allowedTools.includes(toolName)) {
        return this.applyOnViolation(
          denyDecision(
            POLICY_REASON_CODES.TOOL_NOT_ALLOWLISTED,
            `Tool '${event.data.toolName}' is not in allowed tool list`,
            "mcp_tool",
            "high",
          ),
        );
      }
    }

    // Also check forbidden paths in tool parameters (defense in depth).
    if (this.config.guards.forbidden_path && event.data.type === "tool") {
      const params = event.data.parameters ?? {};
      const pathKeys = ["path", "file", "file_path", "filepath", "filename", "target"];
      for (const key of pathKeys) {
        const val = params[key];
        if (typeof val === "string" && val.length > 0) {
          const pathEvent: PolicyEvent = {
            ...event,
            eventType: "file_write",
            data: { type: "file", path: val, operation: "write" },
          };
          const pathCheck = this.forbiddenPathGuard.checkSync(pathEvent, this.policy);
          const pathDecision = this.guardResultToDecision(pathCheck);
          if (pathDecision.status === "deny" || pathDecision.status === "warn") {
            return this.applyOnViolation(pathDecision);
          }
        }
      }
    }

    if (!this.config.guards.secret_leak) {
      return { status: "allow" };
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
      if (applied1.status === "deny" || applied1.status === "warn") return applied1;
    }

    if (this.config.guards.secret_leak) {
      const r2 = this.secretLeakGuard.checkSync(event, this.policy);
      const mapped2 = this.guardResultToDecision(r2);
      const applied2 = this.applyOnViolation(mapped2);
      if (applied2.status === "deny" || applied2.status === "warn") return applied2;
    }

    return { status: "allow" };
  }

  private applyOnViolation(decision: Decision): Decision {
    const action = this.policy.on_violation;
    if (decision.status !== "deny") return decision;

    if (action === "warn") {
      return warnDecision(
        decision.reason_code,
        decision.reason ?? decision.message ?? "Policy violation downgraded to warning",
        decision.guard,
        decision.severity ?? "medium",
      );
    }

    if (action && action !== "cancel") {
      console.warn(`[clawdstrike] Unhandled on_violation action: "${action}" — treating as deny`);
    }

    return decision;
  }

  private guardResultToDecision(result: {
    status: "allow" | "deny" | "warn";
    reason?: string;
    severity?: Severity;
    guard: string;
  }): Decision {
    if (result.status === "allow") return { status: "allow" };
    if (result.status === "warn") {
      return warnDecision(
        POLICY_REASON_CODES.POLICY_WARN,
        result.reason ?? `${result.guard} returned warning`,
        result.guard,
        "medium",
      );
    }
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      result.reason ?? `${result.guard} denied request`,
      result.guard,
      result.severity ?? "high",
    );
  }
}

function policyBaseDirFromRef(policyRef: string): string | undefined {
  const trimmed = policyRef.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.startsWith("clawdstrike:")) return undefined;
  if (resolveBuiltinPolicy(`clawdstrike:${trimmed}`)) return undefined;
  return path.dirname(path.resolve(trimmed));
}

function isSpiderSenseCustomGuard(entry: unknown): boolean {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    return false;
  }
  const pkg = (entry as Record<string, unknown>).package;
  return typeof pkg === "string" && pkg.trim().toLowerCase() === "clawdstrike-spider-sense";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPolicySpiderSenseDisabled(policy: Policy): boolean {
  const raw = (policy.guards as Record<string, unknown> | undefined)?.spider_sense;
  if (raw === false) {
    return true;
  }
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
    return (raw as Record<string, unknown>).enabled === false;
  }
  return false;
}

type SpiderSensePattern = {
  id: string;
  category: string;
  stage: string;
  label: string;
  embedding: number[];
};

type SpiderSenseRuntimeConfig = {
  enabled: boolean;
  similarityThreshold: number;
  ambiguityBand: number;
  topK: number;
  patterns: SpiderSensePattern[];
  embeddingApiUrl?: string;
  embeddingApiKey?: string;
  embeddingModel?: string;
};

const SPIDER_SENSE_DEFAULT_THRESHOLD = 0.85;
const SPIDER_SENSE_DEFAULT_AMBIGUITY_BAND = 0.1;
const SPIDER_SENSE_DEFAULT_TOP_K = 5;
const SPIDER_SENSE_BUILTIN_S2BENCH: SpiderSensePattern[] = [
  {
    id: "s2b-perception-prompt_injection",
    category: "prompt_injection",
    stage: "perception",
    label: "Prompt injection via system override",
    embedding: [0.95, 0.05, 0.0],
  },
  {
    id: "s2b-perception-jailbreak",
    category: "jailbreak",
    stage: "perception",
    label: "Jailbreak attempt via role-play",
    embedding: [0.9, 0.1, 0.05],
  },
  {
    id: "s2b-perception-social_engineering",
    category: "social_engineering",
    stage: "perception",
    label: "Social engineering lure",
    embedding: [0.8, 0.2, 0.1],
  },
  {
    id: "s2b-perception-data_poisoning",
    category: "data_poisoning",
    stage: "perception",
    label: "Training data poisoning probe",
    embedding: [0.7, 0.25, 0.15],
  },
  {
    id: "s2b-perception-evasion",
    category: "evasion",
    stage: "perception",
    label: "Evasion via encoding obfuscation",
    embedding: [0.85, 0.1, 0.1],
  },
  {
    id: "s2b-perception-reconnaissance",
    category: "reconnaissance",
    stage: "perception",
    label: "Capability reconnaissance probe",
    embedding: [0.75, 0.15, 0.2],
  },
  {
    id: "s2b-perception-supply_chain",
    category: "supply_chain",
    stage: "perception",
    label: "Malicious dependency injection",
    embedding: [0.65, 0.3, 0.1],
  },
  {
    id: "s2b-perception-data_exfiltration",
    category: "data_exfiltration",
    stage: "perception",
    label: "Data exfiltration via prompt leak",
    embedding: [0.6, 0.35, 0.05],
  },
  {
    id: "s2b-perception-privilege_escalation",
    category: "privilege_escalation",
    stage: "perception",
    label: "Privilege escalation via context manipulation",
    embedding: [0.55, 0.4, 0.05],
  },
  {
    id: "s2b-cognition-prompt_injection",
    category: "prompt_injection",
    stage: "cognition",
    label: "Instruction hijack in reasoning",
    embedding: [0.05, 0.95, 0.0],
  },
  {
    id: "s2b-cognition-jailbreak",
    category: "jailbreak",
    stage: "cognition",
    label: "Logic bypass via hypothetical framing",
    embedding: [0.1, 0.9, 0.05],
  },
  {
    id: "s2b-cognition-social_engineering",
    category: "social_engineering",
    stage: "cognition",
    label: "Authority impersonation in reasoning",
    embedding: [0.2, 0.8, 0.1],
  },
  {
    id: "s2b-cognition-data_poisoning",
    category: "data_poisoning",
    stage: "cognition",
    label: "Bias injection in chain-of-thought",
    embedding: [0.25, 0.7, 0.15],
  },
  {
    id: "s2b-cognition-evasion",
    category: "evasion",
    stage: "cognition",
    label: "Semantic evasion in reasoning",
    embedding: [0.1, 0.85, 0.1],
  },
  {
    id: "s2b-cognition-reconnaissance",
    category: "reconnaissance",
    stage: "cognition",
    label: "Internal state probing",
    embedding: [0.15, 0.75, 0.2],
  },
  {
    id: "s2b-cognition-supply_chain",
    category: "supply_chain",
    stage: "cognition",
    label: "Tool trust manipulation",
    embedding: [0.3, 0.65, 0.1],
  },
  {
    id: "s2b-cognition-data_exfiltration",
    category: "data_exfiltration",
    stage: "cognition",
    label: "Memory extraction via reasoning",
    embedding: [0.35, 0.6, 0.05],
  },
  {
    id: "s2b-cognition-privilege_escalation",
    category: "privilege_escalation",
    stage: "cognition",
    label: "Role escalation in reasoning",
    embedding: [0.4, 0.55, 0.05],
  },
  {
    id: "s2b-action-prompt_injection",
    category: "prompt_injection",
    stage: "action",
    label: "Action hijack via injected tool call",
    embedding: [0.0, 0.05, 0.95],
  },
  {
    id: "s2b-action-jailbreak",
    category: "jailbreak",
    stage: "action",
    label: "Unauthorized action execution",
    embedding: [0.05, 0.1, 0.9],
  },
  {
    id: "s2b-action-social_engineering",
    category: "social_engineering",
    stage: "action",
    label: "Deceptive output generation",
    embedding: [0.1, 0.2, 0.8],
  },
  {
    id: "s2b-action-data_poisoning",
    category: "data_poisoning",
    stage: "action",
    label: "Malicious file write",
    embedding: [0.15, 0.25, 0.7],
  },
  {
    id: "s2b-action-evasion",
    category: "evasion",
    stage: "action",
    label: "Detection bypass in tool use",
    embedding: [0.1, 0.1, 0.85],
  },
  {
    id: "s2b-action-reconnaissance",
    category: "reconnaissance",
    stage: "action",
    label: "Environment probing via tools",
    embedding: [0.2, 0.15, 0.75],
  },
  {
    id: "s2b-action-supply_chain",
    category: "supply_chain",
    stage: "action",
    label: "Dependency download from untrusted source",
    embedding: [0.1, 0.3, 0.65],
  },
  {
    id: "s2b-action-data_exfiltration",
    category: "data_exfiltration",
    stage: "action",
    label: "Data exfiltration via network egress",
    embedding: [0.05, 0.35, 0.6],
  },
  {
    id: "s2b-action-privilege_escalation",
    category: "privilege_escalation",
    stage: "action",
    label: "Shell escape for privilege escalation",
    embedding: [0.05, 0.4, 0.55],
  },
  {
    id: "s2b-feedback-prompt_injection",
    category: "prompt_injection",
    stage: "feedback",
    label: "Feedback loop injection",
    embedding: [0.5, 0.05, 0.45],
  },
  {
    id: "s2b-feedback-jailbreak",
    category: "jailbreak",
    stage: "feedback",
    label: "Self-reinforcing jailbreak via feedback",
    embedding: [0.45, 0.1, 0.5],
  },
  {
    id: "s2b-feedback-social_engineering",
    category: "social_engineering",
    stage: "feedback",
    label: "Trust amplification via repeated feedback",
    embedding: [0.4, 0.2, 0.45],
  },
  {
    id: "s2b-feedback-data_poisoning",
    category: "data_poisoning",
    stage: "feedback",
    label: "Feedback-driven model drift",
    embedding: [0.35, 0.25, 0.4],
  },
  {
    id: "s2b-feedback-evasion",
    category: "evasion",
    stage: "feedback",
    label: "Adaptive evasion from feedback",
    embedding: [0.42, 0.12, 0.48],
  },
  {
    id: "s2b-feedback-reconnaissance",
    category: "reconnaissance",
    stage: "feedback",
    label: "Response analysis for reconnaissance",
    embedding: [0.4, 0.15, 0.5],
  },
  {
    id: "s2b-feedback-supply_chain",
    category: "supply_chain",
    stage: "feedback",
    label: "Supply chain persistence via feedback",
    embedding: [0.35, 0.3, 0.4],
  },
  {
    id: "s2b-feedback-data_exfiltration",
    category: "data_exfiltration",
    stage: "feedback",
    label: "Gradual data leak via feedback",
    embedding: [0.3, 0.35, 0.4],
  },
  {
    id: "s2b-feedback-privilege_escalation",
    category: "privilege_escalation",
    stage: "feedback",
    label: "Incremental privilege gain via feedback",
    embedding: [0.25, 0.4, 0.4],
  },
];

function parseSpiderSensePatterns(
  config: Record<string, unknown>,
  policyBaseDir?: string,
): SpiderSensePattern[] {
  const normalizeHex = (value: string): string => {
    const trimmed = value.trim().toLowerCase();
    return trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  };
  const hasNonEmptyString = (value: unknown): boolean =>
    typeof value === "string" && value.trim().length > 0;
  const hasNonEmptyArray = (value: unknown): boolean => Array.isArray(value) && value.length > 0;

  const parsePattern = (entry: unknown): SpiderSensePattern | null => {
    if (!isRecord(entry) || !Array.isArray(entry.embedding) || entry.embedding.length === 0) {
      return null;
    }
    const embedding: number[] = [];
    for (const value of entry.embedding) {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        return null;
      }
      embedding.push(value);
    }
    return {
      id: typeof entry.id === "string" ? entry.id : "",
      category: typeof entry.category === "string" ? entry.category : "",
      stage: typeof entry.stage === "string" ? entry.stage : "",
      label: typeof entry.label === "string" ? entry.label : "",
      embedding,
    };
  };
  const assertConsistentEmbeddingDimensions = (
    patterns: SpiderSensePattern[],
    source: string,
  ): void => {
    if (patterns.length === 0) return;
    const expectedDim = patterns[0]!.embedding.length;
    for (let i = 0; i < patterns.length; i++) {
      const dim = patterns[i]!.embedding.length;
      if (dim !== expectedDim) {
        throw new Error(
          `${source} contains embedding dimension mismatch at index ${i}: expected ${expectedDim}, got ${dim}`,
        );
      }
    }
  };

  const rawPatterns = config.patterns;
  if (Array.isArray(rawPatterns)) {
    if (rawPatterns.length > 0) {
      const parsed = rawPatterns.map((entry, index) => {
        const pattern = parsePattern(entry);
        if (!pattern) {
          throw new Error(`spider_sense inline patterns contain invalid entry at index ${index}`);
        }
        return pattern;
      });
      assertConsistentEmbeddingDimensions(parsed, "spider_sense inline patterns");
      return parsed;
    }
  }

  const rawPatternDbPath =
    typeof config.pattern_db_path === "string" ? config.pattern_db_path.trim() : "";
  if (rawPatternDbPath === "builtin:s2bench-v1") {
    assertConsistentEmbeddingDimensions(SPIDER_SENSE_BUILTIN_S2BENCH, "builtin:s2bench-v1");
    return SPIDER_SENSE_BUILTIN_S2BENCH;
  }
  const patternDbPath =
    rawPatternDbPath.length > 0 && !path.isAbsolute(rawPatternDbPath)
      ? path.resolve(policyBaseDir ?? process.cwd(), rawPatternDbPath)
      : rawPatternDbPath;
  if (patternDbPath.length > 0) {
    const raw = readFileSync(patternDbPath, "utf8");
    const expectedChecksum = hasNonEmptyString(config.pattern_db_checksum)
      ? normalizeHex(String(config.pattern_db_checksum))
      : "";
    if (expectedChecksum.length > 0) {
      const actualChecksum = createHash("sha256").update(raw).digest("hex").toLowerCase();
      if (actualChecksum !== expectedChecksum) {
        throw new Error(
          `spider_sense pattern DB checksum mismatch for '${patternDbPath}': expected ${expectedChecksum}, got ${actualChecksum}`,
        );
      }
    }

    const hasSignatureMetadata =
      hasNonEmptyString(config.pattern_db_signature) ||
      hasNonEmptyString(config.pattern_db_signature_key_id) ||
      hasNonEmptyString(config.pattern_db_public_key) ||
      hasNonEmptyString(config.pattern_db_trust_store_path) ||
      hasNonEmptyArray(config.pattern_db_trusted_keys);
    const hasManifestMetadata =
      hasNonEmptyString(config.pattern_db_manifest_path) ||
      hasNonEmptyString(config.pattern_db_manifest_trust_store_path) ||
      hasNonEmptyArray(config.pattern_db_manifest_trusted_keys);
    if (hasSignatureMetadata || hasManifestMetadata) {
      throw new Error(
        "spider_sense signature/manifest integrity metadata is not executable in OpenClaw runtime",
      );
    }

    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error(`spider_sense pattern DB at '${patternDbPath}' is empty or invalid`);
    }
    const patterns = parsed.map((entry, index) => {
      const pattern = parsePattern(entry);
      if (!pattern) {
        throw new Error(
          `spider_sense pattern DB at '${patternDbPath}' contains invalid entry at index ${index}`,
        );
      }
      return pattern;
    });
    assertConsistentEmbeddingDimensions(
      patterns,
      `spider_sense pattern DB at '${patternDbPath}'`,
    );
    return patterns;
  }
  return [];
}

function buildSpiderSenseRuntimeConfig(
  spec: unknown,
  options: { policyBaseDir?: string } = {},
): SpiderSenseRuntimeConfig {
  const record = isRecord(spec) ? spec : {};
  const config = isRecord(record.config) ? record.config : {};
  const similarityThreshold =
    typeof config.similarity_threshold === "number"
      ? config.similarity_threshold
      : SPIDER_SENSE_DEFAULT_THRESHOLD;
  const ambiguityBand =
    typeof config.ambiguity_band === "number"
      ? config.ambiguity_band
      : SPIDER_SENSE_DEFAULT_AMBIGUITY_BAND;
  const topK =
    typeof config.top_k === "number"
      ? Math.max(1, Math.trunc(config.top_k))
      : SPIDER_SENSE_DEFAULT_TOP_K;
  if (!Number.isFinite(similarityThreshold) || similarityThreshold < 0 || similarityThreshold > 1) {
    throw new Error(
      `spider_sense similarity_threshold must be in [0, 1], got ${String(similarityThreshold)}`,
    );
  }
  if (!Number.isFinite(ambiguityBand) || ambiguityBand < 0 || ambiguityBand > 1) {
    throw new Error(`spider_sense ambiguity_band must be in [0, 1], got ${String(ambiguityBand)}`);
  }
  const upperBound = similarityThreshold + ambiguityBand;
  const lowerBound = similarityThreshold - ambiguityBand;
  if (upperBound > 1 || lowerBound < 0) {
    throw new Error(
      `spider_sense threshold/band produce invalid decision range: lower=${lowerBound.toFixed(3)}, upper=${upperBound.toFixed(3)}`,
    );
  }

  const patterns = parseSpiderSensePatterns(config, options.policyBaseDir);
  if (patterns.length === 0) {
    throw new Error("spider_sense requires non-empty patterns or pattern_db_path");
  }

  const embeddingApiUrl =
    typeof config.embedding_api_url === "string" ? config.embedding_api_url : undefined;
  const embeddingApiKey =
    typeof config.embedding_api_key === "string" ? config.embedding_api_key : undefined;
  const embeddingModel =
    typeof config.embedding_model === "string" ? config.embedding_model : undefined;

  return {
    enabled: record.enabled !== false,
    similarityThreshold,
    ambiguityBand,
    topK,
    patterns,
    embeddingApiUrl,
    embeddingApiKey,
    embeddingModel,
  };
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length === 0 || a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    const av = a[i]!;
    const bv = b[i]!;
    dot += av * bv;
    normA += av * av;
    normB += bv * bv;
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

function extractEmbeddingFromEvent(event: PolicyEvent): number[] | null {
  const data: Record<string, unknown> = isRecord(event.data) ? event.data : {};
  const customData = isRecord(data.customData) ? data.customData : null;
  const maybeEmbedding: unknown[] | undefined =
    (Array.isArray(data.embedding) ? data.embedding : undefined) ??
    (customData && Array.isArray(customData.embedding)
      ? (customData.embedding as unknown[])
      : undefined);
  if (!maybeEmbedding) return null;
  const embedding = maybeEmbedding.filter(
    (value: unknown): value is number => typeof value === "number" && Number.isFinite(value),
  );
  return embedding.length > 0 ? embedding : null;
}

function eventToSpiderSenseText(event: PolicyEvent): string {
  return `[event:${event.eventType}] ${JSON.stringify(event.data ?? null)}`;
}

async function fetchSpiderSenseEmbedding(
  runtime: SpiderSenseRuntimeConfig,
  event: PolicyEvent,
): Promise<number[] | null> {
  if (!runtime.embeddingApiUrl || !runtime.embeddingApiKey || !runtime.embeddingModel) {
    return null;
  }
  const response = await fetch(runtime.embeddingApiUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${runtime.embeddingApiKey}`,
    },
    body: JSON.stringify({
      model: runtime.embeddingModel,
      input: eventToSpiderSenseText(event),
    }),
  });
  if (!response.ok) {
    throw new Error(`spider_sense embedding request failed (${response.status})`);
  }
  const json = (await response.json()) as Record<string, unknown>;
  const data = Array.isArray(json.data) ? json.data : [];
  const first = isRecord(data[0]) ? data[0] : {};
  const embedding = Array.isArray(first.embedding) ? first.embedding : [];
  const out = embedding.filter(
    (value): value is number => typeof value === "number" && Number.isFinite(value),
  );
  return out.length > 0 ? out : null;
}

function evaluateSpiderSenseEmbedding(
  runtime: SpiderSenseRuntimeConfig,
  embedding: number[],
): Decision {
  const expectedDim = runtime.patterns[0]?.embedding.length ?? 0;
  if (expectedDim === 0) {
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      "Spider-Sense pattern DB is empty (fail-closed)",
      "clawdstrike-spider-sense",
      "high",
    );
  }
  if (embedding.length !== expectedDim) {
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      `Spider-Sense embedding dimension mismatch (${embedding.length} vs ${expectedDim})`,
      "clawdstrike-spider-sense",
      "high",
    );
  }

  const topMatches = runtime.patterns
    .map((entry) => ({ entry, score: cosineSimilarity(embedding, entry.embedding) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, runtime.topK);
  const top = topMatches[0];
  const topScore = top?.score ?? 0;
  const upper = runtime.similarityThreshold + runtime.ambiguityBand;
  const lower = runtime.similarityThreshold - runtime.ambiguityBand;

  if (top && topScore >= upper) {
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      `Spider-Sense high similarity (${topScore.toFixed(3)}) to pattern '${top.entry.label}'`,
      "clawdstrike-spider-sense",
      "high",
    );
  }
  if (topScore <= lower) {
    return { status: "allow" };
  }
  return warnDecision(
    POLICY_REASON_CODES.POLICY_WARN,
    `Spider-Sense ambiguous similarity (${topScore.toFixed(3)})`,
    "clawdstrike-spider-sense",
    "medium",
  );
}

async function evaluateSpiderSenseRuntime(
  runtime: SpiderSenseRuntimeConfig,
  event: PolicyEvent,
): Promise<Decision> {
  if (!runtime.enabled) return { status: "allow" };
  try {
    const embedding =
      extractEmbeddingFromEvent(event) ?? (await fetchSpiderSenseEmbedding(runtime, event));
    if (!embedding) {
      return { status: "allow" };
    }
    return evaluateSpiderSenseEmbedding(runtime, embedding);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return denyDecision(
      POLICY_REASON_CODES.GUARD_ERROR,
      `Spider-Sense runtime error: ${detail}`,
      "clawdstrike-spider-sense",
      "high",
    );
  }
}

function buildThreatIntelEngine(
  policy: Policy,
  guardToggles: ResolvedClawdstrikeConfig["guards"],
  policyBaseDir?: string,
): CanonicalPolicyEngineLike | null {
  const custom = policy.guards?.custom;
  if (!Array.isArray(custom) || custom.length === 0) {
    return null;
  }

  const policySpiderSenseDisabled = isPolicySpiderSenseDisabled(policy);
  const spiderSenseRuntimes = custom
    .filter((entry) => {
      if (!isSpiderSenseCustomGuard(entry)) return false;
      if (!guardToggles.spider_sense || policySpiderSenseDisabled) return false;
      if (isRecord(entry) && entry.enabled === false) return false;
      return true;
    })
    .map((entry) => buildSpiderSenseRuntimeConfig(entry, { policyBaseDir }));
  const filteredCustom = custom.filter((entry) => {
    if (isSpiderSenseCustomGuard(entry)) {
      return false;
    }
    return true;
  });

  let canonicalEngine: CanonicalPolicyEngineLike | null = null;
  if (filteredCustom.length > 0) {
    // The openclaw Policy types `custom` as `unknown`; the canonical Policy
    // expects `CustomGuardSpec[]`. We've validated it's an array above.
    // GuardConfigs has an index signature so `unknown[]` is assignable.
    const canonicalPolicy: CanonicalPolicy = {
      version: "1.1.0",
      guards: { custom: filteredCustom },
    };
    canonicalEngine = createPolicyEngineFromPolicy(canonicalPolicy);
  }

  if (!canonicalEngine && spiderSenseRuntimes.length === 0) {
    return null;
  }

  if (!canonicalEngine) {
    return {
      evaluate: async (event: PolicyEvent): Promise<Decision> => {
        let out: Decision = { status: "allow" };
        for (const runtime of spiderSenseRuntimes) {
          const decision = await evaluateSpiderSenseRuntime(runtime, event);
          out = combineDecisions(out, decision);
          if (out.status === "deny") return out;
        }
        return out;
      },
    };
  }

  if (spiderSenseRuntimes.length === 0) {
    return canonicalEngine;
  }

  return {
    evaluate: async (event: PolicyEvent): Promise<Decision> => {
      const canonicalDecision = (await canonicalEngine.evaluate(event)) as Decision;
      if (canonicalDecision.status === "deny") return canonicalDecision;

      let spiderDecision: Decision = { status: "allow" };
      for (const runtime of spiderSenseRuntimes) {
        const decision = await evaluateSpiderSenseRuntime(runtime, event);
        spiderDecision = combineDecisions(spiderDecision, decision);
        if (spiderDecision.status === "deny") break;
      }
      return combineDecisions(canonicalDecision, spiderDecision);
    },
  };
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
        : (next.message ?? next.reason),
    };
  }
  return base;
}

function normalizeStringList(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const out: string[] = [];
  for (const value of values) {
    if (typeof value !== "string") continue;
    const normalized = value.trim();
    if (normalized.length > 0) out.push(normalized);
  }
  return out;
}

function extractInputType(data: CuaEventData): string | null {
  const candidates = [data.input_type, data.inputType];
  for (const candidate of candidates) {
    if (typeof candidate === "string") {
      const normalized = candidate.trim().toLowerCase();
      if (normalized.length > 0) return normalized;
    }
  }
  return null;
}

function extractTransferSize(data: CuaEventData): number | null {
  const candidates = [data.transfer_size, data.transferSize, data.size_bytes, data.sizeBytes];

  for (const candidate of candidates) {
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0) {
      return candidate;
    }
    if (typeof candidate === "string") {
      const parsed = Number.parseInt(candidate, 10);
      if (Number.isFinite(parsed) && parsed >= 0) {
        return parsed;
      }
    }
  }

  return null;
}

function parsePort(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
  }
  if (typeof value === "string") {
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
    if (typeof value !== "string") continue;
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
  const parsed = parseNetworkTarget(url ?? "", { emptyPort: "default" });

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
    data.port ??
      data.remote_port ??
      data.remotePort ??
      data.destination_port ??
      data.destinationPort,
  );
  const port = explicitPort ?? (parsed.host ? parsed.port : protocol === "http" ? 80 : 443);

  return {
    host,
    port,
    ...(protocol ? { protocol } : {}),
    ...(url ? { url } : {}),
  };
}

type SideChannelFlag =
  | "clipboard_enabled"
  | "file_transfer_enabled"
  | "audio_enabled"
  | "drive_mapping_enabled"
  | "printing_enabled"
  | "session_share_enabled";

function eventTypeToSideChannelFlag(eventType: PolicyEvent["eventType"]): SideChannelFlag | null {
  switch (eventType) {
    case "remote.clipboard":
      return "clipboard_enabled";
    case "remote.file_transfer":
      return "file_transfer_enabled";
    case "remote.audio":
      return "audio_enabled";
    case "remote.drive_mapping":
      return "drive_mapping_enabled";
    case "remote.printing":
      return "printing_enabled";
    case "remote.session_share":
      return "session_share_enabled";
    default:
      return null;
  }
}
