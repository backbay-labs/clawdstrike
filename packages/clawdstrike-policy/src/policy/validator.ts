import type { Policy } from './schema.js';

export type PolicyLintResult = {
  valid: boolean;
  errors: string[];
  warnings: string[];
};

const PLACEHOLDER_RE = /\$\{([^}]+)\}/g;

const RESERVED_PACKAGES = new Set([
  'clawdstrike-virustotal',
  'clawdstrike-safe-browsing',
  'clawdstrike-snyk',
]);
const SUPPORTED_POLICY_VERSIONS = new Set(['1.1.0', '1.2.0']);
const DEFAULT_POLICY_VERSION = '1.2.0';
const KNOWN_POSTURE_CAPABILITIES = new Set([
  'file_access',
  'file_write',
  'egress',
  'shell',
  'mcp_tool',
  'patch',
  'custom',
]);
const KNOWN_POSTURE_BUDGETS = new Set([
  'file_writes',
  'egress_calls',
  'shell_commands',
  'mcp_tool_calls',
  'patches',
  'custom_calls',
]);

export function validatePolicy(policy: unknown): PolicyLintResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isPlainObject(policy)) {
    return { valid: false, errors: ['Policy must be an object'], warnings: [] };
  }

  const p = policy as Policy;
  const version = p.version ?? DEFAULT_POLICY_VERSION;
  if (typeof version !== 'string' || !isStrictSemver(version)) {
    errors.push(`version must be a strict semver string (got: ${String(version)})`);
  } else if (!SUPPORTED_POLICY_VERSIONS.has(version)) {
    errors.push(`unsupported policy version: ${version} (supported: 1.1.0, 1.2.0)`);
  }

  if (p.guards && isPlainObject(p.guards)) {
    const pathAllowlist = (p.guards as any).path_allowlist;
    if (pathAllowlist !== undefined) {
      if (version === '1.1.0') {
        errors.push('path_allowlist requires policy version 1.2.0');
      }
      validatePathAllowlist(pathAllowlist, 'guards.path_allowlist', errors);
    }

    const custom = (p.guards as any).custom;
    if (custom !== undefined) {
      if (!Array.isArray(custom)) {
        errors.push('guards.custom must be an array');
      } else {
        for (let i = 0; i < custom.length; i++) {
          validateCustomGuardSpec(custom[i], `guards.custom[${i}]`, errors);
        }
      }
    }
  }

  const posture = (p as any).posture;
  if (posture !== undefined) {
    if (version === '1.1.0') {
      errors.push('posture requires policy version 1.2.0');
    }
    validatePosture(posture, 'posture', errors);
  }

  const policyCustomGuards = (p as any).custom_guards;
  if (policyCustomGuards !== undefined) {
    if (!Array.isArray(policyCustomGuards)) {
      errors.push('custom_guards must be an array');
    } else {
      const seen = new Set<string>();
      for (let i = 0; i < policyCustomGuards.length; i++) {
        const value = policyCustomGuards[i];
        const base = `custom_guards[${i}]`;
        if (!isPlainObject(value)) {
          errors.push(`${base} must be an object`);
          continue;
        }

        const id = (value as any).id;
        if (typeof id !== 'string' || id.trim() === '') {
          errors.push(`${base}.id must be a non-empty string`);
          continue;
        }
        if (seen.has(id)) {
          errors.push(`${base}.id duplicate custom guard id: ${id}`);
        } else {
          seen.add(id);
        }

        const enabled = (value as any).enabled;
        if (enabled !== undefined && typeof enabled !== 'boolean') {
          errors.push(`${base}.enabled must be a boolean`);
        }

        const config = (value as any).config;
        if (config !== undefined && !isPlainObject(config)) {
          errors.push(`${base}.config must be an object`);
        }
      }
    }
  }

  // Validate placeholders across the entire policy tree.
  validatePlaceholders(policy, 'policy', errors);

  return { valid: errors.length === 0, errors, warnings };
}

function validatePathAllowlist(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const enabled = value.enabled;
  if (enabled !== undefined && typeof enabled !== 'boolean') {
    errors.push(`${base}.enabled must be a boolean`);
  }

  validateStringArray(value.file_access_allow, `${base}.file_access_allow`, errors);
  validateStringArray(value.file_write_allow, `${base}.file_write_allow`, errors);
  validateStringArray(value.patch_allow, `${base}.patch_allow`, errors);
}

function validatePosture(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const initial = value.initial;
  if (typeof initial !== 'string' || initial.trim() === '') {
    errors.push(`${base}.initial must be a non-empty string`);
  }

  const states = value.states;
  if (!isPlainObject(states) || Object.keys(states).length === 0) {
    errors.push(`${base}.states must be a non-empty object`);
  } else {
    for (const [stateName, stateValue] of Object.entries(states)) {
      const statePath = `${base}.states.${stateName}`;
      if (!isPlainObject(stateValue)) {
        errors.push(`${statePath} must be an object`);
        continue;
      }

      const capabilities = stateValue.capabilities;
      if (capabilities !== undefined) {
        if (!Array.isArray(capabilities)) {
          errors.push(`${statePath}.capabilities must be an array`);
        } else {
          for (let i = 0; i < capabilities.length; i++) {
            const capability = capabilities[i];
            if (typeof capability !== 'string') {
              errors.push(`${statePath}.capabilities[${i}] must be a string`);
              continue;
            }
            if (!KNOWN_POSTURE_CAPABILITIES.has(capability)) {
              errors.push(`${statePath}.capabilities[${i}] unknown capability: '${capability}'`);
            }
          }
        }
      }

      const budgets = stateValue.budgets;
      if (budgets !== undefined) {
        if (!isPlainObject(budgets)) {
          errors.push(`${statePath}.budgets must be an object`);
        } else {
          for (const [budgetName, budgetValue] of Object.entries(budgets)) {
            if (!KNOWN_POSTURE_BUDGETS.has(budgetName)) {
              errors.push(`${statePath}.budgets.${budgetName} unknown budget type: '${budgetName}'`);
            }
            if (!Number.isInteger(budgetValue) || (budgetValue as number) < 0) {
              errors.push(`${statePath}.budgets.${budgetName} budget '${budgetName}' cannot be negative`);
            }
          }
        }
      }
    }
  }

  if (typeof initial === 'string' && isPlainObject(states) && !Object.prototype.hasOwnProperty.call(states, initial)) {
    errors.push(`${base}.initial posture.initial '${initial}' not found in states`);
  }

  const transitions = value.transitions;
  if (transitions !== undefined) {
    if (!Array.isArray(transitions)) {
      errors.push(`${base}.transitions must be an array`);
    } else {
      for (let i = 0; i < transitions.length; i++) {
        const t = transitions[i];
        const transitionPath = `${base}.transitions[${i}]`;
        if (!isPlainObject(t)) {
          errors.push(`${transitionPath} must be an object`);
          continue;
        }

        const from = t.from;
        const to = t.to;
        const on = t.on;
        if (typeof from !== 'string' || from.trim() === '') {
          errors.push(`${transitionPath}.from must be a non-empty string`);
        } else if (from !== '*' && isPlainObject(states) && !Object.prototype.hasOwnProperty.call(states, from)) {
          errors.push(`${transitionPath}.from transition references unknown state: '${from}'`);
        }

        if (typeof to !== 'string' || to.trim() === '') {
          errors.push(`${transitionPath}.to must be a non-empty string`);
        } else if (to === '*') {
          errors.push(`${transitionPath}.to wildcard in 'to' not allowed`);
        } else if (isPlainObject(states) && !Object.prototype.hasOwnProperty.call(states, to)) {
          errors.push(`${transitionPath}.to transition references unknown state: '${to}'`);
        }

        if (typeof on !== 'string') {
          errors.push(`${transitionPath}.on must be a string`);
        } else if (on === 'timeout') {
          const after = t.after;
          if (typeof after !== 'string') {
            errors.push(`${transitionPath}.after timeout transition missing 'after' duration`);
          } else if (!isValidDuration(after)) {
            errors.push(`${transitionPath}.after invalid duration format: '${after}'`);
          }
        }
      }
    }
  }
}

function validateCustomGuardSpec(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const pkg = value.package;
  if (typeof pkg !== 'string' || pkg.trim() === '') {
    errors.push(`${base}.package must be a non-empty string`);
    return;
  }

  if (!RESERVED_PACKAGES.has(pkg)) {
    errors.push(`${base}.package unsupported custom guard package: ${pkg}`);
    return;
  }

  const enabled = value.enabled;
  if (enabled !== undefined && typeof enabled !== 'boolean') {
    errors.push(`${base}.enabled must be a boolean`);
  }

  const config = value.config;
  if (config !== undefined && !isPlainObject(config)) {
    errors.push(`${base}.config must be an object`);
    return;
  }

  const cfg = (isPlainObject(config) ? config : {}) as Record<string, unknown>;
  if (pkg === 'clawdstrike-virustotal') {
    requireString(cfg, `${base}.config.api_key`, errors);
  } else if (pkg === 'clawdstrike-safe-browsing') {
    requireString(cfg, `${base}.config.api_key`, errors);
    requireString(cfg, `${base}.config.client_id`, errors);
  } else if (pkg === 'clawdstrike-snyk') {
    requireString(cfg, `${base}.config.api_token`, errors);
    requireString(cfg, `${base}.config.org_id`, errors);
  }

  const asyncCfg = value.async;
  if (asyncCfg !== undefined) {
    validateAsyncConfig(asyncCfg, `${base}.async`, errors);
  }
}

function validateAsyncConfig(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const timeoutMs = value.timeout_ms;
  if (timeoutMs !== undefined && (!isFiniteNumber(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000)) {
    errors.push(`${base}.timeout_ms must be between 100 and 300000`);
  }

  if (value.rate_limit !== undefined) {
    if (!isPlainObject(value.rate_limit)) {
      errors.push(`${base}.rate_limit must be an object`);
    } else {
      const rl = value.rate_limit as Record<string, unknown>;
      const rps = rl.requests_per_second;
      const rpm = rl.requests_per_minute;
      if (rps !== undefined && (!isFiniteNumber(rps) || rps <= 0)) {
        errors.push(`${base}.rate_limit.requests_per_second must be > 0`);
      }
      if (rpm !== undefined && (!isFiniteNumber(rpm) || rpm <= 0)) {
        errors.push(`${base}.rate_limit.requests_per_minute must be > 0`);
      }
      if (rps !== undefined && rpm !== undefined) {
        errors.push(`${base}.rate_limit must specify only one of requests_per_second or requests_per_minute`);
      }
      const burst = rl.burst;
      if (burst !== undefined && (typeof burst !== 'number' || !Number.isInteger(burst) || burst < 1)) {
        errors.push(`${base}.rate_limit.burst must be >= 1`);
      }
    }
  }

  if (value.cache !== undefined) {
    if (!isPlainObject(value.cache)) {
      errors.push(`${base}.cache must be an object`);
    } else {
      const cache = value.cache as Record<string, unknown>;
      const ttl = cache.ttl_seconds;
      if (ttl !== undefined && (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 1)) {
        errors.push(`${base}.cache.ttl_seconds must be >= 1`);
      }
      const max = cache.max_size_mb;
      if (max !== undefined && (typeof max !== 'number' || !Number.isInteger(max) || max < 1)) {
        errors.push(`${base}.cache.max_size_mb must be >= 1`);
      }
    }
  }

  if (value.circuit_breaker !== undefined) {
    if (!isPlainObject(value.circuit_breaker)) {
      errors.push(`${base}.circuit_breaker must be an object`);
    } else {
      const cb = value.circuit_breaker as Record<string, unknown>;
      const f = cb.failure_threshold;
      if (f !== undefined && (typeof f !== 'number' || !Number.isInteger(f) || f < 1)) {
        errors.push(`${base}.circuit_breaker.failure_threshold must be >= 1`);
      }
      const reset = cb.reset_timeout_ms;
      if (reset !== undefined && (typeof reset !== 'number' || !Number.isInteger(reset) || reset < 1000)) {
        errors.push(`${base}.circuit_breaker.reset_timeout_ms must be >= 1000`);
      }
      const s = cb.success_threshold;
      if (s !== undefined && (typeof s !== 'number' || !Number.isInteger(s) || s < 1)) {
        errors.push(`${base}.circuit_breaker.success_threshold must be >= 1`);
      }
    }
  }

  if (value.retry !== undefined) {
    if (!isPlainObject(value.retry)) {
      errors.push(`${base}.retry must be an object`);
    } else {
      const retry = value.retry as Record<string, unknown>;
      const mult = retry.multiplier;
      if (mult !== undefined && (!isFiniteNumber(mult) || mult < 1)) {
        errors.push(`${base}.retry.multiplier must be >= 1`);
      }
      const init = retry.initial_backoff_ms;
      if (init !== undefined && (typeof init !== 'number' || !Number.isInteger(init) || init < 100)) {
        errors.push(`${base}.retry.initial_backoff_ms must be >= 100`);
      }
      const max = retry.max_backoff_ms;
      if (max !== undefined && (typeof max !== 'number' || !Number.isInteger(max) || max < 100)) {
        errors.push(`${base}.retry.max_backoff_ms must be >= 100`);
      }
      if (typeof init === 'number' && typeof max === 'number' && max < init) {
        errors.push(`${base}.retry.max_backoff_ms must be >= initial_backoff_ms`);
      }
    }
  }
}

function requireString(obj: Record<string, unknown>, field: string, errors: string[]): void {
  const key = field.split('.').slice(-1)[0] ?? '';
  const value = obj[key];
  if (typeof value !== 'string' || value.trim() === '') {
    errors.push(`${field} missing/invalid required string`);
  }
}

function validateStringArray(value: unknown, field: string, errors: string[]): void {
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    errors.push(`${field} must be an array`);
    return;
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== 'string') {
      errors.push(`${field}[${i}] must be a string`);
    }
  }
}

function validatePlaceholders(value: unknown, base: string, errors: string[]): void {
  if (typeof value === 'string') {
    for (const match of value.matchAll(PLACEHOLDER_RE)) {
      const raw = match[1] ?? '';
      const envName = envVarForPlaceholder(raw);
      if (!envName.ok) {
        errors.push(`${base}: ${envName.error}`);
        continue;
      }
      if (process.env[envName.value] === undefined) {
        errors.push(`${base}: missing environment variable ${envName.value}`);
      }
    }
    return;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      validatePlaceholders(value[i], `${base}[${i}]`, errors);
    }
    return;
  }

  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      validatePlaceholders(v, `${base}.${k}`, errors);
    }
  }
}

function envVarForPlaceholder(raw: string): { ok: true; value: string } | { ok: false; error: string } {
  if (raw.startsWith('secrets.')) {
    const name = raw.slice('secrets.'.length);
    if (!name) {
      return { ok: false, error: 'placeholder ${secrets.} is invalid' };
    }
    return { ok: true, value: name };
  }
  if (!raw) {
    return { ok: false, error: 'placeholder ${} is invalid' };
  }
  return { ok: true, value: raw };
}

function isStrictSemver(version: string): boolean {
  const m = /^([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)$/.exec(version);
  return Boolean(m);
}

function isValidDuration(value: string): boolean {
  return /^[0-9]+[smh]$/.test(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}
