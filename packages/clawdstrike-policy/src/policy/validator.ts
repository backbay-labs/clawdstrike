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

export function validatePolicy(policy: unknown): PolicyLintResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isPlainObject(policy)) {
    return { valid: false, errors: ['Policy must be an object'], warnings: [] };
  }

  const p = policy as Policy;
  const version = p.version ?? '1.1.0';
  if (typeof version !== 'string' || !isStrictSemver(version)) {
    errors.push(`version must be a strict semver string (got: ${String(version)})`);
  } else if (version !== '1.1.0') {
    errors.push(`unsupported policy version: ${version} (supported: 1.1.0)`);
  }

  if (p.guards && isPlainObject(p.guards)) {
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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}
