import type { Policy } from '../policy/schema.js';
import { resolvePlaceholders } from '../policy/placeholders.js';
import { buildAsyncGuardConfig } from '../async/config.js';
import type { AsyncGuard } from '../async/types.js';

import { createSafeBrowsingGuard, type SafeBrowsingConfig } from './threat-intel/safe-browsing.js';
import { createSnykGuard, type SnykConfig } from './threat-intel/snyk.js';
import { createVirusTotalGuard, type VirusTotalConfig } from './threat-intel/virustotal.js';

export function buildAsyncGuards(policy: Policy): Array<{ index: number; guard: AsyncGuard }> {
  const custom = Array.isArray(policy.guards?.custom) ? policy.guards?.custom : [];
  const out: Array<{ index: number; guard: AsyncGuard }> = [];

  for (let i = 0; i < custom.length; i++) {
    const spec = custom[i];
    if (!spec || typeof spec !== 'object') continue;
    const enabled = spec.enabled !== false;
    if (!enabled) continue;
    const pkg = String(spec.package);

    const asyncCfg = buildAsyncGuardConfig(spec.async);
    const resolvedConfig = resolvePlaceholders(spec.config ?? {}) as Record<string, unknown>;

    if (pkg === 'clawdstrike-virustotal') {
      out.push({ index: i, guard: createVirusTotalGuard(assertVirusTotal(resolvedConfig), asyncCfg) });
      continue;
    }
    if (pkg === 'clawdstrike-safe-browsing') {
      out.push({ index: i, guard: createSafeBrowsingGuard(assertSafeBrowsing(resolvedConfig), asyncCfg) });
      continue;
    }
    if (pkg === 'clawdstrike-snyk') {
      out.push({ index: i, guard: createSnykGuard(assertSnyk(resolvedConfig), asyncCfg) });
      continue;
    }

    throw new Error(`unsupported custom guard package: ${pkg}`);
  }

  return out;
}

function assertVirusTotal(cfg: Record<string, unknown>): VirusTotalConfig {
  const api_key = requiredString(cfg.api_key, 'config.api_key');
  const base_url = optionalString(cfg.base_url);
  const min_detections = optionalNumber(cfg.min_detections);
  return { api_key, base_url, min_detections };
}

function assertSafeBrowsing(cfg: Record<string, unknown>): SafeBrowsingConfig {
  const api_key = requiredString(cfg.api_key, 'config.api_key');
  const client_id = requiredString(cfg.client_id, 'config.client_id');
  const client_version = optionalString(cfg.client_version);
  const base_url = optionalString(cfg.base_url);
  return { api_key, client_id, client_version, base_url };
}

function assertSnyk(cfg: Record<string, unknown>): SnykConfig {
  const api_token = requiredString(cfg.api_token, 'config.api_token');
  const org_id = requiredString(cfg.org_id, 'config.org_id');
  const base_url = optionalString(cfg.base_url);
  const severity_threshold = optionalString(cfg.severity_threshold) as any;
  const fail_on_upgradable = typeof cfg.fail_on_upgradable === 'boolean' ? cfg.fail_on_upgradable : undefined;
  return { api_token, org_id, base_url, severity_threshold, fail_on_upgradable };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`missing/invalid required string: ${field}`);
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

