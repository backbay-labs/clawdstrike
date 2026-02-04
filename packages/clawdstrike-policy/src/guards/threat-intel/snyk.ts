import type { PolicyEvent } from '@clawdstrike/adapter-core';
import { createHash } from 'node:crypto';

import type { AsyncGuard, GuardResult, HttpClient, HttpRequestPolicy } from '../../async/types.js';

const DEFAULT_BASE_URL = 'https://snyk.io/api/v1';

export type SnykSeverity = 'low' | 'medium' | 'high' | 'critical';

export type SnykConfig = {
  api_token: string;
  org_id: string;
  base_url?: string;
  severity_threshold?: SnykSeverity;
  fail_on_upgradable?: boolean;
};

export function createSnykGuard(config: SnykConfig, asyncCfg: AsyncGuard['config']): AsyncGuard {
  const baseUrl = (config.base_url ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  const threshold = config.severity_threshold ?? 'high';
  const failOnUpgradable = config.fail_on_upgradable === true;

  const allowedHost = new URL(baseUrl).hostname;
  const policy: HttpRequestPolicy = {
    allowedHosts: [allowedHost],
    allowedMethods: ['POST'],
    allowInsecureHttpForLoopback: true,
  };

  return {
    name: 'clawdstrike-snyk',
    config: asyncCfg,

    handles(event: PolicyEvent): boolean {
      return event.eventType === 'file_write' && event.data.type === 'file';
    },

    cacheKey(event: PolicyEvent): string | null {
      if (event.eventType !== 'file_write' || event.data.type !== 'file') return null;
      if (!event.data.path.endsWith('package.json')) return null;
      const bytes = fileContentBytes(event);
      if (!bytes || bytes.length === 0) return null;
      return `pkg:sha256:${sha256Hex(bytes)}`;
    },

    async checkUncached(event: PolicyEvent, http: HttpClient, signal?: AbortSignal): Promise<GuardResult> {
      if (event.eventType !== 'file_write' || event.data.type !== 'file') {
        return allow('clawdstrike-snyk');
      }
      if (!event.data.path.endsWith('package.json')) {
        return allow('clawdstrike-snyk');
      }

      const bytes = fileContentBytes(event);
      if (!bytes || bytes.length === 0) {
        return warn('clawdstrike-snyk', 'Snyk: missing content bytes for package.json', {
          reason: 'missing_content_bytes',
        });
      }

      const endpoint = `${baseUrl}/test`;
      const body = {
        orgId: config.org_id,
        targetFile: 'package.json',
        manifest: bytes.toString('utf8'),
      };

      const resp = await http.requestJson(
        'clawdstrike-snyk',
        'POST',
        endpoint,
        {
          authorization: `token ${config.api_token}`,
          'content-type': 'application/json',
        },
        body,
        policy,
        signal,
      );

      const vulns = extractVulnerabilities(resp.json);
      const atOrAbove = vulns.filter((v) => severityRank(v.severity) >= severityRank(threshold));
      const upgradable = atOrAbove.filter((v) => v.upgradable);

      if (atOrAbove.length === 0) {
        return allow('clawdstrike-snyk', { status: resp.status, audit: resp.audit, threshold });
      }

      if (failOnUpgradable && upgradable.length > 0) {
        return deny(
          'clawdstrike-snyk',
          'high',
          `Snyk: ${upgradable.length} upgradable vulnerabilities at/above threshold`,
          {
            vulns_at_or_above_threshold: atOrAbove.length,
            upgradable_vulns_at_or_above_threshold: upgradable.length,
            threshold,
            status: resp.status,
            audit: resp.audit,
          },
        );
      }

      return warn('clawdstrike-snyk', `Snyk: ${atOrAbove.length} vulnerabilities at/above threshold`, {
        vulns_at_or_above_threshold: atOrAbove.length,
        threshold,
        status: resp.status,
        audit: resp.audit,
      });
    },
  };
}

type Vuln = { severity: SnykSeverity; upgradable: boolean };

function extractVulnerabilities(json: unknown): Vuln[] {
  const root = json as any;
  const list = Array.isArray(root?.vulnerabilities)
    ? root.vulnerabilities
    : Array.isArray(root?.issues?.vulnerabilities)
      ? root.issues.vulnerabilities
      : [];

  const out: Vuln[] = [];
  for (const v of list) {
    const sevRaw = typeof v?.severity === 'string' ? (v.severity as string).toLowerCase() : '';
    const sev = (['low', 'medium', 'high', 'critical'] as const).includes(sevRaw as any)
      ? (sevRaw as SnykSeverity)
      : null;
    if (!sev) continue;

    const isUpgradable = Boolean(v?.isUpgradable);
    const upgradePathHasString = Array.isArray(v?.upgradePath)
      ? v.upgradePath.some((x: unknown) => typeof x === 'string' && x.length > 0)
      : false;

    out.push({ severity: sev, upgradable: isUpgradable || upgradePathHasString });
  }
  return out;
}

function fileContentBytes(event: PolicyEvent): Buffer | null {
  if (event.data.type !== 'file') return null;
  const data = event.data as any;
  if (typeof data.contentBase64 === 'string') {
    try {
      return Buffer.from(data.contentBase64, 'base64');
    } catch {
      return null;
    }
  }
  if (typeof data.content === 'string') {
    return Buffer.from(data.content, 'utf8');
  }
  return null;
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function severityRank(sev: SnykSeverity): number {
  switch (sev) {
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

function allow(guard: string, details?: Record<string, unknown>): GuardResult {
  return { allowed: true, guard, severity: 'low', message: 'Allowed', details };
}

function warn(guard: string, message: string, details?: Record<string, unknown>): GuardResult {
  return { allowed: true, guard, severity: 'medium', message, details };
}

function deny(guard: string, severity: 'high' | 'critical', message: string, details?: Record<string, unknown>): GuardResult {
  return { allowed: false, guard, severity, message, details };
}

