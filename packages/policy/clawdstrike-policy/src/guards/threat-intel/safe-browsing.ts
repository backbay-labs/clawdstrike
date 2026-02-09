import type { PolicyEvent } from '@clawdstrike/adapter-core';

import type { AsyncGuard, GuardResult, HttpClient, HttpRequestPolicy } from '../../async/types.js';

const DEFAULT_BASE_URL = 'https://safebrowsing.googleapis.com/v4';

export type SafeBrowsingConfig = {
  api_key: string;
  client_id: string;
  client_version?: string;
  base_url?: string;
};

export function createSafeBrowsingGuard(config: SafeBrowsingConfig, asyncCfg: AsyncGuard['config']): AsyncGuard {
  const baseUrl = (config.base_url ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  const allowedHost = new URL(baseUrl).hostname;
  const policy: HttpRequestPolicy = {
    allowedHosts: [allowedHost],
    allowedMethods: ['POST'],
    allowInsecureHttpForLoopback: true,
  };

  return {
    name: 'clawdstrike-safe-browsing',
    config: asyncCfg,

    handles(event: PolicyEvent): boolean {
      return event.eventType === 'network_egress';
    },

    cacheKey(event: PolicyEvent): string | null {
      if (event.eventType !== 'network_egress' || event.data.type !== 'network') return null;
      const url = event.data.url ?? `https://${event.data.host}`;
      return `url:${url}`;
    },

    async checkUncached(event: PolicyEvent, http: HttpClient, signal?: AbortSignal): Promise<GuardResult> {
      if (event.eventType !== 'network_egress' || event.data.type !== 'network') {
        return allow('clawdstrike-safe-browsing');
      }

      const url = event.data.url ?? `https://${event.data.host}`;

      const endpoint = `${baseUrl}/threatMatches:find?key=${encodeURIComponent(config.api_key)}`;
      const body = {
        client: {
          clientId: config.client_id,
          clientVersion: config.client_version ?? '0.1.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };

      const resp = await http.requestJson(
        'clawdstrike-safe-browsing',
        'POST',
        endpoint,
        { 'content-type': 'application/json' },
        body,
        policy,
        signal,
      );

      const matches = Array.isArray((resp.json as any)?.matches) ? (resp.json as any).matches : [];
      if (matches.length > 0) {
        return deny('clawdstrike-safe-browsing', 'critical', `Safe Browsing: threat match for URL ${url}`, {
          url,
          status: resp.status,
          audit: resp.audit,
        });
      }

      return allow('clawdstrike-safe-browsing', { url, status: resp.status, audit: resp.audit });
    },
  };
}

function allow(guard: string, details?: Record<string, unknown>): GuardResult {
  return { allowed: true, guard, severity: 'low', message: 'Allowed', details };
}

function deny(guard: string, severity: 'high' | 'critical', message: string, details?: Record<string, unknown>): GuardResult {
  return { allowed: false, guard, severity, message, details };
}

