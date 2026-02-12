import type { PolicyEvent } from '@clawdstrike/adapter-core';
import { createHash } from 'node:crypto';

import type { AsyncGuard, GuardResult, HttpClient, HttpRequestPolicy } from '../../async/types.js';

const DEFAULT_BASE_URL = 'https://www.virustotal.com/api/v3';
const DEFAULT_MIN_DETECTIONS = 5;

export type VirusTotalConfig = {
  api_key: string;
  base_url?: string;
  min_detections?: number;
};

export function createVirusTotalGuard(config: VirusTotalConfig, asyncCfg: AsyncGuard['config']): AsyncGuard {
  const baseUrl = (config.base_url ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  const minDetections = Math.max(1, Math.trunc(config.min_detections ?? DEFAULT_MIN_DETECTIONS));

  const allowedHost = new URL(baseUrl).hostname;
  const policy: HttpRequestPolicy = {
    allowedHosts: [allowedHost],
    allowedMethods: ['GET'],
    allowInsecureHttpForLoopback: true,
  };

  return {
    name: 'clawdstrike-virustotal',
    config: asyncCfg,

    handles(event: PolicyEvent): boolean {
      return event.eventType === 'file_write' || event.eventType === 'network_egress';
    },

    cacheKey(event: PolicyEvent): string | null {
      if (event.eventType === 'file_write' && event.data.type === 'file') {
        const hash = fileSha256Hex(event);
        return hash ? `file:sha256:${hash}` : null;
      }
      if (event.eventType === 'network_egress' && event.data.type === 'network') {
        const url = event.data.url ?? `https://${event.data.host}`;
        return `url:${url}`;
      }
      return null;
    },

    async checkUncached(event: PolicyEvent, http: HttpClient, signal?: AbortSignal): Promise<GuardResult> {
      if (event.eventType === 'file_write' && event.data.type === 'file') {
        const hash = fileSha256Hex(event);
        if (!hash) {
          return warn('clawdstrike-virustotal', 'VirusTotal: missing content bytes or content hash', {
            reason: 'missing_content_hash',
          });
        }

        const url = `${baseUrl}/files/${hash}`;
        const resp = await http.requestJson(
          'clawdstrike-virustotal',
          'GET',
          url,
          { 'x-apikey': config.api_key },
          null,
          policy,
          signal,
        );

        if (resp.status === 404) {
          return warn('clawdstrike-virustotal', 'VirusTotal: file hash not found', {
            hash,
            status: resp.status,
            audit: resp.audit,
          });
        }

        const stats = analysisStats(resp.json);
        const detections = stats.malicious + stats.suspicious;
        if (detections >= minDetections) {
          return deny('clawdstrike-virustotal', 'critical', `VirusTotal: ${detections} detections for file hash ${hash}`, {
            hash,
            last_analysis_stats: stats,
            status: resp.status,
            audit: resp.audit,
          });
        }

        if (stats.malicious > 0) {
          return warn(
            'clawdstrike-virustotal',
            `VirusTotal: malicious detections below threshold (malicious=${stats.malicious}, suspicious=${stats.suspicious})`,
            { hash, last_analysis_stats: stats, status: resp.status, audit: resp.audit },
          );
        }

        return allow('clawdstrike-virustotal', { hash, status: resp.status, audit: resp.audit });
      }

      if (event.eventType === 'network_egress' && event.data.type === 'network') {
        const targetUrl = event.data.url ?? `https://${event.data.host}`;
        const id = Buffer.from(targetUrl, 'utf8').toString('base64url');
        const url = `${baseUrl}/urls/${id}`;
        const resp = await http.requestJson(
          'clawdstrike-virustotal',
          'GET',
          url,
          { 'x-apikey': config.api_key },
          null,
          policy,
          signal,
        );

        if (resp.status === 404) {
          return warn('clawdstrike-virustotal', 'VirusTotal: URL not found', {
            url: targetUrl,
            status: resp.status,
            audit: resp.audit,
          });
        }

        const stats = analysisStats(resp.json);
        const detections = stats.malicious + stats.suspicious;
        if (detections >= minDetections) {
          return deny('clawdstrike-virustotal', 'high', `VirusTotal: ${detections} detections for URL ${targetUrl}`, {
            url: targetUrl,
            last_analysis_stats: stats,
            status: resp.status,
            audit: resp.audit,
          });
        }

        if (stats.malicious > 0) {
          return warn(
            'clawdstrike-virustotal',
            `VirusTotal: malicious detections below threshold (malicious=${stats.malicious}, suspicious=${stats.suspicious})`,
            { url: targetUrl, last_analysis_stats: stats, status: resp.status, audit: resp.audit },
          );
        }

        return allow('clawdstrike-virustotal', { url: targetUrl, status: resp.status, audit: resp.audit });
      }

      return allow('clawdstrike-virustotal');
    },
  };
}

function fileSha256Hex(event: PolicyEvent): string | null {
  if (event.data.type !== 'file') return null;

  const bytes = fileContentBytes(event);
  if (bytes && bytes.byteLength > 0) {
    return sha256Hex(bytes);
  }

  const raw = (event.data as any).contentHash;
  if (typeof raw !== 'string') return null;
  return normalizeSha256Hex(raw);
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

function normalizeSha256Hex(input: string): string | null {
  const trimmed = input.trim();
  const withoutPrefix = trimmed.startsWith('sha256:') ? trimmed.slice('sha256:'.length) : trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
  const hex = withoutPrefix.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  return hex;
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function analysisStats(json: unknown): { malicious: number; suspicious: number } {
  const stats = pointer(json, ['data', 'attributes', 'last_analysis_stats']);
  const malicious = asNumber(pointer(stats, ['malicious'])) ?? 0;
  const suspicious = asNumber(pointer(stats, ['suspicious'])) ?? 0;
  return { malicious, suspicious };
}

function pointer(value: unknown, path: string[]): unknown {
  let cur: any = value;
  for (const p of path) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : typeof value === 'bigint' ? Number(value) : null;
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

