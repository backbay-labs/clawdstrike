/**
 * @clawdstrike/openclaw - Egress Guard
 *
 * Enforces network egress allowlist/denylist policies.
 */

import { minimatch } from 'minimatch';
import type { PolicyEvent, Policy, GuardResult, EventType } from '../types.js';
import { BaseGuard } from './types.js';

/**
 * Default denied domains when no policy is specified
 */
const DEFAULT_DENIED_DOMAINS = [
  '*.onion',
  'localhost',
  '127.*',
  '10.*',
  '192.168.*',
  '172.16.*',
  '172.17.*',
  '172.18.*',
  '172.19.*',
  '172.20.*',
  '172.21.*',
  '172.22.*',
  '172.23.*',
  '172.24.*',
  '172.25.*',
  '172.26.*',
  '172.27.*',
  '172.28.*',
  '172.29.*',
  '172.30.*',
  '172.31.*',
];

/**
 * Default allowed domains for AI agent operations
 */
const DEFAULT_ALLOWED_DOMAINS = [
  'api.anthropic.com',
  'api.openai.com',
  'pypi.org',
  'registry.npmjs.org',
  'crates.io',
  '*.github.com',
  '*.githubusercontent.com',
];

/**
 * EgressGuard - enforces network egress policy
 */
export class EgressGuard extends BaseGuard {
  name(): string {
    return 'egress';
  }

  handles(): EventType[] {
    return ['network_egress'];
  }

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    return this.checkSync(event, policy);
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    const data = event.data;

    // Only handle network events
    if (data.type !== 'network') {
      return this.allow();
    }

    const host = data.host.toLowerCase();
    const egressPolicy = policy.egress;

    // Get configured lists or defaults
    const deniedDomains = egressPolicy?.denied_domains ?? DEFAULT_DENIED_DOMAINS;
    const allowedDomains = egressPolicy?.allowed_domains ?? DEFAULT_ALLOWED_DOMAINS;
    const mode = egressPolicy?.mode ?? 'allowlist';

    // Always check denied domains first (takes precedence)
    if (this.matchesDomain(host, deniedDomains)) {
      return this.deny(
        `Egress to denied domain: ${host}`,
        this.getSeverity(host),
      );
    }

    // Handle different modes
    switch (mode) {
      case 'deny_all':
        return this.deny(`Egress denied (deny_all mode): ${host}`, 'high');

      case 'open':
        return this.allow();

      case 'denylist':
        // In denylist mode, only deny explicitly listed domains
        return this.allow();

      case 'allowlist':
      default:
        // In allowlist mode, only allow explicitly listed domains
        if (this.matchesDomain(host, allowedDomains)) {
          return this.allow();
        }
        return this.deny(
          `Egress to non-allowlisted domain: ${host}`,
          'medium',
        );
    }
  }

  /**
   * Check if a host matches any domain pattern
   */
  private matchesDomain(host: string, patterns: string[]): boolean {
    for (const pattern of patterns) {
      const normalizedPattern = pattern.toLowerCase();

      // Exact match
      if (host === normalizedPattern) {
        return true;
      }

      // Wildcard subdomain match (*.example.com)
      if (normalizedPattern.startsWith('*.')) {
        const baseDomain = normalizedPattern.slice(2);
        if (host === baseDomain || host.endsWith('.' + baseDomain)) {
          return true;
        }
      }

      // IP range match (e.g., 192.168.*)
      if (normalizedPattern.includes('*')) {
        const regexPattern = normalizedPattern
          .replace(/\./g, '\\.')
          .replace(/\*/g, '.*');
        const regex = new RegExp(`^${regexPattern}$`);
        if (regex.test(host)) {
          return true;
        }
      }

      // Use minimatch for complex patterns
      if (minimatch(host, normalizedPattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get severity based on the type of denied domain
   */
  private getSeverity(host: string): 'low' | 'medium' | 'high' | 'critical' {
    // Tor/onion domains are critical
    if (host.endsWith('.onion')) {
      return 'critical';
    }

    // Localhost/private IPs are high
    if (
      host === 'localhost' ||
      host.startsWith('127.') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('172.')
    ) {
      return 'high';
    }

    return 'medium';
  }
}
