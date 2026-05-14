/**
 * Egress Allowlist Guard Simulation
 *
 * Controls network egress by domain. Allow/block lists with domain pattern
 * matching. Block list takes precedence. Default patterns from
 * rulesets/default.yaml.
 */
import type { GuardAction, GuardResult } from './types';

/** Default allow list from rulesets/default.yaml */
const DEFAULT_ALLOW: string[] = [
  '*.openai.com',
  '*.anthropic.com',
  'api.github.com',
  'github.com',
  '*.githubusercontent.com',
  '*.npmjs.org',
  'registry.npmjs.org',
  'pypi.org',
  'files.pythonhosted.org',
  'crates.io',
  'static.crates.io',
];

const DEFAULT_BLOCK: string[] = [];
const DEFAULT_ACTION = 'block';

/**
 * Check if a domain matches a pattern.
 * - `*.example.com` matches `sub.example.com` and `example.com`
 * - Exact match: `api.github.com` matches `api.github.com`
 */
function domainMatches(domain: string, pattern: string): boolean {
  const lowerDomain = domain.toLowerCase();
  const lowerPattern = pattern.toLowerCase();

  // Wildcard pattern: *.example.com
  if (lowerPattern.startsWith('*.')) {
    const suffix = lowerPattern.slice(2); // e.g. "example.com"
    // Match the suffix itself or any subdomain
    return lowerDomain === suffix || lowerDomain.endsWith('.' + suffix);
  }

  // Exact match
  return lowerDomain === lowerPattern;
}

function matchesAny(domain: string, patterns: string[]): boolean {
  return patterns.some((p) => domainMatches(domain, p));
}

export function evaluateEgressAllowlist(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate network_egress actions
  if (action.type !== 'network_egress') {
    return {
      allowed: true,
      guard: 'egress_allowlist',
      severity: 'info',
      message: 'Action type not evaluated by egress_allowlist guard',
    };
  }

  const host = action.host;
  const allow = (config.allow as string[] | undefined) ?? DEFAULT_ALLOW;
  const block = (config.block as string[] | undefined) ?? DEFAULT_BLOCK;
  const defaultAction =
    (config.default_action as string | undefined) ?? DEFAULT_ACTION;

  // Block list takes precedence
  if (matchesAny(host, block)) {
    return {
      allowed: false,
      guard: 'egress_allowlist',
      severity: 'error',
      message: `Egress blocked: ${host} matches block list`,
      details: { host },
    };
  }

  // Check allow list
  if (matchesAny(host, allow)) {
    return {
      allowed: true,
      guard: 'egress_allowlist',
      severity: 'info',
      message: `Egress allowed: ${host}`,
      details: { host },
    };
  }

  // Apply default action
  if (defaultAction === 'block') {
    return {
      allowed: false,
      guard: 'egress_allowlist',
      severity: 'error',
      message: `Egress blocked: ${host} not in allow list`,
      details: { host, default_action: defaultAction },
    };
  }

  return {
    allowed: true,
    guard: 'egress_allowlist',
    severity: 'info',
    message: `Egress allowed by default: ${host}`,
    details: { host },
  };
}
