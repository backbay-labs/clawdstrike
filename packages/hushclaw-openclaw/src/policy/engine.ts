import type { PolicyConfig, PolicyEvent, PolicyDecision, ActionType } from './types.js';

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(config: PolicyConfig) {
    this.config = config;
  }

  async evaluate(event: PolicyEvent): Promise<PolicyDecision> {
    // Check filesystem guards
    if (event.type === 'file_read' || event.type === 'file_write') {
      const fsDecision = this.checkFilesystem(event);
      if (fsDecision.denied) return fsDecision;
    }

    // Check egress guards
    if (event.type === 'network_egress') {
      const egressDecision = this.checkEgress(event);
      if (egressDecision.denied) return egressDecision;
    }

    return { allowed: true, denied: false };
  }

  private checkFilesystem(event: PolicyEvent): PolicyDecision {
    const { filesystem } = this.config;
    if (!filesystem) return { allowed: true, denied: false };

    // Check forbidden paths
    if (filesystem.forbidden_paths) {
      for (const pattern of filesystem.forbidden_paths) {
        if (this.matchPath(event.resource, pattern)) {
          return {
            allowed: false,
            denied: true,
            reason: `Path matches forbidden pattern: ${pattern}`,
            guard: 'ForbiddenPathGuard',
            severity: 'critical',
          };
        }
      }
    }

    // Check allowed write roots for write operations
    if (event.type === 'file_write' && filesystem.allowed_write_roots) {
      const isAllowed = filesystem.allowed_write_roots.some(root =>
        this.matchPath(event.resource, root) || event.resource.startsWith(this.expandPath(root))
      );
      if (!isAllowed) {
        return {
          allowed: false,
          denied: true,
          reason: `Write path not in allowed roots`,
          guard: 'WriteRootGuard',
          severity: 'high',
        };
      }
    }

    return { allowed: true, denied: false };
  }

  private checkEgress(event: PolicyEvent): PolicyDecision {
    const { egress } = this.config;
    if (!egress || egress.mode === 'open') return { allowed: true, denied: false };

    const domain = this.extractDomain(event.resource);

    if (egress.mode === 'allowlist') {
      const allowed = egress.allowed_domains?.some(pattern =>
        this.matchDomain(domain, pattern)
      );
      if (!allowed) {
        return {
          allowed: false,
          denied: true,
          reason: `Domain '${domain}' not in egress allowlist`,
          guard: 'EgressAllowlistGuard',
          severity: 'high',
        };
      }
    }

    if (egress.mode === 'denylist' && egress.denied_domains) {
      const denied = egress.denied_domains.some(pattern =>
        this.matchDomain(domain, pattern)
      );
      if (denied) {
        return {
          allowed: false,
          denied: true,
          reason: `Domain '${domain}' is in deny list`,
          guard: 'EgressDenylistGuard',
          severity: 'high',
        };
      }
    }

    return { allowed: true, denied: false };
  }

  private matchPath(path: string, pattern: string): boolean {
    const expandedPattern = this.expandPath(pattern);
    const expandedPath = this.expandPath(path);

    // Simple prefix match for now
    if (expandedPath.startsWith(expandedPattern)) return true;
    if (expandedPath.includes(expandedPattern)) return true;

    return false;
  }

  private matchDomain(domain: string, pattern: string): boolean {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // Remove *
      return domain.endsWith(suffix) || domain === pattern.slice(2);
    }
    return domain === pattern;
  }

  private extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname;
    } catch {
      return url;
    }
  }

  private expandPath(path: string): string {
    return path.replace(/^~/, process.env.HOME || '/home/user');
  }

  createEvent(action: ActionType, resource: string, params?: Record<string, unknown>): PolicyEvent {
    return {
      type: action,
      resource,
      params,
      timestamp: Date.now(),
    };
  }
}
