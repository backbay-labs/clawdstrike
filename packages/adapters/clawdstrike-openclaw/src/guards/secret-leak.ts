/**
 * @clawdstrike/openclaw - Secret Leak Guard
 *
 * Detects and blocks exposure of secrets in tool outputs and patches.
 */

import type {
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
  SecretPattern,
} from '../types.js';
import { BaseGuard } from './types.js';

/**
 * Built-in secret detection patterns
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Keys
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  {
    name: 'aws_secret_key',
    pattern: /[A-Za-z0-9/+=]{40}/g,
    severity: 'critical',
    description: 'AWS Secret Access Key',
  },

  // GitHub Tokens
  {
    name: 'github_pat',
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token',
  },
  {
    name: 'github_oauth',
    pattern: /gho_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub OAuth Token',
  },
  {
    name: 'github_app_token',
    pattern: /ghu_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub App User Token',
  },
  {
    name: 'github_fine_grained',
    pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g,
    severity: 'critical',
    description: 'GitHub Fine-grained PAT',
  },

  // OpenAI Keys
  {
    name: 'openai_api_key',
    pattern: /sk-[A-Za-z0-9]{48}/g,
    severity: 'critical',
    description: 'OpenAI API Key',
  },
  {
    name: 'openai_project_key',
    pattern: /sk-proj-[A-Za-z0-9]{48}/g,
    severity: 'critical',
    description: 'OpenAI Project API Key',
  },

  // Anthropic Keys
  {
    name: 'anthropic_api_key',
    pattern: /sk-ant-[A-Za-z0-9]{32,}/g,
    severity: 'critical',
    description: 'Anthropic API Key',
  },

  // Google Cloud
  {
    name: 'google_api_key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'critical',
    description: 'Google API Key',
  },
  {
    name: 'gcp_service_account',
    pattern: /"type":\s*"service_account"/g,
    severity: 'high',
    description: 'GCP Service Account JSON',
  },

  // Private Keys
  {
    name: 'private_key_rsa',
    pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'RSA Private Key',
  },
  {
    name: 'private_key_openssh',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'OpenSSH Private Key',
  },
  {
    name: 'private_key_ec',
    pattern: /-----BEGIN EC PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'EC Private Key',
  },
  {
    name: 'private_key_generic',
    pattern: /-----BEGIN PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Private Key',
  },

  // Stripe
  {
    name: 'stripe_secret_key',
    pattern: /sk_live_[A-Za-z0-9]{24,}/g,
    severity: 'critical',
    description: 'Stripe Live Secret Key',
  },
  {
    name: 'stripe_test_key',
    pattern: /sk_test_[A-Za-z0-9]{24,}/g,
    severity: 'medium',
    description: 'Stripe Test Secret Key',
  },

  // Slack
  {
    name: 'slack_token',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: 'high',
    description: 'Slack Token',
  },

  // Generic high-entropy (likely secrets)
  {
    name: 'jwt_token',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    severity: 'high',
    description: 'JWT Token',
  },

  // Database URLs with credentials
  {
    name: 'database_url',
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/g,
    severity: 'critical',
    description: 'Database URL with credentials',
  },
];

/**
 * SecretLeakGuard - detects and blocks secret exposure
 */
export class SecretLeakGuard extends BaseGuard {
  private patterns: SecretPattern[];

  constructor(additionalPatterns: SecretPattern[] = []) {
    super();
    this.patterns = [...SECRET_PATTERNS, ...additionalPatterns];
  }

  name(): string {
    return 'secret_leak';
  }

  handles(): EventType[] {
    return ['patch_apply', 'tool_call'];
  }

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    return this.checkSync(event, policy);
  }

  checkSync(event: PolicyEvent, _policy: Policy): GuardResult {
    const data = event.data;
    let contentToCheck: string | undefined;

    // Get content to check based on event type
    if (data.type === 'patch') {
      contentToCheck = data.patchContent;
    } else if (data.type === 'tool') {
      // Check tool result for secrets
      contentToCheck =
        typeof data.result === 'string' ? data.result : JSON.stringify(data.result ?? '');
    }

    if (!contentToCheck) {
      return this.allow();
    }

    // Check for secret patterns
    const detected = this.detectSecrets(contentToCheck);

    if (detected.length > 0) {
      const highestSeverity = this.getHighestSeverity(detected);
      const secretNames = detected.map((s) => s.name).join(', ');

      return this.deny(
        `Detected potential secrets in output: ${secretNames}`,
        highestSeverity,
      );
    }

    return this.allow();
  }

  /**
   * Detect secrets in content
   */
  detectSecrets(content: string): SecretPattern[] {
    const detected: SecretPattern[] = [];

    for (const pattern of this.patterns) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;

      if (pattern.pattern.test(content)) {
        detected.push(pattern);
      }

      // Reset again after test
      pattern.pattern.lastIndex = 0;
    }

    return detected;
  }

  /**
   * Redact secrets from content
   */
  redact(content: string): string {
    let redacted = content;

    for (const pattern of this.patterns) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;

      redacted = redacted.replace(pattern.pattern, (match) => {
        // Show first 4 chars and last 4 chars, redact the middle
        if (match.length > 12) {
          return match.slice(0, 4) + '[REDACTED]' + match.slice(-4);
        }
        return '[REDACTED]';
      });

      // Reset again after replace
      pattern.pattern.lastIndex = 0;
    }

    return redacted;
  }

  /**
   * Get the highest severity from detected patterns
   */
  private getHighestSeverity(
    patterns: SecretPattern[],
  ): 'low' | 'medium' | 'high' | 'critical' {
    const severityOrder = ['low', 'medium', 'high', 'critical'] as const;

    let highest: (typeof severityOrder)[number] = 'low';

    for (const pattern of patterns) {
      if (
        severityOrder.indexOf(pattern.severity) >
        severityOrder.indexOf(highest)
      ) {
        highest = pattern.severity;
      }
    }

    return highest;
  }
}
