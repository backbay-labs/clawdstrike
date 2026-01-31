/**
 * @hushclaw/openclaw - Patch Integrity Guard
 *
 * Detects dangerous code patterns in patches and file writes.
 */

import type {
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
  DangerousPattern,
} from '../types.js';
import { BaseGuard } from './types.js';

/**
 * Built-in dangerous pattern detection
 */
const DANGEROUS_PATTERNS: DangerousPattern[] = [
  // Shell injection patterns
  {
    name: 'curl_pipe_bash',
    pattern: /curl\s+[^|]*\|\s*(bash|sh|zsh)/gi,
    severity: 'critical',
    description: 'Curl piped to shell execution',
  },
  {
    name: 'wget_pipe_bash',
    pattern: /wget\s+[^|]*\|\s*(bash|sh|zsh)/gi,
    severity: 'critical',
    description: 'Wget piped to shell execution',
  },

  // Dangerous command patterns
  {
    name: 'rm_rf_root',
    pattern: /rm\s+(-rf?|--recursive)\s+[/\\]/gi,
    severity: 'critical',
    description: 'Recursive removal from root',
  },
  {
    name: 'fork_bomb',
    pattern: /:\(\)\{\s*:\|:&\s*\};:/g,
    severity: 'critical',
    description: 'Fork bomb',
  },
  {
    name: 'dd_disk_wipe',
    pattern: /dd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\//gi,
    severity: 'critical',
    description: 'DD disk wipe command',
  },

  // Dangerous JavaScript patterns
  {
    name: 'eval_usage',
    pattern: /\beval\s*\([^)]*\)/gi,
    severity: 'high',
    description: 'Eval function usage',
  },
  {
    name: 'new_function',
    pattern: /new\s+Function\s*\([^)]*\)/gi,
    severity: 'high',
    description: 'new Function constructor',
  },
  {
    name: 'document_write',
    pattern: /document\.write\s*\([^)]*\)/gi,
    severity: 'medium',
    description: 'document.write usage',
  },
  {
    name: 'inner_html_assignment',
    pattern: /\.innerHTML\s*=/gi,
    severity: 'medium',
    description: 'innerHTML assignment (XSS risk)',
  },

  // Dangerous Python patterns
  {
    name: 'python_exec',
    pattern: /\bexec\s*\([^)]*\)/gi,
    severity: 'high',
    description: 'Python exec usage',
  },
  {
    name: 'python_compile',
    pattern: /\bcompile\s*\([^)]*,\s*[^)]*,\s*['"]exec['"]\)/gi,
    severity: 'high',
    description: 'Python compile with exec mode',
  },
  {
    name: 'python_subprocess_shell',
    pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
    severity: 'high',
    description: 'Subprocess with shell=True',
  },
  {
    name: 'python_os_system',
    pattern: /os\.system\s*\([^)]*\)/gi,
    severity: 'high',
    description: 'os.system usage',
  },

  // Environment manipulation
  {
    name: 'env_manipulation',
    pattern: /process\.env\.[A-Z_]+\s*=\s*['"][^'"]+['"]/gi,
    severity: 'medium',
    description: 'Environment variable manipulation',
  },

  // Credential patterns in code
  {
    name: 'hardcoded_password',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi,
    severity: 'high',
    description: 'Hardcoded password',
  },
  {
    name: 'hardcoded_secret',
    pattern: /(?:secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'high',
    description: 'Hardcoded secret/API key',
  },

  // File permission changes
  {
    name: 'chmod_777',
    pattern: /chmod\s+(?:777|a\+rwx)/gi,
    severity: 'medium',
    description: 'Overly permissive chmod',
  },

  // Network exfiltration patterns
  {
    name: 'base64_encode_pipe',
    pattern: /base64\s*[^|]*\|\s*(?:curl|wget|nc)/gi,
    severity: 'high',
    description: 'Base64 encoded data exfiltration',
  },

  // SQL injection patterns
  {
    name: 'sql_concat',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^;]*\+\s*[a-zA-Z_]+/gi,
    severity: 'medium',
    description: 'Potential SQL injection (string concatenation)',
  },
];

/**
 * PatchIntegrityGuard - detects dangerous patterns in patches
 */
export class PatchIntegrityGuard extends BaseGuard {
  private patterns: DangerousPattern[];

  constructor(additionalPatterns: DangerousPattern[] = []) {
    super();
    this.patterns = [...DANGEROUS_PATTERNS, ...additionalPatterns];
  }

  name(): string {
    return 'patch_integrity';
  }

  handles(): EventType[] {
    return ['patch_apply', 'file_write', 'command_exec'];
  }

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    return this.checkSync(event, policy);
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    const data = event.data;
    let contentToCheck: string | undefined;

    // Get content to check based on event type
    if (data.type === 'patch') {
      contentToCheck = data.patchContent;
    } else if (data.type === 'command') {
      contentToCheck = `${data.command} ${data.args.join(' ')}`;

      // Also check against denied patterns from policy
      const deniedPatterns = policy.execution?.denied_patterns ?? [];
      for (const pattern of deniedPatterns) {
        try {
          const regex = new RegExp(pattern, 'gi');
          if (regex.test(contentToCheck)) {
            return this.deny(
              `Command matches denied pattern: ${pattern}`,
              'high',
            );
          }
        } catch {
          // Invalid regex, skip
        }
      }
    }

    if (!contentToCheck) {
      return this.allow();
    }

    // Check for dangerous patterns
    const detected = this.detectDangerousPatterns(contentToCheck);

    if (detected.length > 0) {
      const highestSeverity = this.getHighestSeverity(detected);
      const patternNames = detected.map((p) => p.name).join(', ');

      return this.deny(
        `Detected dangerous patterns: ${patternNames}`,
        highestSeverity,
      );
    }

    return this.allow();
  }

  /**
   * Detect dangerous patterns in content
   */
  detectDangerousPatterns(content: string): DangerousPattern[] {
    const detected: DangerousPattern[] = [];

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
   * Get the highest severity from detected patterns
   */
  private getHighestSeverity(
    patterns: DangerousPattern[],
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
