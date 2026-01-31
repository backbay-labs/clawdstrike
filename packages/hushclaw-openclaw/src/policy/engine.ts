/**
 * @hushclaw/openclaw - Policy Engine
 *
 * Core policy evaluation engine that coordinates guards.
 */

import { watch } from 'chokidar';
import type {
  Policy,
  PolicyEvent,
  Decision,
  EvaluationMode,
  HushClawConfig,
  PolicyLintResult,
  Logger,
} from '../types.js';
import { loadPolicy, resolvePolicyPath, PolicyLoadError } from './loader.js';
import { validatePolicy } from './validator.js';
import { mergeConfig } from '../config.js';
import {
  ForbiddenPathGuard,
  EgressGuard,
  SecretLeakGuard,
  PatchIntegrityGuard,
} from '../guards/index.js';
import type { Guard } from '../guards/index.js';

/**
 * Policy Engine - coordinates guards and policy evaluation
 */
export class PolicyEngine {
  private policy: Policy;
  private policyPath: string;
  private mode: EvaluationMode;
  private guards: Guard[];
  private watcher: ReturnType<typeof watch> | null = null;
  private logger: Logger;

  constructor(config: HushClawConfig, logger?: Logger) {
    const mergedConfig = mergeConfig(config);
    this.mode = mergedConfig.mode;
    this.policyPath = mergedConfig.policy;
    this.logger = logger ?? createDefaultLogger(mergedConfig.logLevel);

    // Load initial policy
    this.policy = this.loadPolicyInternal(mergedConfig.policy);

    // Initialize guards based on config
    this.guards = this.initializeGuards(mergedConfig);

    this.logger.info(`PolicyEngine initialized with mode: ${this.mode}`);
  }

  /**
   * Evaluate an event against the policy
   */
  async evaluate(event: PolicyEvent): Promise<Decision> {
    this.logger.debug(`Evaluating event: ${event.eventType}`, event.eventId);

    // Run through all enabled guards
    for (const guard of this.guards) {
      if (!guard.isEnabled()) {
        continue;
      }

      // Check if guard handles this event type
      const handles = guard.handles();
      if (handles.length > 0 && !handles.includes(event.eventType)) {
        continue;
      }

      const result = await guard.check(event, this.policy);

      if (result.status === 'deny') {
        this.logger.warn(`Guard ${result.guard} denied event: ${result.reason}`);
        return this.applyMode({
          allowed: false,
          denied: true,
          warn: false,
          reason: result.reason,
          guard: result.guard,
          severity: result.severity,
        });
      }

      if (result.status === 'warn') {
        this.logger.info(`Guard ${result.guard} warning: ${result.reason}`);
        // Continue checking other guards but remember the warning
      }
    }

    return { allowed: true, denied: false, warn: false };
  }

  /**
   * Evaluate synchronously (for use in hooks where async is inconvenient)
   */
  evaluateSync(event: PolicyEvent): Decision {
    // Run synchronous checks only
    for (const guard of this.guards) {
      if (!guard.isEnabled()) {
        continue;
      }

      const handles = guard.handles();
      if (handles.length > 0 && !handles.includes(event.eventType)) {
        continue;
      }

      // Use synchronous check if available
      const result = guard.checkSync?.(event, this.policy);
      if (!result) continue;

      if (result.status === 'deny') {
        return this.applyMode({
          allowed: false,
          denied: true,
          warn: false,
          reason: result.reason,
          guard: result.guard,
          severity: result.severity,
        });
      }
    }

    return { allowed: true, denied: false, warn: false };
  }

  /**
   * Redact secrets from a string
   */
  redactSecrets(content: string): string {
    const secretGuard = this.guards.find(
      (g) => g.name() === 'secret_leak'
    ) as SecretLeakGuard | undefined;

    if (!secretGuard) {
      return content;
    }

    return secretGuard.redact(content);
  }

  /**
   * Lint a policy file
   */
  async lintPolicy(policyPath: string): Promise<PolicyLintResult> {
    try {
      const policy = loadPolicy(policyPath);
      return validatePolicy(policy);
    } catch (error) {
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : String(error)],
        warnings: [],
      };
    }
  }

  /**
   * Get currently loaded policy
   */
  getPolicy(): Policy {
    return this.policy;
  }

  /**
   * Reload policy from file
   */
  reloadPolicy(): void {
    this.policy = this.loadPolicyInternal(this.policyPath);
    this.logger.info('Policy reloaded');
  }

  /**
   * Watch policy file for changes and auto-reload
   */
  async watchPolicy(policyPath?: string): Promise<void> {
    const pathToWatch = policyPath ?? this.policyPath;
    const resolvedPath = resolvePolicyPath(pathToWatch);

    this.watcher = watch(resolvedPath, {
      persistent: true,
      ignoreInitial: true,
    });

    this.watcher.on('change', () => {
      this.logger.info(`Policy file changed: ${resolvedPath}`);
      try {
        this.policy = this.loadPolicyInternal(pathToWatch);
        this.logger.info('Policy hot-reloaded successfully');
      } catch (error) {
        this.logger.error(
          `Failed to reload policy: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    });

    this.logger.debug(`Watching policy file: ${resolvedPath}`);
  }

  /**
   * Stop watching policy file
   */
  stopWatching(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
      this.logger.debug('Stopped watching policy file');
    }
  }

  /**
   * Get list of enabled guard names
   */
  enabledGuards(): string[] {
    return this.guards
      .filter((g) => g.isEnabled())
      .map((g) => g.name());
  }

  /**
   * Apply evaluation mode to a decision
   */
  private applyMode(decision: Decision): Decision {
    if (this.mode === 'audit') {
      this.logger.info('[AUDIT]', decision);
      return { allowed: true, denied: false, warn: false };
    }

    if (this.mode === 'advisory' && decision.denied) {
      return {
        ...decision,
        allowed: true,
        denied: false,
        warn: true,
        message: `[ADVISORY] Would deny: ${decision.reason}`,
      };
    }

    return decision;
  }

  /**
   * Internal policy loading with error handling
   */
  private loadPolicyInternal(policyPath: string): Policy {
    try {
      return loadPolicy(policyPath);
    } catch (error) {
      if (error instanceof PolicyLoadError) {
        this.logger.warn(`Failed to load policy: ${error.message}, using empty policy`);
        return {};
      }
      throw error;
    }
  }

  /**
   * Initialize guards based on configuration
   */
  private initializeGuards(config: Required<HushClawConfig>): Guard[] {
    const guards: Guard[] = [];

    if (config.guards.forbidden_path) {
      guards.push(new ForbiddenPathGuard());
    }

    if (config.guards.egress) {
      guards.push(new EgressGuard());
    }

    if (config.guards.secret_leak) {
      guards.push(new SecretLeakGuard());
    }

    if (config.guards.patch_integrity) {
      guards.push(new PatchIntegrityGuard());
    }

    return guards;
  }
}

/**
 * Create a default console logger
 */
function createDefaultLogger(level: string): Logger {
  const levels = ['debug', 'info', 'warn', 'error'];
  const minLevel = levels.indexOf(level);

  return {
    debug: (...args) => {
      if (minLevel <= 0) console.debug('[hushclaw]', ...args);
    },
    info: (...args) => {
      if (minLevel <= 1) console.info('[hushclaw]', ...args);
    },
    warn: (...args) => {
      if (minLevel <= 2) console.warn('[hushclaw]', ...args);
    },
    error: (...args) => {
      if (minLevel <= 3) console.error('[hushclaw]', ...args);
    },
  };
}
