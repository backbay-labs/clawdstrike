/**
 * @hushclaw/openclaw - Configuration
 *
 * Configuration handling and defaults for the HushClaw plugin.
 */

import type {
  HushClawConfig,
  EvaluationMode,
  LogLevel,
  GuardToggles,
} from './types.js';

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: Required<HushClawConfig> = {
  policy: 'hushclaw:ai-agent-minimal',
  mode: 'deterministic',
  logLevel: 'info',
  guards: {
    forbidden_path: true,
    egress: true,
    secret_leak: true,
    patch_integrity: true,
    mcp_tool: false,
  },
};

/**
 * Merge user config with defaults
 */
export function mergeConfig(
  userConfig: HushClawConfig = {},
): Required<HushClawConfig> {
  return {
    policy: userConfig.policy ?? DEFAULT_CONFIG.policy,
    mode: userConfig.mode ?? DEFAULT_CONFIG.mode,
    logLevel: userConfig.logLevel ?? DEFAULT_CONFIG.logLevel,
    guards: mergeGuardToggles(userConfig.guards),
  };
}

/**
 * Merge guard toggles with defaults
 */
function mergeGuardToggles(
  userGuards: GuardToggles = {},
): Required<GuardToggles> {
  const d = DEFAULT_CONFIG.guards;
  const u = userGuards;
  return {
    forbidden_path: u.forbidden_path ?? d.forbidden_path ?? true,
    egress: u.egress ?? d.egress ?? true,
    secret_leak: u.secret_leak ?? d.secret_leak ?? true,
    patch_integrity: u.patch_integrity ?? d.patch_integrity ?? true,
    mcp_tool: u.mcp_tool ?? d.mcp_tool ?? false,
  };
}

/**
 * Validate configuration values
 */
export function validateConfig(config: HushClawConfig): string[] {
  const errors: string[] = [];

  if (config.mode && !isValidMode(config.mode)) {
    errors.push(`Invalid mode: ${config.mode}. Must be one of: deterministic, advisory, audit`);
  }

  if (config.logLevel && !isValidLogLevel(config.logLevel)) {
    errors.push(`Invalid logLevel: ${config.logLevel}. Must be one of: debug, info, warn, error`);
  }

  return errors;
}

/**
 * Type guard for EvaluationMode
 */
function isValidMode(mode: string): mode is EvaluationMode {
  return ['deterministic', 'advisory', 'audit'].includes(mode);
}

/**
 * Type guard for LogLevel
 */
function isValidLogLevel(level: string): level is LogLevel {
  return ['debug', 'info', 'warn', 'error'].includes(level);
}

/**
 * Resolve built-in policy name to file path
 */
export function resolveBuiltinPolicy(name: string): string | null {
  const builtinPolicies: Record<string, string> = {
    'hushclaw:ai-agent-minimal': 'ai-agent-minimal.yaml',
    'hushclaw:strict': 'strict.yaml',
    'hushclaw:permissive': 'permissive.yaml',
    'hushclaw:default': 'ai-agent-minimal.yaml',
  };

  return builtinPolicies[name] ?? null;
}

/**
 * Check if a policy name is a built-in policy
 */
export function isBuiltinPolicy(name: string): boolean {
  return name.startsWith('hushclaw:');
}
