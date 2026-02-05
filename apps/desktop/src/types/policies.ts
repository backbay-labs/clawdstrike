/**
 * Policy Types - SDR policy data model
 */

export type MergeStrategy = "replace" | "merge" | "deep_merge";

export interface Policy {
  version: string;
  name: string;
  description?: string;
  extends?: string;
  merge_strategy?: MergeStrategy;
  guards: GuardConfigs;
  custom_guards?: CustomGuardSpec[];
  settings?: PolicySettings;
}

export interface GuardConfigs {
  forbidden_path?: ForbiddenPathConfig;
  egress_allowlist?: EgressAllowlistConfig;
  secret_leak?: SecretLeakConfig;
  patch_integrity?: PatchIntegrityConfig;
  mcp_tool?: McpToolConfig;
  prompt_injection?: PromptInjectionConfig;
  jailbreak?: JailbreakConfig;
  custom?: CustomGuardSpec[];
}

export interface ForbiddenPathConfig {
  enabled: boolean;
  patterns: string[];
  allow_patterns?: string[];
}

export interface EgressAllowlistConfig {
  enabled: boolean;
  allowed_hosts: string[];
  blocked_hosts?: string[];
}

export interface SecretLeakConfig {
  enabled: boolean;
  patterns?: string[];
  entropy_threshold?: number;
}

export interface PatchIntegrityConfig {
  enabled: boolean;
  require_diff?: boolean;
  max_lines?: number;
}

export interface McpToolConfig {
  enabled: boolean;
  allowed_tools?: string[];
  blocked_tools?: string[];
}

export interface PromptInjectionConfig {
  enabled: boolean;
  threshold?: number;
}

export interface JailbreakConfig {
  enabled: boolean;
  threshold?: number;
}

export interface CustomGuardSpec {
  id: string;
  enabled: boolean;
  config: Record<string, unknown>;
  async?: AsyncGuardConfig;
}

export interface AsyncGuardConfig {
  timeout_ms?: number;
  execution_mode?: "parallel" | "sequential";
  cache?: {
    enabled: boolean;
    ttl_secs?: number;
  };
  rate_limit?: {
    max_requests: number;
    window_secs: number;
  };
  circuit_breaker?: {
    failure_threshold: number;
    recovery_time_secs: number;
  };
  retry?: {
    max_attempts: number;
    delay_ms: number;
  };
}

export interface PolicySettings {
  fail_fast?: boolean;
  log_level?: "debug" | "info" | "warn" | "error";
  audit?: {
    enabled: boolean;
    include_content?: boolean;
  };
}

export interface PolicyBundle {
  policy: Policy;
  policy_hash: string;
  signed_at?: string;
  signature?: string;
  public_key?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  path: string;
  message: string;
  code: string;
}

export interface ValidationWarning {
  path: string;
  message: string;
  suggestion?: string;
}

export type BuiltinRuleset = "default" | "strict" | "ai-agent" | "cicd" | "permissive";

export const BUILTIN_RULESETS: { id: BuiltinRuleset; name: string; description: string }[] = [
  { id: "default", name: "Default", description: "Balanced baseline policy" },
  { id: "strict", name: "Strict", description: "High-security with fail_fast enabled" },
  { id: "ai-agent", name: "AI Agent", description: "AI-specific protections" },
  { id: "cicd", name: "CI/CD", description: "CI/CD pipeline safeguards" },
  { id: "permissive", name: "Permissive", description: "Verbose logging mode" },
];
