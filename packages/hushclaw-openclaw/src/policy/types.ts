export interface EgressConfig {
  mode: 'allowlist' | 'denylist' | 'open';
  allowed_domains?: string[];
  denied_domains?: string[];
}

export interface FilesystemConfig {
  allowed_write_roots?: string[];
  forbidden_paths?: string[];
}

export interface ExecutionConfig {
  mode?: 'allowlist' | 'denylist';
  allowed_commands?: string[];
  denied_patterns?: string[];
}

export interface PolicyConfig {
  version?: string;
  extends?: string;
  egress?: EgressConfig;
  filesystem?: FilesystemConfig;
  execution?: ExecutionConfig;
  on_violation?: 'cancel' | 'warn' | 'log';
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export type ActionType = 'file_read' | 'file_write' | 'network_egress' | 'command_exec' | 'tool_call';

export interface PolicyEvent {
  type: ActionType;
  resource: string;
  params?: Record<string, unknown>;
  timestamp?: number;
}

export interface PolicyDecision {
  allowed: boolean;
  denied: boolean;
  reason?: string;
  guard?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}
