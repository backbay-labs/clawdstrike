export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type EvaluationMode = 'deterministic' | 'advisory' | 'audit';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface GuardToggles {
  forbidden_path?: boolean;
  egress?: boolean;
  secret_leak?: boolean;
  patch_integrity?: boolean;
  mcp_tool?: boolean;
}

export interface ClawdstrikeConfig {
  policy?: string;
  mode?: EvaluationMode;
  logLevel?: LogLevel;
  guards?: GuardToggles;
}

export type Policy = Record<string, unknown>;

export type EventType =
  | 'file_read'
  | 'file_write'
  | 'command_exec'
  | 'network_egress'
  | 'tool_call'
  | 'patch_apply'
  | 'secret_access'
  | 'custom';

export interface PolicyEvent {
  eventId: string;
  eventType: EventType;
  timestamp: string;
  sessionId?: string;
  data: EventData;
  metadata?: Record<string, unknown>;
}

export type EventData =
  | FileEventData
  | CommandEventData
  | NetworkEventData
  | ToolEventData
  | PatchEventData
  | SecretEventData
  | CustomEventData;

export interface FileEventData {
  type: 'file';
  path: string;
  content?: string;
  contentBase64?: string;
  contentHash?: string;
  operation: 'read' | 'write';
}

export interface CommandEventData {
  type: 'command';
  command: string;
  args: string[];
  workingDir?: string;
}

export interface NetworkEventData {
  type: 'network';
  host: string;
  port: number;
  protocol?: string;
  url?: string;
}

export interface ToolEventData {
  type: 'tool';
  toolName: string;
  parameters: Record<string, unknown>;
  result?: string;
}

export interface PatchEventData {
  type: 'patch';
  filePath: string;
  patchContent: string;
  patchHash?: string;
}

export interface SecretEventData {
  type: 'secret';
  secretName: string;
  scope: string;
}

export interface CustomEventData {
  type: 'custom';
  customType: string;
  [key: string]: unknown;
}

export interface Decision {
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  reason?: string;
  guard?: string;
  severity?: Severity;
  message?: string;
}
