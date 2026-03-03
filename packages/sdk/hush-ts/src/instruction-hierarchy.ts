/**
 * Instruction hierarchy enforcement (prompt security).
 *
 * Delegates to the WASM module for all detection and enforcement logic.
 */

import { getWasmModule } from "./crypto/backend.js";
import { toSnakeCaseKeys } from "./case-convert.js";

export enum InstructionLevel {
  Platform = 0,
  System = 1,
  User = 2,
  ToolOutput = 3,
  External = 4,
}

export type MessageRole = "system" | "user" | "assistant" | "tool";

export interface HierarchyMessage {
  id: string;
  level: InstructionLevel;
  role: MessageRole;
  content: string;
  source?: {
    type: "platform" | "developer" | "user" | "tool" | "external";
    identifier?: string;
    url?: string;
    trusted: boolean;
  };
}

export type ConflictSeverity = "low" | "medium" | "high" | "critical";
export type ConflictAction = "allow" | "warn" | "block" | "modify";

export interface HierarchyConflict {
  id: string;
  ruleId: string;
  severity: ConflictSeverity;
  messageId: string;
  description: string;
  action: ConflictAction;
  triggers: string[];
  modification?: { newContent: string; reason: string };
}

export interface EnforcementAction {
  type: "marker_added" | "content_modified" | "message_blocked" | "reminder_injected";
  messageId: string;
  description: string;
  before?: string;
  after?: string;
}

export interface HierarchyEnforcementResult {
  valid: boolean;
  messages: HierarchyMessage[];
  conflicts: HierarchyConflict[];
  actions: EnforcementAction[];
  stats: {
    messagesProcessed: number;
    conflictsDetected: number;
    messagesModified: number;
  };
}

export interface HierarchyEnforcerConfig {
  strictMode?: boolean;
  markers?: {
    systemStart?: string;
    systemEnd?: string;
    userStart?: string;
    userEnd?: string;
    toolStart?: string;
    toolEnd?: string;
    externalStart?: string;
    externalEnd?: string;
  };
  rules?: {
    blockOverrides?: boolean;
    blockImpersonation?: boolean;
    wrapExternalContent?: boolean;
    isolateToolInstructions?: boolean;
    neutralizeFakeDelimiters?: boolean;
  };
  reminders?: {
    enabled?: boolean;
    frequency?: number;
    text?: string;
  };
  context?: {
    maxContextBytes?: number;
  };
}

/** Map numeric InstructionLevel to the string variant expected by Rust serde. */
const LEVEL_NAMES: Record<number, string> = {
  [InstructionLevel.Platform]: "Platform",
  [InstructionLevel.System]: "System",
  [InstructionLevel.User]: "User",
  [InstructionLevel.ToolOutput]: "ToolOutput",
  [InstructionLevel.External]: "External",
};

/** Convert TS messages to Rust-compatible JSON (string level, snake_case source). */
function prepareMessages(messages: HierarchyMessage[]): unknown[] {
  return messages.map((m) => ({
    id: m.id,
    level: typeof m.level === "number" ? (LEVEL_NAMES[m.level] ?? "External") : m.level,
    role: m.role,
    content: m.content,
    ...(m.source ? { source: m.source } : {}),
  }));
}

export class InstructionHierarchyEnforcer {
  // biome-ignore lint/suspicious/noExplicitAny: WASM instance type is dynamic
  private inner: any;

  constructor(config?: HierarchyEnforcerConfig) {
    const wasm = getWasmModule();
    if (!wasm?.WasmInstructionHierarchyEnforcer) {
      throw new Error(
        "WASM not initialized. Call initWasm() before using InstructionHierarchyEnforcer.",
      );
    }
    this.inner = new wasm.WasmInstructionHierarchyEnforcer(
      config ? JSON.stringify(toSnakeCaseKeys(config)) : undefined,
    );
  }

  enforce(messages: HierarchyMessage[]): HierarchyEnforcementResult {
    return JSON.parse(this.inner.enforce(JSON.stringify(prepareMessages(messages))));
  }
}
