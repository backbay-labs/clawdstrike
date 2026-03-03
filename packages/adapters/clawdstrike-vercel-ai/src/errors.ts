export { ClawdstrikeBlockedError } from "@clawdstrike/adapter-core";

export type PromptSecurityBlockKind =
  | "instruction_hierarchy"
  | "jailbreak_detection"
  | "prompt_injection"
  | "output_sanitization";

export class ClawdstrikePromptSecurityError extends Error {
  readonly kind: PromptSecurityBlockKind;
  readonly details: Record<string, unknown>;

  constructor(
    kind: PromptSecurityBlockKind,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ClawdstrikePromptSecurityError";
    this.kind = kind;
    this.details = details;
  }
}
