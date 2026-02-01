import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const OUTPUT_ACTION_TYPES = new Set(["output", "bash_output", "tool_result", "response"]);

export interface SecretLeakConfig {
  secrets?: string[];
  enabled?: boolean;
}

/**
 * Guard that detects secret values in output.
 */
export class SecretLeakGuard implements Guard {
  readonly name = "secret_leak";
  private secrets: string[];
  private enabled: boolean;

  constructor(config: SecretLeakConfig = {}) {
    // Filter out empty/whitespace-only secrets
    this.secrets = (config.secrets ?? []).filter((s) => s && s.trim());
    this.enabled = config.enabled ?? true;
  }

  handles(action: GuardAction): boolean {
    if (action.actionType === "custom" && action.customType) {
      return OUTPUT_ACTION_TYPES.has(action.customType);
    }
    return false;
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    // Skip if disabled or no secrets configured
    if (!this.enabled || this.secrets.length === 0) {
      return GuardResult.allow(this.name);
    }

    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const text = this.extractText(action.customData);
    if (!text) {
      return GuardResult.allow(this.name);
    }

    // Check for any secret in the output
    for (const secret of this.secrets) {
      if (text.includes(secret)) {
        // Create hint (first 4 chars + "...")
        const hint = secret.length > 4 ? secret.slice(0, 4) + "..." : secret.slice(0, 2) + "...";

        return GuardResult.block(
          this.name,
          Severity.CRITICAL,
          "Secret value exposed in output"
        ).withDetails({
          secret_hint: hint,
          action_type: action.customType,
        });
      }
    }

    return GuardResult.allow(this.name);
  }

  private extractText(data?: Record<string, unknown>): string {
    if (!data) return "";

    // Check common content field names
    for (const key of ["content", "output", "result", "error", "text"]) {
      const value = data[key];
      if (typeof value === "string" && value) {
        return value;
      }
    }

    return "";
  }
}
