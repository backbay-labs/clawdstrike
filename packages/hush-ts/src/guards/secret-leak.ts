import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const OUTPUT_ACTION_TYPES = new Set(["output", "bash_output", "tool_result", "response"]);

export interface SecretLeakConfig {
  secrets?: string[];
  patterns?: Array<{
    name?: string;
    pattern: string;
    severity?: "info" | "warning" | "error" | "critical";
  }>;
  enabled?: boolean;
}

/**
 * Guard that detects secret values in output.
 */
export class SecretLeakGuard implements Guard {
  readonly name = "secret_leak";
  private secrets: string[];
  private patterns: Array<{ name?: string; regex: RegExp; severity: Severity }>;
  private enabled: boolean;

  constructor(config: SecretLeakConfig = {}) {
    // Filter out empty/whitespace-only secrets
    this.secrets = (config.secrets ?? []).filter((s) => s && s.trim());
    this.patterns = (config.patterns ?? [])
      .filter((entry) => entry && typeof entry.pattern === "string" && entry.pattern.trim().length > 0)
      .map((entry) => ({
        name: entry.name,
        regex: new RegExp(entry.pattern),
        severity: this.parseSeverity(entry.severity),
      }));
    this.enabled = config.enabled ?? true;
  }

  handles(action: GuardAction): boolean {
    if (action.actionType === "custom" && action.customType) {
      return OUTPUT_ACTION_TYPES.has(action.customType);
    }
    return false;
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    // Skip if disabled or no configured detectors
    if (!this.enabled || (this.secrets.length === 0 && this.patterns.length === 0)) {
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

    // Check configured regex patterns from policy YAML.
    for (const entry of this.patterns) {
      if (entry.regex.test(text)) {
        const hint = entry.name ?? entry.regex.source.slice(0, 24);
        return GuardResult.block(
          this.name,
          entry.severity,
          "Secret pattern matched in output"
        ).withDetails({
          secret_hint: hint,
          action_type: action.customType,
        });
      }
    }

    return GuardResult.allow(this.name);
  }

  private parseSeverity(value?: string): Severity {
    switch (value) {
      case "warning":
        return Severity.WARNING;
      case "error":
        return Severity.ERROR;
      case "critical":
        return Severity.CRITICAL;
      default:
        return Severity.CRITICAL;
    }
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
