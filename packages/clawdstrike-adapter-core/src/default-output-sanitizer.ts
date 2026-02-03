import type { SecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import type { OutputSanitizer, RedactionInfo } from './sanitizer.js';

export class DefaultOutputSanitizer implements OutputSanitizer {
  private readonly engine: PolicyEngineLike;

  constructor(engine: PolicyEngineLike) {
    this.engine = engine;
  }

  sanitize<T>(output: T, context: SecurityContext): T {
    if (!this.engine.redactSecrets) {
      return output;
    }

    if (!this.containsSensitive(output)) {
      return output;
    }

    return this.redactValue(output, context, new WeakMap()) as T;
  }

  containsSensitive<T>(output: T): boolean {
    if (!this.engine.redactSecrets) {
      return false;
    }

    return this.containsSensitiveInternal(output, new WeakSet());
  }

  getRedactions<T>(output: T): RedactionInfo[] {
    const redactions: RedactionInfo[] = [];

    if (this.containsSensitive(output)) {
      redactions.push({
        type: 'secret',
        pattern: 'detected',
      });
    }

    return redactions;
  }

  private containsSensitiveInternal(output: unknown, seen: WeakSet<object>): boolean {
    if (output === null || output === undefined) {
      return false;
    }

    if (typeof output === 'string') {
      const redacted = this.engine.redactSecrets?.(output) ?? output;
      return redacted !== output;
    }

    if (typeof output !== 'object') {
      return false;
    }

    if (output instanceof Date) {
      return false;
    }

    if (seen.has(output)) {
      return false;
    }
    seen.add(output);

    if (Array.isArray(output)) {
      for (const item of output) {
        if (this.containsSensitiveInternal(item, seen)) {
          return true;
        }
      }
      return false;
    }

    for (const value of Object.values(output as Record<string, unknown>)) {
      if (this.containsSensitiveInternal(value, seen)) {
        return true;
      }
    }
    return false;
  }

  private redactValue(
    output: unknown,
    _context: SecurityContext,
    seen: WeakMap<object, unknown>,
  ): unknown {
    if (output === null || output === undefined) {
      return output;
    }

    if (typeof output === 'string') {
      return this.engine.redactSecrets ? this.engine.redactSecrets(output) : output;
    }

    if (typeof output !== 'object') {
      return output;
    }

    if (output instanceof Date) {
      return output;
    }

    const existing = seen.get(output);
    if (existing) {
      return existing;
    }

    if (Array.isArray(output)) {
      const arr: unknown[] = [];
      seen.set(output, arr);
      for (const item of output) {
        arr.push(this.redactValue(item, _context, seen));
      }
      return arr;
    }

    const obj: Record<string, unknown> = {};
    seen.set(output, obj);
    for (const [key, value] of Object.entries(output as Record<string, unknown>)) {
      obj[key] = this.redactValue(value, _context, seen);
    }
    return obj;
  }
}
