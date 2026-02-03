import { describe, it, expect } from 'vitest';
import { DefaultOutputSanitizer } from './default-output-sanitizer.js';
import { createSecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';

describe('DefaultOutputSanitizer', () => {
  it('does not throw on cyclic outputs when checking sensitivity', () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
      redactSecrets: value => value,
    };

    const sanitizer = new DefaultOutputSanitizer(engine);
    const obj: any = { ok: true };
    obj.self = obj;

    expect(() => sanitizer.containsSensitive(obj)).not.toThrow();
    expect(sanitizer.containsSensitive(obj)).toBe(false);
  });

  it('preserves references when no redactions are needed', () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
      redactSecrets: value => value,
    };

    const sanitizer = new DefaultOutputSanitizer(engine);
    const context = createSecurityContext({ contextId: 'ctx-1', sessionId: 'sess-1' });
    const output = { nested: { msg: 'hello' }, list: ['a', 'b'] };

    const sanitized = sanitizer.sanitize(output, context);
    expect(sanitized).toBe(output);
  });

  it('redacts cyclic graphs without leaking original references', () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
      redactSecrets: value => value.replaceAll('SECRET', '[REDACTED]'),
    };

    const sanitizer = new DefaultOutputSanitizer(engine);
    const context = createSecurityContext({ contextId: 'ctx-2', sessionId: 'sess-2' });

    const output: any = { secret: 'SECRET' };
    output.self = output;

    const sanitized: any = sanitizer.sanitize(output, context);
    expect(sanitized).not.toBe(output);
    expect(sanitized.secret).toBe('[REDACTED]');
    expect(sanitized.self).toBe(sanitized);
    expect(sanitized.self).not.toBe(output);
  });
});

