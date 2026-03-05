import { describe, it, expect } from 'vitest';
import {
  createFrameworkAdapter,
  type Decision,
  type FrameworkAdapter,
  type PolicyEngineLike,
} from '../../src/index.js';
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockEngine(
  defaultDecision: Decision = { status: 'allow' },
): PolicyEngineLike {
  return {
    evaluate: async () => defaultDecision,
    redactSecrets: (v: string) => v,
  };
}

type AdapterEntry = { label: string; adapter: FrameworkAdapter };

function buildAdapters(): AdapterEntry[] {
  const engine = createMockEngine();

  return [
    { label: 'createFrameworkAdapter("claude")', adapter: createFrameworkAdapter('claude', engine) },
    { label: 'createFrameworkAdapter("vercel-ai")', adapter: createFrameworkAdapter('vercel-ai', engine) },
    { label: 'createFrameworkAdapter("openclaw")', adapter: createFrameworkAdapter('openclaw', engine) },
    { label: 'createFrameworkAdapter("langchain")', adapter: createFrameworkAdapter('langchain', engine) },
  ];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Cross-Adapter Interface Consistency', () => {
  const adapters = buildAdapters();

  describe.each(adapters)('$label', ({ adapter }) => {
    it('has a non-empty string name', () => {
      expect(typeof adapter.name).toBe('string');
      expect(adapter.name.length).toBeGreaterThan(0);
    });

    it('has a non-empty string version', () => {
      expect(typeof adapter.version).toBe('string');
      expect(adapter.version.length).toBeGreaterThan(0);
    });

    it('exposes all FrameworkAdapter methods', () => {
      const requiredMethods = [
        'initialize',
        'createContext',
        'interceptToolCall',
        'processOutput',
        'finalizeContext',
        'getEngine',
        'getHooks',
      ] as const;
      const optionalMethods = ['interceptInboundMessage'] as const;

      for (const method of requiredMethods) {
        expect(typeof (adapter as Record<string, unknown>)[method]).toBe('function');
      }

      for (const method of optionalMethods) {
        const candidate = (adapter as Record<string, unknown>)[method];
        if (candidate !== undefined) {
          expect(typeof candidate).toBe('function');
        }
      }
    });

    it('createContext() returns a SecurityContext with required fields', () => {
      const ctx = adapter.createContext({ testKey: 'testValue' });

      expect(typeof ctx.id).toBe('string');
      expect(ctx.id.length).toBeGreaterThan(0);

      expect(typeof ctx.sessionId).toBe('string');
      expect(ctx.sessionId.length).toBeGreaterThan(0);

      expect(ctx.createdAt).toBeInstanceOf(Date);

      expect(typeof ctx.checkCount).toBe('number');
      expect(ctx.checkCount).toBe(0);

      expect(typeof ctx.violationCount).toBe('number');
      expect(ctx.violationCount).toBe(0);
    });

    it('createContext() includes metadata', () => {
      const ctx = adapter.createContext({ custom: 42 });

      expect(ctx.metadata).toBeDefined();
      expect(ctx.metadata.custom).toBe(42);
    });

    it('getEngine() returns an object with an evaluate method', () => {
      const engine = adapter.getEngine();
      expect(engine).toBeDefined();
      expect(typeof engine.evaluate).toBe('function');
    });

    it('getHooks() returns an object', () => {
      const hooks = adapter.getHooks();
      expect(hooks).toBeDefined();
      expect(typeof hooks).toBe('object');
    });
  });
});
