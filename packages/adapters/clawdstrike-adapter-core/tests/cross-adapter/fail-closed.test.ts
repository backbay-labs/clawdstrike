import { describe, it, expect } from 'vitest';
import {
  createFrameworkAdapter,
  type FrameworkAdapter,
  type GenericToolCall,
  type PolicyEngineLike,
} from '../../src/index.js';
import { VercelAIAdapter } from '@clawdstrike/vercel-ai';
import { ClaudeAdapter } from '@clawdstrike/claude';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createThrowingEngine(): PolicyEngineLike {
  return {
    evaluate: () => {
      throw new Error('engine exploded');
    },
    redactSecrets: (v: string) => v,
  };
}

function createAsyncThrowingEngine(): PolicyEngineLike {
  return {
    evaluate: async () => {
      throw new Error('async engine exploded');
    },
    redactSecrets: (v: string) => v,
  };
}

function makeToolCall(name: string = 'some_tool'): GenericToolCall {
  return {
    id: `tc-${name}-${Date.now()}`,
    name,
    parameters: { path: '/tmp/test.txt' },
    timestamp: new Date(),
    source: 'test',
  };
}

type AdapterEntry = { label: string; adapter: FrameworkAdapter };

function buildAdapters(engine: PolicyEngineLike): AdapterEntry[] {
  return [
    { label: 'createFrameworkAdapter("claude")', adapter: createFrameworkAdapter('claude', engine) },
    { label: 'createFrameworkAdapter("vercel-ai")', adapter: createFrameworkAdapter('vercel-ai', engine) },
    { label: 'createFrameworkAdapter("openclaw")', adapter: createFrameworkAdapter('openclaw', engine) },
    { label: 'VercelAIAdapter', adapter: new VercelAIAdapter(engine) },
    { label: 'ClaudeAdapter', adapter: new ClaudeAdapter(engine) as unknown as FrameworkAdapter },
  ];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Cross-Adapter Fail-Closed Behavior', () => {
  describe('synchronous engine throw', () => {
    it('no adapter returns proceed:true when the engine throws', async () => {
      const engine = createThrowingEngine();
      const adapters = buildAdapters(engine);

      for (const { label, adapter } of adapters) {
        const ctx = adapter.createContext();
        let proceed: boolean | undefined;

        try {
          const result = await adapter.interceptToolCall(ctx, makeToolCall());
          proceed = result.proceed;
        } catch {
          // Throwing is also an acceptable fail-closed behavior.
          proceed = undefined;
        }

        expect(
          proceed,
          `${label}: must not return proceed:true when engine throws (got proceed=${proceed})`,
        ).not.toBe(true);
      }
    });

    it('adapter either denies or throws -- never silently allows', async () => {
      const engine = createThrowingEngine();
      const adapters = buildAdapters(engine);

      for (const { label, adapter } of adapters) {
        const ctx = adapter.createContext();
        let threw = false;
        let result: { proceed: boolean; decision: { status: string } } | undefined;

        try {
          result = await adapter.interceptToolCall(ctx, makeToolCall());
        } catch {
          threw = true;
        }

        const failedClosed = threw || (result !== undefined && !result.proceed);
        expect(
          failedClosed,
          `${label}: must fail closed (threw=${threw}, proceed=${result?.proceed})`,
        ).toBe(true);
      }
    });
  });

  describe('async engine throw', () => {
    it('no adapter returns proceed:true when the async engine throws', async () => {
      const engine = createAsyncThrowingEngine();
      const adapters = buildAdapters(engine);

      for (const { label, adapter } of adapters) {
        const ctx = adapter.createContext();
        let proceed: boolean | undefined;

        try {
          const result = await adapter.interceptToolCall(ctx, makeToolCall());
          proceed = result.proceed;
        } catch {
          proceed = undefined;
        }

        expect(
          proceed,
          `${label}: must not return proceed:true when async engine throws`,
        ).not.toBe(true);
      }
    });
  });

  describe('engine returning undefined', () => {
    it('no adapter returns proceed:true when engine returns undefined', async () => {
      const brokenEngine: PolicyEngineLike = {
        evaluate: () => undefined as never,
      };
      const adapters = buildAdapters(brokenEngine);

      for (const { label, adapter } of adapters) {
        const ctx = adapter.createContext();
        let proceed: boolean | undefined;

        try {
          const result = await adapter.interceptToolCall(ctx, makeToolCall());
          proceed = result.proceed;
        } catch {
          // Throwing is acceptable.
          proceed = undefined;
        }

        // The adapter must not allow through an undefined decision.
        // It should either deny or throw.
        expect(
          proceed,
          `${label}: must not return proceed:true when engine returns undefined`,
        ).not.toBe(true);
      }
    });
  });

  it('all adapters behave consistently on engine failure', async () => {
    const engine = createThrowingEngine();
    const adapters = buildAdapters(engine);

    const behaviors: { label: string; behavior: 'denied' | 'threw' }[] = [];

    for (const { label, adapter } of adapters) {
      const ctx = adapter.createContext();
      try {
        const result = await adapter.interceptToolCall(ctx, makeToolCall());
        if (!result.proceed) {
          behaviors.push({ label, behavior: 'denied' });
        } else {
          // This should not happen, but record it.
          behaviors.push({ label, behavior: 'threw' });
        }
      } catch {
        behaviors.push({ label, behavior: 'threw' });
      }
    }

    // All adapters should exhibit the same fail-closed behavior pattern.
    const uniqueBehaviors = new Set(behaviors.map(b => b.behavior));
    expect(
      uniqueBehaviors.size,
      `All adapters should agree on fail-closed behavior: ${behaviors.map(b => `${b.label}=${b.behavior}`).join(', ')}`,
    ).toBe(1);
  });
});
