import { describe, it, expect } from 'vitest';
import {
  createFrameworkAdapter,
  type Decision,
  type FrameworkAdapter,
  type GenericToolCall,
  type PolicyEngineLike,
  type PolicyEvent,
} from '../../src/index.js';
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DENIED_TOOL = 'dangerous_tool';
const WARNING_TOOL = 'risky_tool';

function createRoutingEngine(): PolicyEngineLike {
  return {
    evaluate: async (event: PolicyEvent): Promise<Decision> => {
      const toolName =
        event.data.type === 'tool' ? event.data.toolName : undefined;

      if (toolName === DENIED_TOOL) {
        return {
          status: 'deny',
          reason_code: 'TEST_DENY',
          guard: 'mock',
          reason: 'tool denied for test',
          message: 'tool denied for test',
        };
      }

      if (toolName === WARNING_TOOL) {
        return {
          status: 'warn',
          reason_code: 'TEST_WARN',
          guard: 'mock',
          reason: 'tool warned for test',
          message: 'tool warned for test',
        };
      }

      return { status: 'allow' };
    },
    redactSecrets: (v: string) => v,
  };
}

function makeToolCall(name: string): GenericToolCall {
  return {
    id: `tc-${name}-${Date.now()}`,
    name,
    parameters: {},
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
  ];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Cross-Adapter Decision Parity', () => {
  it('all adapters return proceed:true for an allowed tool call', async () => {
    const engine = createRoutingEngine();
    const adapters = buildAdapters(engine);
    const results: { label: string; proceed: boolean; status: string }[] = [];

    for (const { label, adapter } of adapters) {
      const ctx = adapter.createContext();
      const result = await adapter.interceptToolCall(ctx, makeToolCall('safe_tool'));
      results.push({ label, proceed: result.proceed, status: result.decision.status });
    }

    for (const r of results) {
      expect(r.proceed, `${r.label} should proceed`).toBe(true);
      expect(r.status, `${r.label} decision should be allow`).toBe('allow');
    }

    // Verify cross-adapter consistency: all proceed values are equal.
    const proceedValues = new Set(results.map(r => r.proceed));
    expect(proceedValues.size).toBe(1);
  });

  it('all adapters return proceed:false for a denied tool call', async () => {
    const engine = createRoutingEngine();
    const adapters = buildAdapters(engine);
    const results: { label: string; proceed: boolean; status: string }[] = [];

    for (const { label, adapter } of adapters) {
      const ctx = adapter.createContext();
      const result = await adapter.interceptToolCall(ctx, makeToolCall(DENIED_TOOL));
      results.push({ label, proceed: result.proceed, status: result.decision.status });
    }

    for (const r of results) {
      expect(r.proceed, `${r.label} should not proceed`).toBe(false);
      expect(r.status, `${r.label} decision should be deny`).toBe('deny');
    }

    const proceedValues = new Set(results.map(r => r.proceed));
    expect(proceedValues.size).toBe(1);
  });

  it('all adapters return proceed:true with warning for a warned tool call', async () => {
    const engine = createRoutingEngine();
    const adapters = buildAdapters(engine);
    const results: { label: string; proceed: boolean; status: string; warning?: string }[] = [];

    for (const { label, adapter } of adapters) {
      const ctx = adapter.createContext();
      const result = await adapter.interceptToolCall(ctx, makeToolCall(WARNING_TOOL));
      results.push({
        label,
        proceed: result.proceed,
        status: result.decision.status,
        warning: result.warning,
      });
    }

    for (const r of results) {
      expect(r.proceed, `${r.label} should proceed on warn`).toBe(true);
      expect(r.status, `${r.label} decision should be warn`).toBe('warn');
      expect(r.warning, `${r.label} should include a warning message`).toBeDefined();
    }

    const proceedValues = new Set(results.map(r => r.proceed));
    expect(proceedValues.size).toBe(1);

    const statusValues = new Set(results.map(r => r.status));
    expect(statusValues.size).toBe(1);
  });

  it('decision status is identical across all adapters for each scenario', async () => {
    const engine = createRoutingEngine();
    const adapters = buildAdapters(engine);

    const scenarios = [
      { name: 'allowed', tool: 'safe_tool' },
      { name: 'denied', tool: DENIED_TOOL },
      { name: 'warned', tool: WARNING_TOOL },
    ];

    for (const scenario of scenarios) {
      const statuses: string[] = [];
      const proceeds: boolean[] = [];

      for (const { adapter } of adapters) {
        const ctx = adapter.createContext();
        const result = await adapter.interceptToolCall(ctx, makeToolCall(scenario.tool));
        statuses.push(result.decision.status);
        proceeds.push(result.proceed);
      }

      // All adapters agree on the decision status.
      expect(
        new Set(statuses).size,
        `Scenario "${scenario.name}": all adapters must agree on decision status`,
      ).toBe(1);

      // All adapters agree on proceed.
      expect(
        new Set(proceeds).size,
        `Scenario "${scenario.name}": all adapters must agree on proceed`,
      ).toBe(1);
    }
  });
});
