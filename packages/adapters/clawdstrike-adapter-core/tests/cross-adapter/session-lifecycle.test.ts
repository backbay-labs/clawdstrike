import { describe, it, expect } from 'vitest';
import {
  createFrameworkAdapter,
  type Decision,
  type FrameworkAdapter,
  type GenericToolCall,
  type PolicyEngineLike,
  type PolicyEvent,
  type SessionSummary,
} from '../../src/index.js';
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DENIED_TOOL = 'blocked_tool';

function createLifecycleEngine(): PolicyEngineLike {
  return {
    evaluate: async (event: PolicyEvent): Promise<Decision> => {
      const toolName =
        event.data.type === 'tool' ? event.data.toolName : undefined;

      if (toolName === DENIED_TOOL) {
        return {
          status: 'deny',
          reason_code: 'TEST_LIFECYCLE_DENY',
          guard: 'mock',
          reason: 'blocked for lifecycle test',
          message: 'blocked for lifecycle test',
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

async function runLifecycle(adapter: FrameworkAdapter): Promise<SessionSummary> {
  const ctx = adapter.createContext({ test: 'lifecycle' });

  // Tool call 1: allowed
  await adapter.interceptToolCall(ctx, makeToolCall('read_file'));

  // Tool call 2: denied
  await adapter.interceptToolCall(ctx, makeToolCall(DENIED_TOOL));

  // Tool call 3: allowed
  await adapter.interceptToolCall(ctx, makeToolCall('list_files'));

  return await adapter.finalizeContext(ctx);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Cross-Adapter Session Lifecycle', () => {
  it('all adapters report totalToolCalls >= 3 after three intercepts', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);

    for (const { label, adapter } of adapters) {
      const summary = await runLifecycle(adapter);
      expect(
        summary.totalToolCalls,
        `${label}: totalToolCalls should be >= 3`,
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it('all adapters report blockedToolCalls >= 1 after one denial', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);

    for (const { label, adapter } of adapters) {
      const summary = await runLifecycle(adapter);
      expect(
        summary.blockedToolCalls,
        `${label}: blockedToolCalls should be >= 1`,
      ).toBeGreaterThanOrEqual(1);
    }
  });

  it('all adapters include the denied tool name in toolsBlocked', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);

    for (const { label, adapter } of adapters) {
      const summary = await runLifecycle(adapter);
      expect(
        summary.toolsBlocked,
        `${label}: toolsBlocked should contain "${DENIED_TOOL}"`,
      ).toContain(DENIED_TOOL);
    }
  });

  it('all summaries have the same field names and types', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);
    const summaries: { label: string; summary: SessionSummary }[] = [];

    for (const { label, adapter } of adapters) {
      summaries.push({ label, summary: await runLifecycle(adapter) });
    }

    // Verify each summary has all required fields with correct types.
    for (const { label, summary } of summaries) {
      expect(typeof summary.sessionId, `${label}: sessionId`).toBe('string');
      expect(summary.startTime, `${label}: startTime`).toBeInstanceOf(Date);
      expect(summary.endTime, `${label}: endTime`).toBeInstanceOf(Date);
      expect(typeof summary.duration, `${label}: duration`).toBe('number');
      expect(typeof summary.totalToolCalls, `${label}: totalToolCalls`).toBe('number');
      expect(typeof summary.blockedToolCalls, `${label}: blockedToolCalls`).toBe('number');
      expect(typeof summary.warningsIssued, `${label}: warningsIssued`).toBe('number');
      expect(Array.isArray(summary.toolsUsed), `${label}: toolsUsed`).toBe(true);
      expect(Array.isArray(summary.toolsBlocked), `${label}: toolsBlocked`).toBe(true);
      expect(Array.isArray(summary.auditEvents), `${label}: auditEvents`).toBe(true);
      expect(typeof summary.policy, `${label}: policy`).toBe('string');
      expect(typeof summary.mode, `${label}: mode`).toBe('string');
    }

    // All summaries should have the same set of keys.
    const keySets = summaries.map(({ summary }) => Object.keys(summary).sort().join(','));
    const uniqueKeySets = new Set(keySets);
    expect(
      uniqueKeySets.size,
      'All summaries should have identical field names',
    ).toBe(1);
  });

  it('endTime is after startTime in all summaries', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);

    for (const { label, adapter } of adapters) {
      const summary = await runLifecycle(adapter);
      expect(
        summary.endTime.getTime(),
        `${label}: endTime should be >= startTime`,
      ).toBeGreaterThanOrEqual(summary.startTime.getTime());
    }
  });

  it('duration is non-negative in all summaries', async () => {
    const engine = createLifecycleEngine();
    const adapters = buildAdapters(engine);

    for (const { label, adapter } of adapters) {
      const summary = await runLifecycle(adapter);
      expect(
        summary.duration,
        `${label}: duration should be >= 0`,
      ).toBeGreaterThanOrEqual(0);
    }
  });
});
