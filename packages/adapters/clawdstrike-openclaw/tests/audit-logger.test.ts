/**
 * @clawdstrike/openclaw - Audit Logger & Session Lifecycle Tests
 *
 * Tests for OpenClawAuditLogger (A5) and session lifecycle (A7).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { AuditEvent, AuditLogger, GenericToolCall } from '@clawdstrike/adapter-core';

import { OpenClawAuditLogger } from '../src/audit/adapter-logger.js';
import { OpenClawAdapter } from '../src/openclaw-adapter.js';
import { PolicyEngine } from '../src/policy/engine.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAuditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    type: 'tool_call_start',
    timestamp: new Date(),
    contextId: 'ctx-1',
    sessionId: 'sess-1',
    toolName: 'read_file',
    ...overrides,
  };
}

function makeToolCall(overrides: Partial<GenericToolCall> = {}): GenericToolCall {
  return {
    id: `tc-${Date.now()}`,
    name: 'read_file',
    parameters: { path: '/project/src/index.ts' },
    timestamp: new Date(),
    source: 'test',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// OpenClawAuditLogger unit tests
// ---------------------------------------------------------------------------

describe('OpenClawAuditLogger', () => {
  let logger: OpenClawAuditLogger;

  beforeEach(() => {
    logger = new OpenClawAuditLogger();
  });

  it('implements all AuditLogger methods', () => {
    const auditLogger: AuditLogger = logger;
    expect(typeof auditLogger.log).toBe('function');
    expect(typeof auditLogger.getSessionEvents).toBe('function');
    expect(typeof auditLogger.getContextEvents).toBe('function');
    expect(typeof auditLogger.export).toBe('function');
    expect(typeof auditLogger.prune).toBe('function');
  });

  it('log() stores events queryable by sessionId', async () => {
    const event1 = makeAuditEvent({ sessionId: 'sess-a', contextId: 'ctx-1' });
    const event2 = makeAuditEvent({ sessionId: 'sess-b', contextId: 'ctx-2' });
    const event3 = makeAuditEvent({ sessionId: 'sess-a', contextId: 'ctx-3' });

    await logger.log(event1);
    await logger.log(event2);
    await logger.log(event3);

    const sessA = await logger.getSessionEvents('sess-a');
    expect(sessA).toHaveLength(2);
    expect(sessA.map(e => e.id)).toContain(event1.id);
    expect(sessA.map(e => e.id)).toContain(event3.id);

    const sessB = await logger.getSessionEvents('sess-b');
    expect(sessB).toHaveLength(1);
    expect(sessB[0].id).toBe(event2.id);
  });

  it('log() stores events queryable by contextId', async () => {
    const event1 = makeAuditEvent({ contextId: 'ctx-x', sessionId: 'sess-1' });
    const event2 = makeAuditEvent({ contextId: 'ctx-y', sessionId: 'sess-1' });
    const event3 = makeAuditEvent({ contextId: 'ctx-x', sessionId: 'sess-2' });

    await logger.log(event1);
    await logger.log(event2);
    await logger.log(event3);

    const ctxX = await logger.getContextEvents('ctx-x');
    expect(ctxX).toHaveLength(2);

    const ctxY = await logger.getContextEvents('ctx-y');
    expect(ctxY).toHaveLength(1);
    expect(ctxY[0].id).toBe(event2.id);
  });

  describe('export()', () => {
    beforeEach(async () => {
      await logger.log(
        makeAuditEvent({
          id: 'evt-export-1',
          type: 'tool_call_start',
          sessionId: 'sess-export',
          contextId: 'ctx-export',
          toolName: 'write_file',
        }),
      );
      await logger.log(
        makeAuditEvent({
          id: 'evt-export-2',
          type: 'tool_call_blocked',
          sessionId: 'sess-export',
          contextId: 'ctx-export',
          toolName: 'rm_file',
          decision: { status: 'deny', guard: 'forbidden_path', reason: 'Blocked' },
        }),
      );
    });

    it('produces valid JSON', async () => {
      const json = await logger.export('json');
      const parsed = JSON.parse(json);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].id).toBe('evt-export-1');
      expect(parsed[1].id).toBe('evt-export-2');
    });

    it('produces valid JSONL', async () => {
      const jsonl = await logger.export('jsonl');
      const lines = jsonl.split('\n').filter(Boolean);
      expect(lines).toHaveLength(2);

      const first = JSON.parse(lines[0]);
      expect(first.id).toBe('evt-export-1');

      const second = JSON.parse(lines[1]);
      expect(second.id).toBe('evt-export-2');
    });

    it('produces valid CSV with headers', async () => {
      const csv = await logger.export('csv');
      const lines = csv.split('\n');
      expect(lines.length).toBeGreaterThanOrEqual(3); // header + 2 data rows

      const headers = lines[0].split(',');
      expect(headers).toContain('id');
      expect(headers).toContain('type');
      expect(headers).toContain('sessionId');
      expect(headers).toContain('toolName');
      expect(headers).toContain('decision');

      // Second data row should have 'deny' decision
      const blockedRow = lines[2].split(',');
      expect(blockedRow).toContain('deny');
    });
  });

  describe('prune()', () => {
    it('removes events older than the given date', async () => {
      const oldDate = new Date('2024-01-01T00:00:00Z');
      const newDate = new Date('2025-06-01T00:00:00Z');
      const cutoff = new Date('2025-01-01T00:00:00Z');

      await logger.log(makeAuditEvent({ id: 'old-1', timestamp: oldDate, sessionId: 'sess-prune' }));
      await logger.log(makeAuditEvent({ id: 'old-2', timestamp: oldDate, sessionId: 'sess-prune' }));
      await logger.log(makeAuditEvent({ id: 'new-1', timestamp: newDate, sessionId: 'sess-prune' }));

      const pruned = await logger.prune(cutoff);
      expect(pruned).toBe(2);

      const remaining = await logger.getSessionEvents('sess-prune');
      expect(remaining).toHaveLength(1);
      expect(remaining[0].id).toBe('new-1');
    });

    it('returns 0 when nothing to prune', async () => {
      await logger.log(makeAuditEvent({ timestamp: new Date() }));
      const pruned = await logger.prune(new Date('2020-01-01'));
      expect(pruned).toBe(0);
    });
  });

  it('respects maxEvents limit', async () => {
    const small = new OpenClawAuditLogger({ maxEvents: 3 });

    for (let i = 0; i < 5; i++) {
      await small.log(makeAuditEvent({ id: `evt-${i}`, sessionId: 'sess-cap' }));
    }

    const events = await small.getSessionEvents('sess-cap');
    expect(events).toHaveLength(3);
    // Should keep the most recent 3
    expect(events.map(e => e.id)).toEqual(['evt-2', 'evt-3', 'evt-4']);
  });
});

// ---------------------------------------------------------------------------
// OpenClawAdapter audit wiring
// ---------------------------------------------------------------------------

describe('OpenClawAdapter audit wiring', () => {
  it('uses OpenClawAuditLogger by default', () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });
    const adapter = new OpenClawAdapter(engine);
    const logger = adapter.getAuditLogger();
    expect(logger).toBeInstanceOf(OpenClawAuditLogger);
  });

  it('accepts a custom audit logger', () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });
    const custom = new OpenClawAuditLogger({ maxEvents: 100 });
    const adapter = new OpenClawAdapter(engine, { auditLogger: custom });
    expect(adapter.getAuditLogger()).toBe(custom);
  });
});

// ---------------------------------------------------------------------------
// Session lifecycle: createContext -> interceptToolCall -> processOutput -> finalizeContext
// ---------------------------------------------------------------------------

describe('Session lifecycle', () => {
  let adapter: OpenClawAdapter;
  let auditLogger: OpenClawAuditLogger;

  beforeEach(() => {
    auditLogger = new OpenClawAuditLogger();
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });
    adapter = new OpenClawAdapter(engine, { auditLogger });
  });

  it('full lifecycle: createContext -> interceptToolCall -> processOutput -> finalizeContext', async () => {
    // 1) createContext
    const ctx = adapter.createContext({ userId: 'test-user' });
    expect(ctx.id).toBeDefined();
    expect(ctx.sessionId).toBeDefined();
    expect(ctx.metadata).toMatchObject({ framework: 'openclaw', userId: 'test-user' });

    // 2) interceptToolCall - allowed action
    const toolCall = makeToolCall({ name: 'read_file', parameters: { path: '/project/src/index.ts' } });
    const result = await adapter.interceptToolCall(ctx, toolCall);
    expect(result.proceed).toBe(true);
    expect(result.decision.status).toBe('allow');

    // 3) processOutput
    const output = await adapter.processOutput(ctx, toolCall, 'file contents here');
    expect(output.output).toBe('file contents here');
    expect(output.modified).toBe(false);

    // 4) finalizeContext
    const summary = await adapter.finalizeContext(ctx);
    expect(summary.sessionId).toBe(ctx.sessionId);
    expect(summary.totalToolCalls).toBe(1);
    expect(summary.blockedToolCalls).toBe(0);
    expect(summary.toolsUsed).toContain('read_file');
    expect(summary.toolsBlocked).toHaveLength(0);
    expect(summary.auditEvents.length).toBeGreaterThan(0);
    expect(summary.startTime).toBeInstanceOf(Date);
    expect(summary.endTime).toBeInstanceOf(Date);
    expect(summary.duration).toBeGreaterThanOrEqual(0);
  });

  it('records blocked tool calls in the session summary', async () => {
    const ctx = adapter.createContext();

    // Attempt to read a forbidden path
    const toolCall = makeToolCall({
      name: 'read_file',
      parameters: { path: `${require('os').homedir()}/.ssh/id_rsa` },
    });
    const result = await adapter.interceptToolCall(ctx, toolCall);
    expect(result.proceed).toBe(false);
    expect(result.decision.status).toBe('deny');

    const summary = await adapter.finalizeContext(ctx);
    expect(summary.totalToolCalls).toBe(1);
    expect(summary.blockedToolCalls).toBe(1);
    expect(summary.toolsBlocked).toContain('read_file');
  });

  it('audit logger receives events from the adapter lifecycle', async () => {
    const ctx = adapter.createContext();

    const toolCall = makeToolCall({ name: 'list_dir', parameters: { path: '/project' } });
    await adapter.interceptToolCall(ctx, toolCall);
    await adapter.processOutput(ctx, toolCall, ['file1.ts', 'file2.ts']);

    const events = await auditLogger.getSessionEvents(ctx.sessionId);
    expect(events.length).toBeGreaterThan(0);

    const types = events.map(e => e.type);
    expect(types).toContain('tool_call_start');
    expect(types).toContain('tool_call_end');
  });

  it('multiple tool calls accumulate in session summary', async () => {
    const ctx = adapter.createContext();

    // First call - allowed
    const tc1 = makeToolCall({ name: 'read_file', parameters: { path: '/project/README.md' } });
    await adapter.interceptToolCall(ctx, tc1);
    await adapter.processOutput(ctx, tc1, '# README');

    // Second call - also allowed
    const tc2 = makeToolCall({ name: 'list_dir', parameters: { path: '/project' } });
    await adapter.interceptToolCall(ctx, tc2);
    await adapter.processOutput(ctx, tc2, ['src/', 'tests/']);

    const summary = await adapter.finalizeContext(ctx);
    expect(summary.totalToolCalls).toBe(2);
    expect(summary.blockedToolCalls).toBe(0);
    expect(summary.toolsUsed).toContain('read_file');
    expect(summary.toolsUsed).toContain('list_dir');
  });

  it('warnings are counted in session summary', async () => {
    // Use advisory mode so denials become warnings
    const advisoryLogger = new OpenClawAuditLogger();
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'advisory',
      logLevel: 'error',
    });
    const advisoryAdapter = new OpenClawAdapter(engine, {
      auditLogger: advisoryLogger,
      blockOnViolation: false,
    });

    const ctx = advisoryAdapter.createContext();

    const toolCall = makeToolCall({
      name: 'read_file',
      parameters: { path: `${require('os').homedir()}/.ssh/id_rsa` },
    });
    await advisoryAdapter.interceptToolCall(ctx, toolCall);

    const summary = await advisoryAdapter.finalizeContext(ctx);
    expect(summary.warningsIssued).toBeGreaterThanOrEqual(1);
  });
});
