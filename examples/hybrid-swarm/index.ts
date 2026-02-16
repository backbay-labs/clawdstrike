/**
 * Hybrid Swarm Example
 *
 * Full integration demonstrating:
 * - Adapter-based tool interception (ClaudeAdapter, VercelAIAdapter, FrameworkToolBoundary)
 * - hushd attribution via direct /api/v1/check calls
 * - SSE live event monitoring
 * - Audit queries for per-agent and per-session visibility
 *
 * Prerequisites:
 *   cargo run -p hushd -- --ruleset strict
 */

import { ClaudeAdapter } from '@clawdstrike/claude';
import { VercelAIAdapter } from '@clawdstrike/vercel-ai';
import {
  FrameworkToolBoundary,
  wrapFrameworkToolDispatcher,
  ClawdstrikeBlockedError,
} from '@clawdstrike/adapter-core';
import { createStrikeCell } from '@clawdstrike/engine-remote';

const HUSHD_URL = process.env.HUSHD_URL ?? 'http://127.0.0.1:9876';
const SESSION_ID = `hybrid-${Date.now()}`;

// -- Helpers ---------------------------------------------------------------

async function healthCheck(): Promise<void> {
  const res = await fetch(`${HUSHD_URL}/health`);
  if (!res.ok) throw new Error(`hushd health check failed: ${res.status}`);
  console.log('[ok] hushd is running\n');
}

interface CheckResult {
  allowed: boolean;
  guard: string;
  severity: string;
  message: string;
}

async function hushdCheck(
  agentId: string,
  actionType: string,
  target: string,
  content?: string,
): Promise<CheckResult> {
  const body: Record<string, unknown> = {
    action_type: actionType,
    target,
    session_id: SESSION_ID,
    agent_id: agentId,
  };
  if (content !== undefined) body.content = content;

  const res = await fetch(`${HUSHD_URL}/api/v1/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return (await res.json()) as CheckResult;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function status(allowed: boolean): string {
  return allowed ? 'ALLOWED' : 'BLOCKED';
}

// -- SSE Listener ----------------------------------------------------------

interface SSEEvent {
  agentId: string;
  actionType: string;
  target: string;
  allowed: boolean;
}

function startSSEListener(
  events: SSEEvent[],
  controller: AbortController,
): void {
  (async () => {
    try {
      const res = await fetch(`${HUSHD_URL}/api/v1/events`, {
        signal: controller.signal,
      });
      if (!res.body) return;

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data:')) continue;
          try {
            const data = JSON.parse(line.slice(5).trim());
            if (data.session_id && data.session_id !== SESSION_ID) continue;
            events.push({
              agentId: data.agent_id ?? 'unknown',
              actionType: data.action_type ?? '?',
              target: data.target ?? '?',
              allowed: data.allowed ?? true,
            });
          } catch { /* skip non-JSON */ }
        }
      }
    } catch { /* abort expected */ }
  })();
}

// -- Main ------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('===============================================');
  console.log('  Hybrid Swarm Example');
  console.log('  Session:', SESSION_ID);
  console.log('===============================================\n');

  await healthCheck();

  // Start SSE listener
  const sseEvents: SSEEvent[] = [];
  const sseController = new AbortController();
  startSSEListener(sseEvents, sseController);
  await sleep(500);

  // Create engines (all use hushd remote)
  const plannerEngine = createStrikeCell({ baseUrl: HUSHD_URL });
  const coderEngine = createStrikeCell({ baseUrl: HUSHD_URL });
  const reviewerEngine = createStrikeCell({ baseUrl: HUSHD_URL });

  // -- Phase 1: Planner (ClaudeAdapter) ------------------------------------

  console.log('=== Phase 1: Planner (ClaudeAdapter) ===\n');

  const planner = new ClaudeAdapter(plannerEngine);
  const plannerCtx = planner.createContext({ agentId: 'planner' });

  const plannerActions = [
    { name: 'read_file', params: { path: 'src/main.rs' }, actionType: 'file_access', target: 'src/main.rs' },
    { name: 'list_directory', params: { path: 'src/' }, actionType: 'file_access', target: 'src/' },
    { name: 'create_plan', params: { description: 'feature X' }, actionType: 'mcp_tool', target: 'create_plan' },
  ];

  for (const action of plannerActions) {
    // Adapter interception
    const intercept = await planner.interceptToolCall(plannerCtx, {
      name: action.name,
      parameters: action.params,
    });

    // Direct hushd check for attribution
    const hResult = await hushdCheck('planner', action.actionType, action.target);
    console.log(`  ${action.name.padEnd(18)} adapter: ${status(intercept.proceed)}  hushd: ${status(hResult.allowed)}`);
  }

  // -- Phase 2: Coder (VercelAIAdapter) ------------------------------------

  console.log('\n=== Phase 2: Coder (VercelAIAdapter) ===\n');

  const coder = new VercelAIAdapter(coderEngine);
  const coderCtx = coder.createContext({ agentId: 'coder' });

  const coderActions = [
    { name: 'write_file', params: { path: 'src/feature.ts', content: 'export const x = 1;' }, actionType: 'file_write', target: 'src/feature.ts', content: 'export const x = 1;' },
    { name: 'write_file', params: { path: '~/.ssh/config', content: 'Host evil' }, actionType: 'file_write', target: '~/.ssh/config', content: 'Host evil' },
    { name: 'shell_exec', params: { command: 'npm test' }, actionType: 'shell', target: 'npm test' },
    { name: 'write_file', params: { path: '/etc/passwd', content: 'root::0:0:::' }, actionType: 'file_write', target: '/etc/passwd', content: 'root::0:0:::' },
  ];

  for (const action of coderActions) {
    // Adapter: wrap tool and execute
    const tools = {
      [action.name]: {
        execute: async (input: unknown) => ({ ok: true, input }),
      },
    };
    const secured = coder.wrapTools(tools, coderCtx);

    let adapterAllowed: boolean;
    try {
      await secured[action.name].execute(action.params);
      adapterAllowed = true;
    } catch (e) {
      adapterAllowed = !(e instanceof ClawdstrikeBlockedError);
    }

    // Direct hushd check for attribution
    const hResult = await hushdCheck('coder', action.actionType, action.target, action.content);
    console.log(`  ${action.name.padEnd(18)} adapter: ${status(adapterAllowed)}  hushd: ${status(hResult.allowed)}`);
  }

  // -- Phase 3: Reviewer (FrameworkToolBoundary) ---------------------------

  console.log('\n=== Phase 3: Reviewer (FrameworkToolBoundary) ===\n');

  const reviewerBoundary = new FrameworkToolBoundary('generic', { engine: reviewerEngine });
  const reviewerDispatch = wrapFrameworkToolDispatcher(
    reviewerBoundary,
    async (toolName, _input, _runId) => ({ ok: true, tool: toolName }),
  );

  const reviewerActions = [
    { name: 'read_file', params: { path: 'src/feature.ts' }, actionType: 'file_access', target: 'src/feature.ts' },
    { name: 'search', params: { query: 'TODO' }, actionType: 'mcp_tool', target: 'search' },
    { name: 'grep', params: { pattern: 'fixme' }, actionType: 'mcp_tool', target: 'grep' },
    { name: 'write_file', params: { path: 'review.md', content: '# Review' }, actionType: 'file_write', target: 'review.md' },
  ];

  for (const action of reviewerActions) {
    let adapterAllowed: boolean;
    try {
      await reviewerDispatch(action.name, action.params, `run-${Date.now()}`);
      adapterAllowed = true;
    } catch (e) {
      adapterAllowed = !(e instanceof ClawdstrikeBlockedError);
    }

    // Direct hushd check for attribution
    const hResult = await hushdCheck('reviewer', action.actionType, action.target);
    console.log(`  ${action.name.padEnd(18)} adapter: ${status(adapterAllowed)}  hushd: ${status(hResult.allowed)}`);
  }

  // -- Phase 4: Audit + Summary --------------------------------------------

  console.log('\n=== Phase 4: Audit & Summary ===\n');

  // Finalize adapter contexts for session summaries
  const plannerSummary = await planner.finalizeContext(plannerCtx);
  const coderSummary = await coder.finalizeContext(coderCtx);

  console.log('-- Adapter Session Summaries --');
  for (const [label, summary] of [['Planner', plannerSummary], ['Coder', coderSummary]] as const) {
    console.log(`  ${label}:`);
    console.log(`    Total tool calls:   ${summary.totalToolCalls}`);
    console.log(`    Blocked:            ${summary.blockedToolCalls}`);
    console.log(`    Tools used:         ${summary.toolsUsed.join(', ') || '(none)'}`);
    console.log(`    Tools blocked:      ${summary.toolsBlocked.join(', ') || '(none)'}`);
  }

  // Query hushd audit per agent
  console.log('\n-- hushd Audit Per Agent --');
  for (const agentId of ['planner', 'coder', 'reviewer']) {
    const auditRes = await fetch(
      `${HUSHD_URL}/api/v1/audit?agent_id=${agentId}&session_id=${SESSION_ID}&limit=20`,
    );
    const audit = (await auditRes.json()) as {
      total: number;
      events: Array<{ action_type: string; target: string; decision: string }>;
    };
    console.log(`\n  ${agentId} (${audit.total} events):`);
    for (const evt of audit.events) {
      console.log(`    ${evt.action_type.padEnd(14)} ${evt.target.padEnd(25)} ${evt.decision}`);
    }
  }

  // Full session audit
  console.log('\n-- Full Session Audit --');
  const sessionRes = await fetch(
    `${HUSHD_URL}/api/v1/audit?session_id=${SESSION_ID}&limit=50`,
  );
  const sessionAudit = (await sessionRes.json()) as { total: number };
  console.log(`  Session ${SESSION_ID}: ${sessionAudit.total} total events`);

  // Aggregate stats
  const statsRes = await fetch(`${HUSHD_URL}/api/v1/audit/stats`);
  const stats = (await statsRes.json()) as { total_events: number; violations: number; allowed: number };
  console.log('\n-- Aggregate Stats --');
  console.log(`  Total events: ${stats.total_events}`);
  console.log(`  Allowed:      ${stats.allowed}`);
  console.log(`  Violations:   ${stats.violations}`);

  // SSE summary
  sseController.abort();
  console.log(`\n-- SSE Events Captured: ${sseEvents.length} --`);
  for (const evt of sseEvents.slice(0, 10)) {
    console.log(`  [${evt.agentId}] ${evt.actionType} ${evt.target} -> ${evt.allowed ? 'allow' : 'block'}`);
  }
  if (sseEvents.length > 10) {
    console.log(`  ... and ${sseEvents.length - 10} more`);
  }

  // Final verdict
  const hasViolations = stats.violations > 0;
  console.log(`\n=== Verdict: ${hasViolations ? 'Security policies enforced correctly' : 'No violations detected (is hushd running with strict ruleset?)'} ===`);
  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
