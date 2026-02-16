/**
 * Secure Agent Swarm Example
 *
 * Demonstrates a 3-agent swarm (planner/coder/reviewer) where each agent
 * has different security policies enforced through Clawdstrike adapters
 * and hushd attribution.
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
const SESSION_ID = `swarm-${Date.now()}`;

// ── Helpers ──────────────────────────────────────────────────────────

async function healthCheck(): Promise<void> {
  const res = await fetch(`${HUSHD_URL}/health`);
  if (!res.ok) throw new Error(`hushd health check failed: ${res.status}`);
  console.log('[✓] hushd is running\n');
}

interface CheckResult {
  allowed: boolean;
  guard: string;
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

function status(allowed: boolean): string {
  return allowed ? '✅ allowed' : '🚫 blocked';
}

// ── Agent Definitions ────────────────────────────────────────────────

interface AgentAction {
  actionType: string;
  target: string;
  content?: string;
  toolName: string;
  toolParams: Record<string, unknown>;
}

interface AgentDef {
  id: string;
  label: string;
  actions: AgentAction[];
}

const agents: AgentDef[] = [
  {
    id: 'planner',
    label: 'Planner (ClaudeAdapter)',
    actions: [
      { actionType: 'file_access', target: 'src/main.rs', toolName: 'read_file', toolParams: { path: 'src/main.rs' } },
      { actionType: 'file_access', target: 'src/', toolName: 'list_directory', toolParams: { path: 'src/' } },
      { actionType: 'mcp_tool', target: 'create_plan', toolName: 'create_plan', toolParams: { description: 'implement feature X' } },
    ],
  },
  {
    id: 'coder',
    label: 'Coder (VercelAIAdapter)',
    actions: [
      { actionType: 'file_write', target: 'src/feature.ts', content: 'export const x = 1;', toolName: 'write_file', toolParams: { path: 'src/feature.ts', content: 'export const x = 1;' } },
      { actionType: 'file_write', target: '~/.ssh/config', content: 'Host evil', toolName: 'write_file', toolParams: { path: '~/.ssh/config', content: 'Host evil' } },
      { actionType: 'shell', target: 'npm test', toolName: 'shell_exec', toolParams: { command: 'npm test' } },
    ],
  },
  {
    id: 'reviewer',
    label: 'Reviewer (FrameworkToolBoundary)',
    actions: [
      { actionType: 'file_access', target: 'src/feature.ts', toolName: 'read_file', toolParams: { path: 'src/feature.ts' } },
      { actionType: 'mcp_tool', target: 'search', toolName: 'search', toolParams: { query: 'TODO' } },
      { actionType: 'file_write', target: 'review.md', content: '# Review', toolName: 'write_file', toolParams: { path: 'review.md', content: '# Review' } },
    ],
  },
];

// ── Main ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('═══════════════════════════════════════════════');
  console.log('  Secure Agent Swarm Example');
  console.log('  Session:', SESSION_ID);
  console.log('═══════════════════════════════════════════════\n');

  await healthCheck();

  // Create adapter engines (all point at the same hushd)
  const plannerEngine = createStrikeCell({ baseUrl: HUSHD_URL });
  const coderEngine = createStrikeCell({ baseUrl: HUSHD_URL });
  const reviewerEngine = createStrikeCell({ baseUrl: HUSHD_URL });

  // Create adapters
  const plannerAdapter = new ClaudeAdapter(plannerEngine);
  const coderAdapter = new VercelAIAdapter(coderEngine);
  const reviewerBoundary = new FrameworkToolBoundary('generic', { engine: reviewerEngine });
  const reviewerDispatch = wrapFrameworkToolDispatcher(
    reviewerBoundary,
    async (toolName, _input, _runId) => ({ ok: true, tool: toolName }),
  );

  // Create adapter contexts
  const plannerCtx = plannerAdapter.createContext({ agentId: 'planner' });
  const coderCtx = coderAdapter.createContext({ agentId: 'coder' });

  // ── Per-Agent Execution ──────────────────────────────────────────

  const results: Array<{ agent: string; tool: string; adapterResult: string; hushdResult: string }> = [];

  for (const agent of agents) {
    console.log(`\n── ${agent.label} ──`);

    for (const action of agent.actions) {
      // Direct hushd check (for attribution)
      const hResult = await hushdCheck(agent.id, action.actionType, action.target, action.content);

      // Adapter-level check
      let adapterAllowed: boolean;
      try {
        if (agent.id === 'planner') {
          const intercept = await plannerAdapter.interceptToolCall(plannerCtx, {
            name: action.toolName,
            parameters: action.toolParams,
          });
          adapterAllowed = intercept.proceed;
        } else if (agent.id === 'coder') {
          const tools: Record<string, { execute: (input: unknown) => Promise<unknown> }> = {
            [action.toolName]: { execute: async (input: unknown) => ({ ok: true, input }) },
          };
          const secured = coderAdapter.wrapTools(tools, coderCtx);
          try {
            await secured[action.toolName].execute(action.toolParams);
            adapterAllowed = true;
          } catch (e) {
            adapterAllowed = !(e instanceof ClawdstrikeBlockedError);
          }
        } else {
          // reviewer - uses FrameworkToolBoundary dispatcher
          try {
            await reviewerDispatch(action.toolName, action.toolParams, `run-${Date.now()}`);
            adapterAllowed = true;
          } catch (e) {
            adapterAllowed = !(e instanceof ClawdstrikeBlockedError);
          }
        }
      } catch {
        adapterAllowed = false;
      }

      const line = `  ${action.toolName.padEnd(18)} ${status(hResult.allowed).padEnd(14)} (hushd: ${hResult.guard})`;
      console.log(line);

      results.push({
        agent: agent.id,
        tool: action.toolName,
        adapterResult: adapterAllowed ? 'allowed' : 'blocked',
        hushdResult: hResult.allowed ? 'allowed' : 'blocked',
      });
    }
  }

  // ── Decision Table ─────────────────────────────────────────────────

  console.log('\n\n═══ Decision Table ═══');
  console.log('Agent'.padEnd(12) + 'Tool'.padEnd(20) + 'Adapter'.padEnd(12) + 'hushd');
  console.log('─'.repeat(56));
  for (const r of results) {
    console.log(
      r.agent.padEnd(12) + r.tool.padEnd(20) + r.adapterResult.padEnd(12) + r.hushdResult,
    );
  }

  // ── Audit Queries ──────────────────────────────────────────────────

  console.log('\n\n═══ Audit Queries ═══');
  for (const agent of agents) {
    const auditRes = await fetch(
      `${HUSHD_URL}/api/v1/audit?agent_id=${agent.id}&session_id=${SESSION_ID}&limit=10`,
    );
    const audit = (await auditRes.json()) as { total: number; events: Array<{ action_type: string; decision: string }> };
    console.log(`\n${agent.label}: ${audit.total} events`);
    for (const evt of audit.events) {
      console.log(`  ${evt.action_type} → ${evt.decision}`);
    }
  }

  // ── SSE Live Events (2 seconds) ────────────────────────────────────

  console.log('\n\n═══ SSE Live Events (2s sample) ═══');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2000);

  try {
    const sseRes = await fetch(`${HUSHD_URL}/api/v1/events`, {
      signal: controller.signal,
    });

    if (sseRes.body) {
      const reader = sseRes.body.getReader();
      const decoder = new TextDecoder();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const text = decoder.decode(value, { stream: true });
          for (const line of text.split('\n').filter(l => l.startsWith('data:'))) {
            try {
              const data = JSON.parse(line.slice(5).trim());
              if (data.session_id && data.session_id !== SESSION_ID) continue;
              console.log(`  [${data.agent_id ?? '?'}] ${data.action_type} → ${data.allowed ? 'allow' : 'block'}`);
            } catch { /* skip non-JSON */ }
          }
        }
      } catch { /* abort expected */ }
    }
  } catch { /* abort expected */ }
  clearTimeout(timeout);

  // ── Final Stats ────────────────────────────────────────────────────

  const statsRes = await fetch(`${HUSHD_URL}/api/v1/audit/stats`);
  const stats = (await statsRes.json()) as { total_events: number; violations: number; allowed: number };
  console.log('\n═══ Final Stats ═══');
  console.log(`  Total events: ${stats.total_events}`);
  console.log(`  Allowed:      ${stats.allowed}`);
  console.log(`  Violations:   ${stats.violations}`);
  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
