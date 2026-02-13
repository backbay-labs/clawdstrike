import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { ClawdstrikeBlockedError, ClaudeToolBoundary, wrapClaudeToolDispatcher } from '../../dist/index.js';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawdstrike-claude-poc-'));
const blockedSideEffectPath = path.join(tmpDir, 'blocked-side-effect.txt');
const allowedSideEffectPath = path.join(tmpDir, 'allowed-side-effect.txt');

const report = {
  scenario: 'claude-fail-closed',
  startedAt: new Date().toISOString(),
  checks: [],
};

function check(name, pass, details = {}) {
  report.checks.push({ name, pass, details });
  if (!pass) {
    throw new Error(`${name} failed: ${JSON.stringify(details)}`);
  }
}

const engine = {
  evaluate(event) {
    if (event.eventType === 'command_exec') {
      return {
        status: 'deny',
        guard: 'policy_guard',
        reason: 'blocked dangerous command',
      };
    }
    return { status: 'allow', guard: 'policy_guard' };
  },
};

const boundary = new ClaudeToolBoundary({
  engine,
  config: { blockOnViolation: true },
});

let dispatchCalls = 0;
const wrappedDispatch = wrapClaudeToolDispatcher(
  boundary,
  async (toolName, input, runId) => {
    dispatchCalls += 1;
    const sideEffectPath = toolName === 'read_file' ? allowedSideEffectPath : blockedSideEffectPath;
    fs.writeFileSync(sideEffectPath, JSON.stringify({ toolName, input, runId }));
    return { ok: true, toolName, runId };
  },
);

let blockedError = null;
try {
  await wrappedDispatch('bash', { cmd: 'rm -rf /' }, 'run-blocked');
} catch (error) {
  blockedError = error;
}
check(
  'blocked command throws ClawdstrikeBlockedError',
  blockedError instanceof ClawdstrikeBlockedError,
  blockedError instanceof Error
    ? { errorType: blockedError.constructor.name }
    : { reason: 'no error thrown' },
);

check('blocked command does not execute side effect', !fs.existsSync(blockedSideEffectPath), {
  blockedSideEffectPath,
  exists: fs.existsSync(blockedSideEffectPath),
});

const allowedResult = await wrappedDispatch('read_file', { path: './README.md' }, 'run-allowed');
check('allowed tool executes dispatcher', allowedResult?.ok === true, { allowedResult });
check('allowed tool can write side effect', fs.existsSync(allowedSideEffectPath), {
  allowedSideEffectPath,
  exists: fs.existsSync(allowedSideEffectPath),
});

const blockedAudit = boundary.getAuditEvents().find((e) => e.type === 'tool_call_blocked');
check('blocked audit event recorded', Boolean(blockedAudit), {
  eventTypes: boundary.getAuditEvents().map((e) => e.type),
});

check('dispatcher called exactly once (allowed path only)', dispatchCalls === 1, { dispatchCalls });

report.finishedAt = new Date().toISOString();
report.status = 'pass';
report.tmpDir = tmpDir;
report.dispatchCalls = dispatchCalls;

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
