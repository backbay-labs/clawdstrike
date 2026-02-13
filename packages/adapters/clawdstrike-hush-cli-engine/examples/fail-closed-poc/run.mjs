import { createStrikeCell } from '../../dist/index.js';

const report = {
  scenario: 'engine-local-fail-closed',
  startedAt: new Date().toISOString(),
  checks: [],
};

function check(name, pass, details = {}) {
  report.checks.push({ name, pass, details });
  if (!pass) {
    throw new Error(`${name} failed: ${JSON.stringify(details)}`);
  }
}

const engine = createStrikeCell({
  hushPath: '/definitely/not/a/real/hush-binary',
  policyRef: 'default',
  timeoutMs: 250,
});

const decision = await engine.evaluate({
  eventId: 'poc-local-engine-fail-closed',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'bash', parameters: { cmd: 'echo test' } },
});

check('engine-local returns deny on spawn error', decision.status === 'deny', { decision });
check('engine-local reason is engine_error', decision.reason === 'engine_error', { decision });
check('engine-local includes failure message', typeof decision.message === 'string' && decision.message.length > 0, {
  decision,
});

report.finishedAt = new Date().toISOString();
report.status = 'pass';
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
