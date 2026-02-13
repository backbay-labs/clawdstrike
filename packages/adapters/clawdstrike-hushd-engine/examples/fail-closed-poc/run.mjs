import { createStrikeCell } from '../../dist/index.js';

const report = {
  scenario: 'engine-remote-fail-closed',
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
  baseUrl: 'http://127.0.0.1:9',
  timeoutMs: 300,
});

const decision = await engine.evaluate({
  eventId: 'poc-remote-engine-fail-closed',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'bash', parameters: { cmd: 'echo test' } },
});

check('engine-remote returns deny on transport error', decision.status === 'deny', { decision });
check('engine-remote reason is engine_error', decision.reason === 'engine_error', { decision });
check('engine-remote includes failure message', typeof decision.message === 'string' && decision.message.length > 0, {
  decision,
});

report.finishedAt = new Date().toISOString();
report.status = 'pass';
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
