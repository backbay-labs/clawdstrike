#!/usr/bin/env node

/**
 * bb-edr (simulation)
 *
 * Generates an example `.hush/audit.jsonl` log by simulating a handful of tool actions
 * (file reads/writes, egress, and commands), gating each one with clawdstrike policy checks.
 *
 * This does NOT run OpenClaw. It demonstrates the data you can feed into an agentic EDR loop.
 */

const fs = require('fs');
const path = require('path');

const { importOpenclawSdk } = require('./tools/openclaw');

function loadScenario() {
  const raw = fs.readFileSync('./scenario.json', 'utf8');
  const parsed = JSON.parse(raw);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid scenario.json');
  }
  if (!Array.isArray(parsed.actions)) {
    throw new Error('scenario.json must contain an "actions" array');
  }

  return parsed;
}

async function main() {
  const { checkPolicy, AuditStore } = await importOpenclawSdk();

  const config = {
    policy: './policy.yaml',
    mode: 'deterministic',
    logLevel: 'error',
  };

  const scenario = loadScenario();
  const runId = typeof scenario.runId === 'string' ? scenario.runId : 'bb-edr-demo';

  const store = new AuditStore('.hush/audit.jsonl');
  store.clear();

  console.log('bb-edr (Simulated Agent Activity)');
  console.log('================================\n');

  for (const item of scenario.actions) {
    const action = item.action;
    const resource = item.resource;
    const note = typeof item.note === 'string' ? item.note : '';

    if (typeof action !== 'string' || typeof resource !== 'string') {
      console.log(`[skip] invalid action entry: ${JSON.stringify(item)}`);
      continue;
    }

    const decision = await checkPolicy(config, action, resource);

    const status = decision.denied ? 'DENY' : decision.warn ? 'WARN' : 'ALLOW';
    const guard = decision.guard ? ` (${decision.guard})` : '';
    const reason = decision.reason ? ` - ${decision.reason}` : '';
    const noteSuffix = note ? `  # ${note}` : '';

    console.log(`[clawdstrike] ${status}: ${action} ${JSON.stringify(resource)}${guard}${reason}${noteSuffix}`);

    store.append({
      type: action,
      resource,
      decision: decision.denied ? 'denied' : 'allowed',
      guard: decision.guard,
      reason: decision.reason,
      runId,
    });

    // Optional side effect for the demo: create the "quarantine" file if policy allows it.
    if (action === 'file_write' && !decision.denied) {
      const absolute = path.resolve(resource);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, `bb-edr quarantine artifact (${new Date().toISOString()})\n`);
    }
  }

  console.log('\nWrote audit log: .hush/audit.jsonl');
  console.log('Next: npm run triage');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
