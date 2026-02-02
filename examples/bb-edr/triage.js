#!/usr/bin/env node

/**
 * bb-edr (triage)
 *
 * A tiny "EDR loop" that reads `.hush/audit.jsonl`, flags denied events, and writes:
 * - `reports/incident-<timestamp>.md` (incident summary)
 * - `state/blocklist.txt` (optional response artifact)
 *
 * In a real OpenClaw setup, you would replace this heuristic triage with an agent skill
 * that reads the same audit log and decides on response actions.
 */

const fs = require('fs');
const path = require('path');

const { importOpenclawSdk } = require('./tools/openclaw');

function safeFilenameTimestamp(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function tryParseUrlHost(value) {
  try {
    const u = new URL(value);
    return u.hostname;
  } catch {
    // If it's a bare host, treat it as host.
    const host = String(value).split('/')[0]?.trim();
    return host || null;
  }
}

function summarizeDeniedByGuard(events) {
  const counts = new Map();
  for (const e of events) {
    const guard = e.guard || 'unknown';
    counts.set(guard, (counts.get(guard) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

async function main() {
  const { AuditStore, checkPolicy } = await importOpenclawSdk();

  const config = {
    policy: './policy.yaml',
    mode: 'deterministic',
    logLevel: 'error',
  };

  const store = new AuditStore('.hush/audit.jsonl');
  const denied = store.query({ denied: true });

  if (denied.length === 0) {
    console.log('No denied events found. Nothing to triage.');
    console.log('Tip: run `npm run simulate` first.');
    return;
  }

  const now = new Date();
  const reportPath = `./reports/incident-${safeFilenameTimestamp(now)}.md`;

  const canWriteReport = await checkPolicy(config, 'file_write', reportPath);
  if (canWriteReport.denied) {
    console.error(`[clawdstrike] DENY: file_write ${JSON.stringify(reportPath)} (${canWriteReport.guard}) - ${canWriteReport.reason}`);
    process.exit(1);
  }

  const byGuard = summarizeDeniedByGuard(denied);

  const lines = [];
  lines.push(`# bb-edr Incident Report`);
  lines.push('');
  lines.push(`Generated: ${now.toISOString()}`);
  lines.push('');
  lines.push(`## Summary`);
  lines.push('');
  lines.push(`Denied events: **${denied.length}**`);
  lines.push('');
  lines.push(`### By guard`);
  lines.push('');
  for (const [guard, count] of byGuard) {
    lines.push(`- ${guard}: ${count}`);
  }
  lines.push('');
  lines.push(`## Timeline (denied only)`);
  lines.push('');

  const sorted = [...denied].sort((a, b) => a.timestamp - b.timestamp);
  for (const e of sorted) {
    const when = new Date(e.timestamp).toISOString();
    lines.push(`- **${when}** \`${e.type}\` \`${e.resource}\`${e.guard ? ` (guard: ${e.guard})` : ''}${e.reason ? ` — ${e.reason}` : ''}`);
  }

  lines.push('');
  lines.push('## Recommended response');
  lines.push('');
  lines.push('- Review the denied events and confirm whether they indicate malicious intent or a policy misconfiguration.');
  lines.push('- If a request is legitimate, update `policy.yaml` narrowly (avoid broad allow rules).');
  lines.push('- If a request is suspicious, rotate any potentially exposed credentials and consider tightening tool/egress permissions.');

  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, lines.join('\n') + '\n', 'utf8');

  console.log(`Wrote incident report: ${reportPath}`);

  // Optional response artifact: build a domain blocklist from denied network events.
  const deniedHosts = new Set();
  for (const e of denied) {
    if (e.type !== 'network' && e.type !== 'network_egress') continue;
    const host = tryParseUrlHost(e.resource);
    if (host) deniedHosts.add(host);
  }

  if (deniedHosts.size > 0) {
    const blocklistPath = './state/blocklist.txt';
    const canWriteBlocklist = await checkPolicy(config, 'file_write', blocklistPath);
    if (!canWriteBlocklist.denied) {
      fs.mkdirSync(path.dirname(blocklistPath), { recursive: true });
      fs.writeFileSync(blocklistPath, [...deniedHosts].sort().join('\n') + '\n', 'utf8');
      console.log(`Wrote blocklist: ${blocklistPath}`);
    } else {
      console.log(`[clawdstrike] DENY: file_write ${JSON.stringify(blocklistPath)} (${canWriteBlocklist.guard}) - ${canWriteBlocklist.reason}`);
    }
  }

  console.log('\nTry: npx clawdstrike audit query --denied');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
