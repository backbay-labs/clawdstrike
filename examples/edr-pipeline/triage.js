#!/usr/bin/env node

/**
 * Fetch denied audit events from hushd and write an incident report.
 */

const fs = require('fs');
const path = require('path');

function safeFilenameTimestamp(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function summarizeByGuard(events) {
  const counts = new Map();
  for (const e of events) {
    const guard = e.guard || 'unknown';
    counts.set(guard, (counts.get(guard) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

async function main() {
  const baseUrl = process.env.HUSHD_URL ?? 'http://localhost:8080';
  const apiKey = process.env.HUSHD_API_KEY;
  if (!apiKey) {
    throw new Error('Missing HUSHD_API_KEY');
  }

  const resp = await fetch(`${baseUrl}/api/v1/audit?format=jsonl&decision=blocked&limit=500`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  const body = await resp.text();
  if (!resp.ok) {
    throw new Error(`audit query failed: ${resp.status} ${body}`);
  }

  const events = body
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  if (events.length === 0) {
    console.log('No denied events found.');
    return;
  }

  const byGuard = summarizeByGuard(events);
  const now = new Date();
  const reportPath = path.join(
    __dirname,
    'reports',
    `incident-${safeFilenameTimestamp(now)}.md`,
  );

  const lines = [];
  lines.push(`# hushd EDR Incident Report`);
  lines.push('');
  lines.push(`Generated: ${now.toISOString()}`);
  lines.push('');
  lines.push(`Denied events: **${events.length}**`);
  lines.push('');
  lines.push(`## By guard`);
  lines.push('');
  for (const [guard, count] of byGuard) {
    lines.push(`- ${guard}: ${count}`);
  }
  lines.push('');
  lines.push(`## Timeline (denied)`);
  lines.push('');

  const sorted = [...events].sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  for (const e of sorted) {
    const when = new Date(e.timestamp).toISOString();
    const tgt = e.target ? ` ${JSON.stringify(e.target)}` : '';
    lines.push(`- **${when}** \`${e.action_type}\`${tgt} (guard: ${e.guard})`);
  }
  lines.push('');

  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, lines.join('\n') + '\n', 'utf8');
  console.log(`Wrote report: ${reportPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

