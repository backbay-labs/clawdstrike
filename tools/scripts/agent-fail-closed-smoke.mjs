import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..');
const REPORT_DIR = path.join(REPO_ROOT, 'docs/reports');
fs.mkdirSync(REPORT_DIR, { recursive: true });

const scenarios = [
  {
    id: 'codex',
    name: 'Codex adapter fail-closed boundary',
    cwd: path.join(REPO_ROOT, 'packages/adapters/clawdstrike-codex'),
    command: ['npm', ['run', 'poc:fail-closed']],
  },
  {
    id: 'claude-code',
    name: 'Claude Code adapter fail-closed boundary',
    cwd: path.join(REPO_ROOT, 'packages/adapters/clawdstrike-claude-code'),
    command: ['npm', ['run', 'poc:fail-closed']],
  },
  {
    id: 'engine-local',
    name: 'Engine-local fail-closed transport',
    cwd: path.join(REPO_ROOT, 'packages/adapters/clawdstrike-hush-cli-engine'),
    command: ['npm', ['run', 'poc:fail-closed']],
  },
  {
    id: 'engine-remote',
    name: 'Engine-remote fail-closed transport',
    cwd: path.join(REPO_ROOT, 'packages/adapters/clawdstrike-hushd-engine'),
    command: ['npm', ['run', 'poc:fail-closed']],
  },
];

const startedAt = new Date().toISOString();
const results = [];
let failed = 0;

for (const scenario of scenarios) {
  process.stdout.write(`\n[agent-fail-closed] ${scenario.id}: ${scenario.name}\n`);

  const [bin, args] = scenario.command;
  const proc = spawnSync(bin, args, {
    cwd: scenario.cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const stdout = proc.stdout ?? '';
  const stderr = proc.stderr ?? '';

  let parsed = null;
  try {
    const maybeJson = stdout.trim().split('\n').filter(Boolean).slice(-1)[0];
    parsed = maybeJson ? JSON.parse(maybeJson) : null;
  } catch {
    parsed = null;
  }

  const pass = proc.status === 0;
  if (!pass) failed += 1;

  results.push({
    id: scenario.id,
    name: scenario.name,
    pass,
    exitCode: proc.status,
    signal: proc.signal,
    stdout,
    stderr,
    parsed,
  });

  process.stdout.write(pass ? '[agent-fail-closed] PASS\n' : '[agent-fail-closed] FAIL\n');
}

const finishedAt = new Date().toISOString();
const report = {
  name: 'agent-fail-closed-smoke',
  startedAt,
  finishedAt,
  summary: {
    total: scenarios.length,
    passed: scenarios.length - failed,
    failed,
  },
  scenarios: results,
};

const jsonPath = path.join(REPORT_DIR, 'agent-fail-closed-smoke.json');
const mdPath = path.join(REPORT_DIR, 'agent-fail-closed-smoke.md');

fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

const md = [];
md.push('# Agent Fail-Closed Smoke Report');
md.push('');
md.push(`- Started: ${startedAt}`);
md.push(`- Finished: ${finishedAt}`);
md.push(`- Passed: ${report.summary.passed}`);
md.push(`- Failed: ${report.summary.failed}`);
md.push('');
for (const r of results) {
  md.push(`## ${r.id} - ${r.pass ? 'PASS' : 'FAIL'}`);
  md.push('');
  md.push(`- Exit code: ${r.exitCode}`);
  if (r.parsed?.checks) {
    md.push(`- Checks: ${r.parsed.checks.length}`);
    for (const c of r.parsed.checks) {
      md.push(`  - [${c.pass ? 'x' : ' '}] ${c.name}`);
    }
  }
  md.push('');
}
fs.writeFileSync(mdPath, `${md.join('\n')}\n`);

process.stdout.write(`\nReport JSON: ${jsonPath}\n`);
process.stdout.write(`Report MD: ${mdPath}\n`);

if (failed > 0) {
  process.exit(1);
}
