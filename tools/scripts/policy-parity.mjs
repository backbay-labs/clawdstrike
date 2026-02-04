#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');

const fixturesDir = path.join(repoRoot, 'fixtures', 'threat-intel');
const policyPath = path.join(fixturesDir, 'policy.yaml');
const eventsPath = path.join(fixturesDir, 'events.jsonl');

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function readJsonl(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

async function startMockServer({ maliciousFileHash }) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    // VirusTotal
    if (req.method === 'GET' && url.pathname.startsWith('/vt/api/v3/files/')) {
      const hash = url.pathname.split('/').pop() ?? '';
      const malicious = hash === maliciousFileHash ? 3 : 0;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          data: { attributes: { last_analysis_stats: { malicious, suspicious: 0 } } },
        }),
      );
      return;
    }

    if (req.method === 'GET' && url.pathname.startsWith('/vt/api/v3/urls/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } },
        }),
      );
      return;
    }

    // Safe Browsing
    if (req.method === 'POST' && url.pathname === '/gsb/v4/threatMatches:find') {
      let body = '';
      for await (const chunk of req) body += chunk;
      let parsed = {};
      try {
        parsed = JSON.parse(body || '{}');
      } catch {
        parsed = {};
      }

      const entries = parsed?.threatInfo?.threatEntries ?? [];
      const entryUrl = Array.isArray(entries) && entries[0] && typeof entries[0].url === 'string' ? entries[0].url : '';
      const isBad = entryUrl.includes('evil.example');

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(isBad ? JSON.stringify({ matches: [{ threatType: 'MALWARE' }] }) : JSON.stringify({}));
      return;
    }

    // Snyk
    if (req.method === 'POST' && url.pathname === '/snyk/api/v1/test') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ vulnerabilities: [{ severity: 'high', isUpgradable: true }] }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({}));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('mock server failed to bind');
  const base = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl: base,
    close: async () => {
      await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

async function runHushSimulate(env) {
  const hushPath = path.join(repoRoot, 'target', 'debug', 'hush');
  if (!fs.existsSync(hushPath)) {
    throw new Error(`missing hush binary at ${hushPath}; build it first`);
  }

  const { stdout, stderr, code, signal } = await spawnCapture(hushPath, ['policy', 'simulate', policyPath, eventsPath, '--json'], {
    cwd: repoRoot,
    env,
    timeoutMs: 30_000,
  });

  if (signal) {
    throw new Error(`hush policy simulate terminated with signal ${signal}: ${stderr || stdout}`);
  }
  if (code !== 0 && code !== 1 && code !== 2) {
    throw new Error(`hush policy simulate failed: ${stderr || stdout}`);
  }
  return JSON.parse(stdout);
}

async function runTsEngine(env, events) {
  const distEntry = path.join(repoRoot, 'packages', 'clawdstrike-policy', 'dist', 'index.js');
  const mod = await import(pathToFileURL(distEntry).href);
  const engine = mod.createPolicyEngine({ policyRef: policyPath, resolve: false });

  const out = new Map();
  for (const evt of events) {
    const decision = await engine.evaluate(evt);
    out.set(evt.eventId, decision);
  }
  return out;
}

function spawnCapture(command, args, opts) {
  const timeoutMs = opts?.timeoutMs ?? 30_000;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: opts?.cwd, env: opts?.env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.on('data', (c) => stdoutChunks.push(String(c)));
    child.stderr.on('data', (c) => stderrChunks.push(String(c)));

    let settled = false;
    const settleOnce = (fn) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const timeoutId = setTimeout(() => {
      settleOnce(() => {
        child.kill('SIGKILL');
        reject(new Error(`spawn timed out after ${timeoutMs}ms`));
      });
    }, timeoutMs);
    timeoutId.unref?.();

    child.once('error', (err) => {
      settleOnce(() => {
        clearTimeout(timeoutId);
        reject(err);
      });
    });

    child.once('close', (code, signal) => {
      settleOnce(() => {
        clearTimeout(timeoutId);
        resolve({
          stdout: stdoutChunks.join(''),
          stderr: stderrChunks.join(''),
          code,
          signal,
        });
      });
    });
  });
}

function pickComparableDecision(d) {
  return {
    allowed: Boolean(d.allowed),
    denied: Boolean(d.denied),
    warn: Boolean(d.warn),
    guard: d.guard ?? null,
    severity: d.severity ?? null,
  };
}

function compare(tsById, hushOutput) {
  const results = hushOutput?.results ?? [];
  const mismatches = [];

  for (const r of results) {
    const id = r.eventId ?? r.event_id;
    const hushDecision = r.decision;
    const tsDecision = tsById.get(id);
    if (!tsDecision) {
      mismatches.push({ id, reason: 'missing ts decision' });
      continue;
    }

    const a = pickComparableDecision(tsDecision);
    const b = pickComparableDecision(hushDecision);
    const same = JSON.stringify(a) === JSON.stringify(b);
    if (!same) {
      mismatches.push({ id, ts: a, hush: b });
    }
  }

  return mismatches;
}

async function main() {
  const events = readJsonl(eventsPath);
  const file1 = events.find((e) => e.eventId === 'ti-0001');
  if (!file1) throw new Error('missing ti-0001');

  const contentB64 = file1?.data?.contentBase64 ?? '';
  const maliciousHash = sha256Hex(Buffer.from(contentB64, 'base64'));

  const server = await startMockServer({ maliciousFileHash: maliciousHash });

  // Set env vars for both the in-process TS engine and the spawned hush CLI.
  process.env.VT_API_KEY = 'dummy';
  process.env.GSB_API_KEY = 'dummy';
  process.env.GSB_CLIENT_ID = 'clawdstrike-parity';
  process.env.SNYK_API_TOKEN = 'dummy';
  process.env.SNYK_ORG_ID = 'org-123';
  process.env.TI_VT_BASE_URL = `${server.baseUrl}/vt/api/v3`;
  process.env.TI_GSB_BASE_URL = `${server.baseUrl}/gsb/v4`;
  process.env.TI_SNYK_BASE_URL = `${server.baseUrl}/snyk/api/v1`;

  const env = { ...process.env };

  try {
    const tsById = await runTsEngine(env, events);
    const hush = await runHushSimulate(env);
    const mismatches = compare(tsById, hush);

    if (mismatches.length > 0) {
      // eslint-disable-next-line no-console
      console.error(`policy parity failed (${mismatches.length} mismatch(es))`);
      for (const m of mismatches.slice(0, 20)) {
        // eslint-disable-next-line no-console
        console.error(JSON.stringify(m, null, 2));
      }
      process.exit(1);
    }

    // eslint-disable-next-line no-console
    console.log(`policy parity ok (${events.length} events)`);
  } finally {
    await server.close();
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(2);
});
