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

const suites = [
  {
    name: 'threat-intel',
    policyRef: path.join(repoRoot, 'fixtures', 'threat-intel', 'policy.yaml'),
    eventsPath: path.join(repoRoot, 'fixtures', 'threat-intel', 'events.jsonl'),
    usesThreatIntelMocks: true,
    engineKind: 'policy',
  },
  {
    name: 'default-ruleset',
    policyRef: path.join(repoRoot, 'rulesets', 'default.yaml'),
    eventsPath: path.join(repoRoot, 'fixtures', 'policy-events', 'v1', 'events.jsonl'),
    usesThreatIntelMocks: false,
    engineKind: 'sdk',
  },
  {
    name: 'strict-ruleset',
    policyRef: path.join(repoRoot, 'rulesets', 'strict.yaml'),
    eventsPath: path.join(repoRoot, 'fixtures', 'policy-events', 'v1', 'events.jsonl'),
    usesThreatIntelMocks: false,
    engineKind: 'sdk',
  },
  {
    name: 'permissive-ruleset',
    policyRef: path.join(repoRoot, 'rulesets', 'permissive.yaml'),
    eventsPath: path.join(repoRoot, 'fixtures', 'policy-events', 'v1', 'events.jsonl'),
    usesThreatIntelMocks: false,
    engineKind: 'sdk',
  },
];

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

async function runHushSimulate(env, policyRef, eventsPath) {
  const hushPath = path.join(repoRoot, 'target', 'debug', 'hush');
  if (!fs.existsSync(hushPath)) {
    throw new Error(`missing hush binary at ${hushPath}; build it first`);
  }

  const { stdout, stderr, code, signal } = await spawnCapture(hushPath, ['policy', 'simulate', policyRef, eventsPath, '--json'], {
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

async function runTsEngine(env, policyRef, events, engineKind) {
  const byId = new Map();

  if (engineKind === 'policy') {
    const distEntry = path.join(repoRoot, 'packages', 'clawdstrike-policy', 'dist', 'index.js');
    const mod = await import(pathToFileURL(distEntry).href);
    const engine = mod.createPolicyEngine({ policyRef, resolve: false });
    for (const evt of events) {
      const decision = await engine.evaluate(evt);
      byId.set(evt.eventId, decision);
    }
    return byId;
  }

  if (engineKind === 'sdk') {
    const distEntry = path.join(repoRoot, 'packages', 'hush-ts', 'dist', 'index.js');
    if (!fs.existsSync(distEntry)) {
      throw new Error(`missing hush-ts dist at ${distEntry}; run npm --prefix packages/hush-ts run build`);
    }
    const mod = await import(pathToFileURL(distEntry).href);
    const sdk = await mod.Clawdstrike.fromPolicy(policyRef);
    for (const evt of events) {
      const decision = await evaluateSdkEvent(sdk, evt);
      byId.set(evt.eventId, decision);
    }
    return byId;
  }

  throw new Error(`unknown TS engine kind: ${String(engineKind)}`);
}

async function evaluateSdkEvent(sdk, event) {
  const data = event?.data ?? {};
  switch (event?.eventType) {
    case 'file_read':
      return sdk.check('file_access', { path: data.path });
    case 'file_write':
      return sdk.check('file_write', { path: data.path, content: data.content });
    case 'network_egress':
      return sdk.check('network_egress', { host: data.host, port: data.port, url: data.url });
    case 'tool_call':
      return sdk.check('mcp_tool', { tool: data.toolName, args: data.parameters ?? {} });
    case 'patch_apply':
      return sdk.check('patch', { path: data.filePath, diff: data.patchContent });
    case 'custom':
      return sdk.check('custom', {
        customType: data.customType,
        customData: {
          text: data.text,
        },
      });
    default:
      return sdk.check('custom', { customType: 'custom', customData: data });
  }
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
  const status = typeof d?.status === 'string' ? d.status.toLowerCase() : null;
  const allowedFromStatus = status && ['allow', 'allowed', 'pass', 'ok'].includes(status);
  const deniedFromStatus = status && ['deny', 'denied', 'block', 'blocked', 'fail', 'error'].includes(status);
  const warnFromStatus = status && ['warn', 'warning'].includes(status);
  const allowed = typeof d?.allowed === 'boolean' ? d.allowed : Boolean(allowedFromStatus);
  const denied = typeof d?.denied === 'boolean' ? d.denied : Boolean(deniedFromStatus);
  const warn = typeof d?.warn === 'boolean' ? d.warn : Boolean(warnFromStatus);
  const guard = d.guard ?? null;
  let severity = d.severity ?? null;
  if (typeof severity === 'string') {
    const normalized = severity.toLowerCase();
    if (normalized === 'info' || normalized === 'low') severity = 'low';
    else if (normalized === 'warning' || normalized === 'warn' || normalized === 'medium') severity = 'medium';
    else if (normalized === 'error' || normalized === 'high') severity = 'high';
    else if (normalized === 'critical') severity = 'critical';
    else severity = normalized;
  }

  if (allowed && !denied && !warn && guard === null && severity === 'low') {
    severity = null;
  }

  return {
    allowed,
    denied,
    warn,
    guard,
    severity,
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
  const suiteSummaries = [];

  for (const suite of suites) {
    const events = readJsonl(suite.eventsPath);
    let server = null;
    const env = { ...process.env };

    if (suite.usesThreatIntelMocks) {
      const file1 = events.find((e) => e.eventId === 'ti-0001');
      if (!file1) throw new Error('missing ti-0001 for threat-intel parity suite');

      const contentB64 = file1?.data?.contentBase64 ?? '';
      const maliciousHash = sha256Hex(Buffer.from(contentB64, 'base64'));
      server = await startMockServer({ maliciousFileHash: maliciousHash });

      env.VT_API_KEY = 'dummy';
      env.GSB_API_KEY = 'dummy';
      env.GSB_CLIENT_ID = 'clawdstrike-parity';
      env.SNYK_API_TOKEN = 'dummy';
      env.SNYK_ORG_ID = 'org-123';
      env.TI_VT_BASE_URL = `${server.baseUrl}/vt/api/v3`;
      env.TI_GSB_BASE_URL = `${server.baseUrl}/gsb/v4`;
      env.TI_SNYK_BASE_URL = `${server.baseUrl}/snyk/api/v1`;
      process.env.VT_API_KEY = env.VT_API_KEY;
      process.env.GSB_API_KEY = env.GSB_API_KEY;
      process.env.GSB_CLIENT_ID = env.GSB_CLIENT_ID;
      process.env.SNYK_API_TOKEN = env.SNYK_API_TOKEN;
      process.env.SNYK_ORG_ID = env.SNYK_ORG_ID;
      process.env.TI_VT_BASE_URL = env.TI_VT_BASE_URL;
      process.env.TI_GSB_BASE_URL = env.TI_GSB_BASE_URL;
      process.env.TI_SNYK_BASE_URL = env.TI_SNYK_BASE_URL;
    }

    try {
      const tsById = await runTsEngine(env, suite.policyRef, events, suite.engineKind);
      const hush = await runHushSimulate(env, suite.policyRef, suite.eventsPath);
      const mismatches = compare(tsById, hush);
      suiteSummaries.push({
        name: suite.name,
        policyRef: suite.policyRef,
        events: events.length,
        mismatches,
      });
    } finally {
      if (server) {
        await server.close();
      }
    }
  }

  const failed = suiteSummaries.filter((s) => s.mismatches.length > 0);
  if (failed.length > 0) {
    // eslint-disable-next-line no-console
    console.error(`policy parity failed (${failed.length} suite(s) with mismatches)`);
    for (const suite of failed) {
      // eslint-disable-next-line no-console
      console.error(`suite=${suite.name} policy=${suite.policyRef} mismatches=${suite.mismatches.length}`);
      for (const mismatch of suite.mismatches.slice(0, 20)) {
        // eslint-disable-next-line no-console
        console.error(JSON.stringify(mismatch, null, 2));
      }
    }
    process.exit(1);
  }

  for (const suite of suiteSummaries) {
    // eslint-disable-next-line no-console
    console.log(`policy parity ok suite=${suite.name} events=${suite.events}`);
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(2);
});
