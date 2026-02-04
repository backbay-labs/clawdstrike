import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createPolicyEngine } from './engine.js';

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

async function startMockServer(maliciousFileHash: string): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
  counts: { vtFiles: number; vtUrls: number; gsb: number; snyk: number };
}> {
  const counts = { vtFiles: 0, vtUrls: 0, gsb: 0, snyk: 0 };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname.startsWith('/api/v3/files/')) {
      counts.vtFiles += 1;
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

    if (req.method === 'GET' && url.pathname.startsWith('/api/v3/urls/')) {
      counts.vtUrls += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } },
        }),
      );
      return;
    }

    if (req.method === 'POST' && url.pathname === '/v4/threatMatches:find') {
      counts.gsb += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ matches: [{ threatType: 'MALWARE' }] }));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/test') {
      counts.snyk += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ vulnerabilities: [{ severity: 'high', isUpgradable: true }] }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({}));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('server failed to bind');
  }

  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    counts,
    close: async () => {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

function writeTempPolicy(yaml: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawdstrike-policy-'));
  const file = path.join(dir, 'policy.yaml');
  fs.writeFileSync(file, yaml, 'utf8');
  return file;
}

test('threat intel guards evaluate and cache', async () => {
  const fileContent = Buffer.from('definitely-malicious', 'utf8');
  const server = await startMockServer(sha256Hex(fileContent));

  process.env.VT_API_KEY_TEST = 'dummy';
  process.env.GSB_API_KEY_TEST = 'dummy';
  process.env.GSB_CLIENT_ID_TEST = 'clawdstrike-test';
  process.env.SNYK_API_TOKEN_TEST = 'dummy';
  process.env.SNYK_ORG_ID_TEST = 'org-123';

  process.env.VT_BASE_URL_TEST = `${server.baseUrl}/api/v3`;
  process.env.GSB_BASE_URL_TEST = `${server.baseUrl}/v4`;
  process.env.SNYK_BASE_URL_TEST = `${server.baseUrl}/api/v1`;

  const policyPath = writeTempPolicy(`
version: "1.0.0"
name: "ti"
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "\${VT_API_KEY_TEST}"
        base_url: "\${VT_BASE_URL_TEST}"
        min_detections: 2
    - package: "clawdstrike-safe-browsing"
      enabled: true
      config:
        api_key: "\${GSB_API_KEY_TEST}"
        client_id: "\${GSB_CLIENT_ID_TEST}"
        base_url: "\${GSB_BASE_URL_TEST}"
    - package: "clawdstrike-snyk"
      enabled: true
      config:
        api_token: "\${SNYK_API_TOKEN_TEST}"
        org_id: "\${SNYK_ORG_ID_TEST}"
        base_url: "\${SNYK_BASE_URL_TEST}"
        severity_threshold: high
        fail_on_upgradable: true
`);

  const engine = createPolicyEngine({ policyRef: policyPath, resolve: false });

  const fileEvent: PolicyEvent = {
    eventId: 'evt-file',
    eventType: 'file_write',
    timestamp: new Date().toISOString(),
    data: {
      type: 'file',
      path: '/tmp/ok.txt',
      operation: 'write',
      contentBase64: fileContent.toString('base64'),
      contentHash: `sha256:${sha256Hex(fileContent)}`,
    },
  };

  const d1 = await engine.evaluate(fileEvent);
  expect(d1.denied).toBe(true);
  expect(d1.guard).toBe('clawdstrike-virustotal');

  const d2 = await engine.evaluate(fileEvent);
  expect(d2.denied).toBe(true);
  expect(server.counts.vtFiles).toBe(1);

  const netEvent: PolicyEvent = {
    eventId: 'evt-net',
    eventType: 'network_egress',
    timestamp: new Date().toISOString(),
    data: {
      type: 'network',
      host: 'evil.example',
      port: 443,
      protocol: 'tcp',
      url: 'https://evil.example/malware',
    },
  };

  const d3 = await engine.evaluate(netEvent);
  expect(d3.denied).toBe(true);
  expect(d3.guard).toBe('clawdstrike-safe-browsing');

  const snykEvent: PolicyEvent = {
    eventId: 'evt-snyk',
    eventType: 'file_write',
    timestamp: new Date().toISOString(),
    data: {
      type: 'file',
      path: '/tmp/package.json',
      operation: 'write',
      content: '{"name":"demo","version":"1.0.0"}',
    },
  };

  const d4 = await engine.evaluate(snykEvent);
  expect(d4.denied).toBe(true);
  expect(d4.guard).toBe('clawdstrike-snyk');

  await server.close();
});

test('policy load fails closed when env vars are missing', async () => {
  const policyPath = writeTempPolicy(`
version: "1.0.0"
name: "ti"
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "\${VT_API_KEY_DOES_NOT_EXIST}"
`);

  expect(() => createPolicyEngine({ policyRef: policyPath, resolve: false })).toThrow(/missing environment variable/i);
});
