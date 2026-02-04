import http from 'node:http';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createPolicyEngineFromPolicy } from './engine.js';
import { CustomGuardRegistry } from './custom-registry.js';
import { loadPolicyFromString } from './policy/loader.js';

async function startCountingServer(): Promise<{
  baseUrl: string;
  counts: { hits: number };
  close: () => Promise<void>;
}> {
  const counts = { hits: 0 };
  const server = http.createServer((_req, res) => {
    counts.hits += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } },
      }),
    );
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

test('policy custom_guards fail closed when registry missing', () => {
  const policy = loadPolicyFromString(
    `
version: "1.1.0"
name: "custom"
custom_guards:
  - id: "acme.deny"
    enabled: true
    config: {}
`,
    { resolve: false },
  );

  expect(() => createPolicyEngineFromPolicy(policy)).toThrow(/CustomGuardRegistry/i);
});

test('custom_guards deny prevents async guard network calls', async () => {
  const server = await startCountingServer();

  const policy = loadPolicyFromString(
    `
version: "1.1.0"
name: "custom"
custom_guards:
  - id: "acme.deny"
    enabled: true
    config: {}
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "dummy"
        base_url: "${server.baseUrl}/api/v3"
        min_detections: 2
`,
    { resolve: false },
  );

  const registry = new CustomGuardRegistry();
  registry.register({
    id: 'acme.deny',
    build: () => ({
      name: 'acme.deny',
      handles: () => true,
      check: () => ({ allowed: false, guard: 'acme.deny', severity: 'high', message: 'Denied by custom guard' }),
    }),
  });

  const engine = createPolicyEngineFromPolicy(policy, { customGuardRegistry: registry });

  const event: PolicyEvent = {
    eventId: 'evt-file',
    eventType: 'file_write',
    timestamp: new Date().toISOString(),
    data: {
      type: 'file',
      path: '/tmp/ok.txt',
      operation: 'write',
      content: 'hello',
    },
  };

  const decision = await engine.evaluate(event);
  expect(decision.denied).toBe(true);
  expect(decision.guard).toBe('acme.deny');
  expect(server.counts.hits).toBe(0);

  await server.close();
});

