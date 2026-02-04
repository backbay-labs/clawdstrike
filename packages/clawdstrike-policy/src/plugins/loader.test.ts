import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createPolicyEngineFromPolicy } from '../engine.js';
import { CustomGuardRegistry } from '../custom-registry.js';
import { loadPolicyFromString } from '../policy/loader.js';
import { loadTrustedPluginIntoRegistry } from './loader.js';

function makeTempPluginDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'clawdstrike-plugin-'));
}

test('refuses untrusted plugins (trusted-only loader)', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-untrusted',
      guards: [{ name: 'acme.deny', entrypoint: './guard.mjs' }],
      trust: { level: 'untrusted', sandbox: 'wasm' },
    }),
    'utf8',
  );

  const registry = new CustomGuardRegistry();
  await expect(loadTrustedPluginIntoRegistry(dir, registry)).rejects.toThrow(/untrusted/i);
});

test('loads a trusted plugin and registers guard factories', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-trusted',
      guards: [{ name: 'acme.deny', entrypoint: './guard.mjs' }],
      trust: { level: 'trusted', sandbox: 'node' },
    }),
    'utf8',
  );

  fs.writeFileSync(
    path.join(dir, 'guard.mjs'),
    `
export default {
  id: "acme.deny",
  build: (_config) => ({
    name: "acme.deny",
    handles: () => true,
    check: () => ({ allowed: false, guard: "acme.deny", severity: "high", message: "Denied" }),
  }),
};
`,
    'utf8',
  );

  const registry = new CustomGuardRegistry();
  const loaded = await loadTrustedPluginIntoRegistry(dir, registry);
  expect(loaded.registered).toEqual(['acme.deny']);

  const policy = loadPolicyFromString(
    `
version: "1.1.0"
name: "plugin"
custom_guards:
  - id: "acme.deny"
    enabled: true
    config: {}
`,
    { resolve: false },
  );

  const engine = createPolicyEngineFromPolicy(policy, { customGuardRegistry: registry });
  const event: PolicyEvent = {
    eventId: 'evt-plugin',
    eventType: 'tool_call',
    timestamp: new Date().toISOString(),
    data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
  };

  const decision = await engine.evaluate(event);
  expect(decision.status).toBe('deny');
  expect(decision.guard).toBe('acme.deny');
});

