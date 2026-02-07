import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createPolicyEngineFromPolicy } from '../engine.js';
import { CustomGuardRegistry } from '../custom-registry.js';
import { loadPolicyFromString } from '../policy/loader.js';
import { inspectPlugin, loadTrustedPluginIntoRegistry, PluginLoader } from './loader.js';

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
  expect(loaded.executionMode).toBe('node');

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

test('gates untrusted high-risk capabilities (scaffold policy)', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-untrusted-risky',
      guards: [{ name: 'acme.deny', entrypoint: './guard.mjs' }],
      trust: { level: 'untrusted', sandbox: 'node' },
      capabilities: {
        subprocess: true,
      },
    }),
    'utf8',
  );
  fs.writeFileSync(
    path.join(dir, 'guard.mjs'),
    `
export default {
  id: "acme.deny",
  build: () => ({
    name: "acme.deny",
    handles: () => true,
    check: () => ({ allowed: true, guard: "acme.deny", severity: "low", message: "Allowed" }),
  }),
};
`,
    'utf8',
  );

  const loader = new PluginLoader({
    trustedOnly: false,
    allowWasmSandbox: false,
  });

  await expect(loader.inspect(dir)).rejects.toThrow(/cannot request subprocess capability/i);
});

test('checks clawdstrike compatibility range during inspect', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-versioned',
      clawdstrike: {
        minVersion: '9.9.9',
      },
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
  build: () => ({
    name: "acme.deny",
    handles: () => true,
    check: () => ({ allowed: true, guard: "acme.deny", severity: "low", message: "Allowed" }),
  }),
};
`,
    'utf8',
  );

  await expect(inspectPlugin(dir)).rejects.toThrow(/requires clawdstrike >= 9.9.9/i);
});

test('loads wasm plugin via CLI bridge runtime', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-wasm',
      guards: [{ name: 'acme.wasm', entrypoint: './guard.wasm' }],
      trust: { level: 'trusted', sandbox: 'wasm' },
      capabilities: {
        network: false,
        subprocess: false,
        filesystem: { read: false, write: false },
        secrets: { access: false },
      },
      resources: {
        maxMemoryMb: 16,
        maxCpuMs: 50,
        maxTimeoutMs: 500,
      },
    }),
    'utf8',
  );
  fs.writeFileSync(path.join(dir, 'guard.wasm'), 'wasm', 'utf8');

  const bridge = path.join(dir, 'mock-bridge.mjs');
  fs.writeFileSync(
    bridge,
    `#!/usr/bin/env node
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  const out = {
    version: 1,
    command: 'guard_wasm_check',
    result: {
      allowed: false,
      guard: 'acme.wasm',
      severity: 'error',
      message: 'Denied by wasm bridge',
      details: { seen: Boolean(input) },
    },
    audit: [],
    exit_code: 2,
  };
  process.stdout.write(JSON.stringify(out));
});`,
    'utf8',
  );
  fs.chmodSync(bridge, 0o755);

  const registry = new CustomGuardRegistry();
  const loader = new PluginLoader({
    trustedOnly: true,
    allowWasmSandbox: true,
    wasmBridge: {
      command: ['node', bridge],
      timeoutMs: 5_000,
    },
  });
  const loaded = await loader.loadIntoRegistry(dir, registry);
  expect(loaded.executionMode).toBe('wasm');
  expect(loaded.registered).toEqual(['acme.wasm']);

  const policy = loadPolicyFromString(
    `
version: "1.2.0"
name: "plugin-wasm"
custom_guards:
  - id: "acme.wasm"
    enabled: true
    config: {}
`,
    { resolve: false },
  );

  const engine = createPolicyEngineFromPolicy(policy, { customGuardRegistry: registry });
  const event: PolicyEvent = {
    eventId: 'evt-wasm',
    eventType: 'tool_call',
    timestamp: new Date().toISOString(),
    data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
  };

  const decision = await engine.evaluate(event);
  expect(decision.status).toBe('deny');
  expect(decision.guard).toBe('acme.wasm');
});

test('wasm plugin handle "custom" only matches custom events', async () => {
  const dir = makeTempPluginDir();
  fs.writeFileSync(
    path.join(dir, 'clawdstrike.plugin.json'),
    JSON.stringify({
      version: '1.0.0',
      name: 'acme-wasm-custom-handles',
      guards: [{ name: 'acme.wasm', entrypoint: './guard.wasm', handles: ['custom'] }],
      trust: { level: 'trusted', sandbox: 'wasm' },
      capabilities: {
        network: false,
        subprocess: false,
        filesystem: { read: false, write: false },
        secrets: { access: false },
      },
      resources: {
        maxMemoryMb: 16,
        maxCpuMs: 50,
        maxTimeoutMs: 500,
      },
    }),
    'utf8',
  );
  fs.writeFileSync(path.join(dir, 'guard.wasm'), 'wasm', 'utf8');

  const bridge = path.join(dir, 'mock-bridge.mjs');
  fs.writeFileSync(
    bridge,
    `#!/usr/bin/env node
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  const out = {
    version: 1,
    command: 'guard_wasm_check',
    result: {
      allowed: false,
      guard: 'acme.wasm',
      severity: 'error',
      message: 'Denied by wasm bridge',
      details: { seen: Boolean(input) },
    },
    audit: [],
    exit_code: 2,
  };
  process.stdout.write(JSON.stringify(out));
});`,
    'utf8',
  );
  fs.chmodSync(bridge, 0o755);

  const registry = new CustomGuardRegistry();
  const loader = new PluginLoader({
    trustedOnly: true,
    allowWasmSandbox: true,
    wasmBridge: {
      command: ['node', bridge],
      timeoutMs: 5_000,
    },
  });
  await loader.loadIntoRegistry(dir, registry);

  const policy = loadPolicyFromString(
    `
version: "1.2.0"
name: "plugin-wasm-custom"
custom_guards:
  - id: "acme.wasm"
    enabled: true
    config: {}
`,
    { resolve: false },
  );

  const engine = createPolicyEngineFromPolicy(policy, { customGuardRegistry: registry });
  const toolEvent: PolicyEvent = {
    eventId: 'evt-tool',
    eventType: 'tool_call',
    timestamp: new Date().toISOString(),
    data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
  };
  const toolDecision = await engine.evaluate(toolEvent);
  expect(toolDecision.status).toBe('allow');

  const customEvent: PolicyEvent = {
    eventId: 'evt-custom',
    eventType: 'custom',
    timestamp: new Date().toISOString(),
    data: { type: 'custom', customType: 'demo', ok: true },
  };
  const customDecision = await engine.evaluate(customEvent);
  expect(customDecision.status).toBe('deny');
  expect(customDecision.guard).toBe('acme.wasm');
});
