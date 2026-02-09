import { parsePluginManifest } from './manifest.js';

test('parses minimal manifest and applies safe defaults', () => {
  const manifest = parsePluginManifest({
    version: '1.0.0',
    name: 'acme-guard',
    guards: [{ name: 'acme.deny', entrypoint: './dist/guard.js' }],
    trust: { level: 'trusted' },
  });

  expect(manifest.trust.sandbox).toBe('node');
  expect(manifest.capabilities.network).toBe(false);
  expect(manifest.capabilities.subprocess).toBe(false);
  expect(manifest.capabilities.filesystem.write).toBe(false);
  expect(manifest.capabilities.filesystem.read).toEqual([]);
  expect(manifest.capabilities.secrets.access).toBe(false);
  expect(manifest.resources.maxMemoryMb).toBe(64);
  expect(manifest.resources.maxCpuMs).toBe(100);
  expect(manifest.resources.maxTimeoutMs).toBe(5000);
});

test('rejects duplicate guard names', () => {
  expect(() =>
    parsePluginManifest({
      version: '1.0.0',
      name: 'acme-guard',
      guards: [
        { name: 'acme.deny', entrypoint: './dist/a.js' },
        { name: 'acme.deny', entrypoint: './dist/b.js' },
      ],
      trust: { level: 'trusted' },
    }),
  ).toThrow(/duplicates guard/i);
});

test('rejects invalid compatibility semver', () => {
  expect(() =>
    parsePluginManifest({
      version: '1.0.0',
      name: 'acme-guard',
      clawdstrike: { minVersion: '1.x' },
      guards: [{ name: 'acme.deny', entrypoint: './dist/guard.js' }],
      trust: { level: 'trusted' },
    }),
  ).toThrow(/minVersion must be strict semver/i);
});

test('accepts extended capability structure', () => {
  const manifest = parsePluginManifest({
    version: '1.0.0',
    name: 'acme-guard',
    guards: [
      {
        name: 'acme.deny',
        entrypoint: './dist/guard.js',
        handles: ['tool_call', 'file_write'],
      },
    ],
    capabilities: {
      network: true,
      filesystem: {
        read: ['**/*.md'],
        write: false,
      },
      secrets: { access: false },
      subprocess: false,
    },
    resources: {
      maxMemoryMb: 32,
      maxCpuMs: 50,
      maxTimeoutMs: 1000,
    },
    trust: { level: 'trusted', sandbox: 'node' },
  });

  expect(manifest.guards[0]?.handles).toEqual(['tool_call', 'file_write']);
  expect(manifest.capabilities.network).toBe(true);
  expect(manifest.capabilities.filesystem.read).toEqual(['**/*.md']);
  expect(manifest.resources.maxMemoryMb).toBe(32);
});

