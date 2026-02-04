export type PluginTrustLevel = 'trusted' | 'untrusted';
export type PluginTrustSandbox = 'node' | 'wasm';

export interface PluginGuardManifestEntry {
  name: string;
  entrypoint: string;
}

export interface PluginManifest {
  version: string;
  name: string;
  guards: PluginGuardManifestEntry[];
  trust: {
    level: PluginTrustLevel;
    sandbox?: PluginTrustSandbox;
  };
}

export function parsePluginManifest(value: unknown): PluginManifest {
  if (!isPlainObject(value)) {
    throw new Error('plugin manifest must be an object');
  }

  const version = value.version;
  if (typeof version !== 'string' || version.trim() === '') {
    throw new Error('plugin manifest.version must be a non-empty string');
  }

  const name = value.name;
  if (typeof name !== 'string' || name.trim() === '') {
    throw new Error('plugin manifest.name must be a non-empty string');
  }

  const trust = (value as any).trust;
  if (!isPlainObject(trust)) {
    throw new Error('plugin manifest.trust must be an object');
  }
  const level = (trust as any).level;
  if (level !== 'trusted' && level !== 'untrusted') {
    throw new Error('plugin manifest.trust.level must be "trusted" or "untrusted"');
  }
  const sandbox = (trust as any).sandbox;
  if (sandbox !== undefined && sandbox !== 'node' && sandbox !== 'wasm') {
    throw new Error('plugin manifest.trust.sandbox must be "node" or "wasm"');
  }

  const guards = (value as any).guards;
  if (!Array.isArray(guards) || guards.length === 0) {
    throw new Error('plugin manifest.guards must be a non-empty array');
  }

  const parsedGuards: PluginGuardManifestEntry[] = [];
  for (let i = 0; i < guards.length; i++) {
    const g = guards[i];
    const base = `plugin manifest.guards[${i}]`;
    if (!isPlainObject(g)) {
      throw new Error(`${base} must be an object`);
    }

    const guardName = (g as any).name;
    if (typeof guardName !== 'string' || guardName.trim() === '') {
      throw new Error(`${base}.name must be a non-empty string`);
    }

    const entrypoint = (g as any).entrypoint;
    if (typeof entrypoint !== 'string' || entrypoint.trim() === '') {
      throw new Error(`${base}.entrypoint must be a non-empty string`);
    }

    parsedGuards.push({ name: guardName, entrypoint });
  }

  return {
    version,
    name,
    guards: parsedGuards,
    trust: { level, sandbox },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

