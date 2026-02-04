import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

import type { CustomGuardFactory } from '../custom-registry.js';
import { CustomGuardRegistry } from '../custom-registry.js';
import { parsePluginManifest, type PluginManifest } from './manifest.js';

export type PluginLoadResult = {
  root: string;
  manifest: PluginManifest;
  registered: string[];
};

export type PluginResolveOptions = {
  fromDir?: string;
};

export async function loadTrustedPluginIntoRegistry(
  pluginRef: string,
  registry: CustomGuardRegistry,
  options: PluginResolveOptions = {},
): Promise<PluginLoadResult> {
  const root = resolvePluginRoot(pluginRef, options.fromDir ?? process.cwd());
  const manifestPath = path.join(root, 'clawdstrike.plugin.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`missing clawdstrike.plugin.json in ${root}`);
  }

  const manifestRaw = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as unknown;
  const manifest = parsePluginManifest(manifestRaw);

  // Trusted-only (dev-mode) loader. Untrusted/WASM requires a real sandbox boundary.
  if (manifest.trust.level !== 'trusted') {
    throw new Error(`refusing to load untrusted plugin: ${manifest.name}`);
  }
  if (manifest.trust.sandbox === 'wasm') {
    throw new Error(`refusing to load wasm-sandboxed plugin until WASM sandbox is implemented: ${manifest.name}`);
  }

  const registered: string[] = [];
  for (const g of manifest.guards) {
    const entryPath = path.resolve(root, g.entrypoint);
    const mod = await import(pathToFileURL(entryPath).href);
    const factory = extractFactory(mod);
    if (factory.id !== g.name) {
      throw new Error(`plugin guard id mismatch: manifest=${g.name} entrypoint=${factory.id}`);
    }
    registry.register(factory);
    registered.push(factory.id);
  }

  return { root, manifest, registered };
}

export function resolvePluginRoot(pluginRef: string, fromDir: string): string {
  const maybePath = path.isAbsolute(pluginRef) ? pluginRef : path.resolve(fromDir, pluginRef);
  if (fs.existsSync(maybePath)) {
    const stat = fs.statSync(maybePath);
    return stat.isDirectory() ? maybePath : path.dirname(maybePath);
  }

  const require = createRequire(import.meta.url);
  const pkgJsonPath = require.resolve(`${pluginRef}/package.json`, { paths: [fromDir] });
  return path.dirname(pkgJsonPath);
}

function extractFactory(mod: any): CustomGuardFactory {
  const candidate = mod?.factory ?? mod?.default ?? mod;
  if (!isFactory(candidate)) {
    throw new Error('invalid plugin guard entrypoint: expected CustomGuardFactory export');
  }
  return candidate;
}

function isFactory(value: any): value is CustomGuardFactory {
  return Boolean(value) && typeof value === 'object' && typeof value.id === 'string' && typeof value.build === 'function';
}

