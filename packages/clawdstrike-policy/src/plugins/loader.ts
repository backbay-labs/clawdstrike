import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

import type { CustomGuardFactory } from '../custom-registry.js';
import { CustomGuardRegistry } from '../custom-registry.js';
import {
  parsePluginManifest,
  type PluginCapabilities,
  type PluginManifest,
  type PluginResourceLimits,
} from './manifest.js';

const DEFAULT_CURRENT_VERSION = '0.1.0';

export type PluginLoadResult = {
  root: string;
  manifest: PluginManifest;
  registered: string[];
  executionMode: PluginExecutionMode;
};

export type PluginResolveOptions = {
  fromDir?: string;
};

export type PluginExecutionMode = 'node' | 'wasm';

export interface PluginLoaderOptions extends PluginResolveOptions {
  trustedOnly?: boolean;
  allowWasmSandbox?: boolean;
  currentClawdstrikeVersion?: string;
  maxResources?: Partial<PluginResourceLimits>;
}

export interface PluginInspectResult {
  root: string;
  manifest: PluginManifest;
  executionMode: PluginExecutionMode;
}

export class PluginLoader {
  private readonly options: Required<
    Pick<PluginLoaderOptions, 'trustedOnly' | 'allowWasmSandbox' | 'currentClawdstrikeVersion'>
  > & {
    fromDir: string;
    maxResources: Partial<PluginResourceLimits>;
  };
  private readonly inspected = new Map<string, PluginInspectResult>();

  constructor(options: PluginLoaderOptions = {}) {
    this.options = {
      fromDir: options.fromDir ?? process.cwd(),
      trustedOnly: options.trustedOnly ?? true,
      allowWasmSandbox: options.allowWasmSandbox ?? false,
      currentClawdstrikeVersion: options.currentClawdstrikeVersion ?? DEFAULT_CURRENT_VERSION,
      maxResources: options.maxResources ?? {},
    };
  }

  async inspect(pluginRef: string): Promise<PluginInspectResult> {
    const cached = this.inspected.get(pluginRef);
    if (cached) {
      return cached;
    }

    const root = resolvePluginRoot(pluginRef, this.options.fromDir);
    const manifestPath = path.join(root, 'clawdstrike.plugin.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error(`missing clawdstrike.plugin.json in ${root}`);
    }

    const manifestRaw = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as unknown;
    const manifest = parsePluginManifest(manifestRaw);

    this.validateTrustPolicy(manifest);
    this.validateCompatibility(manifest);
    this.validateCapabilityPolicy(manifest.capabilities, manifest.name, manifest.trust.level);
    this.validateResourceLimits(manifest.resources, manifest.name);

    const result: PluginInspectResult = {
      root,
      manifest,
      executionMode: manifest.trust.sandbox,
    };
    this.inspected.set(pluginRef, result);
    return result;
  }

  async loadIntoRegistry(
    pluginRef: string,
    registry: CustomGuardRegistry,
  ): Promise<PluginLoadResult> {
    const inspected = await this.inspect(pluginRef);

    // WASM path is intentionally scaffolded and guarded until sandbox runtime lands.
    if (inspected.executionMode === 'wasm') {
      throw new Error(
        `WASM plugin loading scaffold is present but runtime is not implemented yet: ${inspected.manifest.name}`,
      );
    }

    const registered: string[] = [];
    for (const g of inspected.manifest.guards) {
      const entryPath = path.resolve(inspected.root, g.entrypoint);
      const mod = await import(pathToFileURL(entryPath).href);
      const factory = extractFactory(mod);
      if (factory.id !== g.name) {
        throw new Error(`plugin guard id mismatch: manifest=${g.name} entrypoint=${factory.id}`);
      }
      registry.register(factory);
      registered.push(factory.id);
    }

    return {
      root: inspected.root,
      manifest: inspected.manifest,
      registered,
      executionMode: inspected.executionMode,
    };
  }

  clearCache(): void {
    this.inspected.clear();
  }

  private validateTrustPolicy(manifest: PluginManifest): void {
    if (this.options.trustedOnly && manifest.trust.level !== 'trusted') {
      throw new Error(`refusing to load untrusted plugin: ${manifest.name}`);
    }
    if (manifest.trust.sandbox === 'wasm' && !this.options.allowWasmSandbox) {
      throw new Error(
        `refusing to load wasm-sandboxed plugin until WASM sandbox is enabled: ${manifest.name}`,
      );
    }
  }

  private validateCompatibility(manifest: PluginManifest): void {
    const compat = manifest.clawdstrike;
    if (!compat) {
      return;
    }

    const current = parseSemver(this.options.currentClawdstrikeVersion);
    if (!current) {
      return;
    }

    if (compat.minVersion) {
      const min = parseSemver(compat.minVersion);
      if (min && compareSemver(current, min) < 0) {
        throw new Error(
          `plugin ${manifest.name} requires clawdstrike >= ${compat.minVersion} (current ${this.options.currentClawdstrikeVersion})`,
        );
      }
    }

    if (compat.maxVersion && !satisfiesMaxVersion(current, compat.maxVersion)) {
      throw new Error(
        `plugin ${manifest.name} requires clawdstrike <= ${compat.maxVersion} (current ${this.options.currentClawdstrikeVersion})`,
      );
    }
  }

  private validateCapabilityPolicy(
    capabilities: PluginCapabilities,
    pluginName: string,
    trustLevel: 'trusted' | 'untrusted',
  ): void {
    // Capability policy stubs: enforce high-risk defaults before sandbox exists.
    if (trustLevel === 'untrusted') {
      if (capabilities.subprocess) {
        throw new Error(`untrusted plugin ${pluginName} cannot request subprocess capability`);
      }
      if (capabilities.filesystem.write) {
        throw new Error(`untrusted plugin ${pluginName} cannot request filesystem write capability`);
      }
      if (capabilities.secrets.access) {
        throw new Error(`untrusted plugin ${pluginName} cannot request secrets access capability`);
      }
    }
  }

  private validateResourceLimits(resources: PluginResourceLimits, pluginName: string): void {
    const max = this.options.maxResources;
    if (typeof max.maxMemoryMb === 'number' && resources.maxMemoryMb > max.maxMemoryMb) {
      throw new Error(
        `plugin ${pluginName} maxMemoryMb=${resources.maxMemoryMb} exceeds loader limit ${max.maxMemoryMb}`,
      );
    }
    if (typeof max.maxCpuMs === 'number' && resources.maxCpuMs > max.maxCpuMs) {
      throw new Error(
        `plugin ${pluginName} maxCpuMs=${resources.maxCpuMs} exceeds loader limit ${max.maxCpuMs}`,
      );
    }
    if (typeof max.maxTimeoutMs === 'number' && resources.maxTimeoutMs > max.maxTimeoutMs) {
      throw new Error(
        `plugin ${pluginName} maxTimeoutMs=${resources.maxTimeoutMs} exceeds loader limit ${max.maxTimeoutMs}`,
      );
    }
  }
}

export async function loadTrustedPluginIntoRegistry(
  pluginRef: string,
  registry: CustomGuardRegistry,
  options: PluginLoaderOptions = {},
): Promise<PluginLoadResult> {
  const loader = new PluginLoader({ ...options, trustedOnly: true, allowWasmSandbox: false });
  return loader.loadIntoRegistry(pluginRef, registry);
}

export async function inspectPlugin(
  pluginRef: string,
  options: PluginLoaderOptions = {},
): Promise<PluginInspectResult> {
  const loader = new PluginLoader(options);
  return loader.inspect(pluginRef);
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

type Semver = [number, number, number];

function parseSemver(value: string): Semver | null {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  if (!m) {
    return null;
  }
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareSemver(a: Semver, b: Semver): number {
  if (a[0] !== b[0]) return a[0] - b[0];
  if (a[1] !== b[1]) return a[1] - b[1];
  return a[2] - b[2];
}

function satisfiesMaxVersion(current: Semver, maxVersion: string): boolean {
  const maxStrict = parseSemver(maxVersion);
  if (maxStrict) {
    return compareSemver(current, maxStrict) <= 0;
  }

  const majorWildcard = /^(\d+)\.x$/.exec(maxVersion);
  if (majorWildcard) {
    return current[0] === Number(majorWildcard[1]);
  }

  const minorWildcard = /^(\d+)\.(\d+)\.x$/.exec(maxVersion);
  if (minorWildcard) {
    return current[0] === Number(minorWildcard[1]) && current[1] === Number(minorWildcard[2]);
  }

  // Unknown max format is treated as unconstrained at this scaffold phase.
  return true;
}
