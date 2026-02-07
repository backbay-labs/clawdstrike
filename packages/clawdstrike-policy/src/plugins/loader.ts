import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';

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
  wasmBridge?: WasmExecutionBridgeOptions;
}

export interface WasmExecutionBridgeOptions {
  command?: string[];
  timeoutMs?: number;
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
    wasmBridge: Required<WasmExecutionBridgeOptions>;
  };
  private readonly inspected = new Map<string, PluginInspectResult>();

  constructor(options: PluginLoaderOptions = {}) {
    this.options = {
      fromDir: options.fromDir ?? process.cwd(),
      trustedOnly: options.trustedOnly ?? true,
      allowWasmSandbox: options.allowWasmSandbox ?? false,
      currentClawdstrikeVersion: options.currentClawdstrikeVersion ?? DEFAULT_CURRENT_VERSION,
      maxResources: options.maxResources ?? {},
      wasmBridge: {
        command:
          options.wasmBridge?.command && options.wasmBridge.command.length > 0
            ? [...options.wasmBridge.command]
            : [process.env.HUSH_PATH ?? 'hush'],
        timeoutMs: options.wasmBridge?.timeoutMs ?? 15_000,
      },
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

    if (inspected.executionMode === 'wasm') {
      const registered = this.loadWasmIntoRegistry(inspected, registry);
      return {
        root: inspected.root,
        manifest: inspected.manifest,
        registered,
        executionMode: inspected.executionMode,
      };
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

  private loadWasmIntoRegistry(
    inspected: PluginInspectResult,
    registry: CustomGuardRegistry,
  ): string[] {
    const registered: string[] = [];

    for (const g of inspected.manifest.guards) {
      const wasmPath = path.resolve(inspected.root, g.entrypoint);
      if (!fs.existsSync(wasmPath)) {
        throw new Error(`missing wasm guard entrypoint for ${g.name}: ${wasmPath}`);
      }

      const handles = new Set<string>(Array.isArray(g.handles) ? g.handles : []);
      const pluginCapabilities = inspected.manifest.capabilities;
      const pluginResources = inspected.manifest.resources;

      registry.register({
        id: g.name,
        build: (config) => ({
          name: g.name,
          handles: (event) => {
            if (handles.size === 0) return true;
            const action = mapPolicyEventToGuardHandle(event?.eventType);
            return handles.has(action) || handles.has('custom');
          },
          check: async (event) => {
            const bridge = await invokeWasmBridge({
              command: this.options.wasmBridge.command,
              timeoutMs: this.options.wasmBridge.timeoutMs,
              entrypoint: wasmPath,
              guard: g.name,
              payload: event,
              actionType: mapPolicyEventToGuardHandle(event?.eventType),
              config,
              capabilities: pluginCapabilities,
              resources: pluginResources,
            });
            return bridge;
          },
        }),
      });

      registered.push(g.name);
    }

    return registered;
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

type BridgeInvocation = {
  command: string[];
  timeoutMs: number;
  entrypoint: string;
  guard: string;
  payload: unknown;
  actionType?: string;
  config: Record<string, unknown>;
  capabilities: PluginCapabilities;
  resources: PluginResourceLimits;
};

async function invokeWasmBridge(args: BridgeInvocation): Promise<{
  allowed: boolean;
  guard: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details?: Record<string, unknown>;
}> {
  const [bin, ...prefix] = args.command;
  if (!bin) {
    throw new Error('invalid wasm bridge command: missing executable');
  }

  const procArgs: string[] = [
    ...prefix,
    'guard',
    'wasm-check',
    '--entrypoint',
    args.entrypoint,
    '--guard',
    args.guard,
    '--input-json',
    '-',
    '--config-json',
    JSON.stringify(args.config ?? {}),
    '--max-memory-mb',
    String(args.resources.maxMemoryMb),
    '--max-cpu-ms',
    String(args.resources.maxCpuMs),
    '--max-timeout-ms',
    String(args.resources.maxTimeoutMs),
    '--json',
  ];

  if (args.actionType) {
    procArgs.push('--action-type', args.actionType);
  }
  if (args.capabilities.network) {
    procArgs.push('--allow-network');
  }
  if (args.capabilities.subprocess) {
    procArgs.push('--allow-subprocess');
  }
  if (Array.isArray(args.capabilities.filesystem?.read) && args.capabilities.filesystem.read.length > 0) {
    procArgs.push('--allow-fs-read');
  }
  if (args.capabilities.filesystem?.write) {
    procArgs.push('--allow-fs-write');
  }
  if (args.capabilities.secrets?.access) {
    procArgs.push('--allow-secrets');
  }

  const payloadText = JSON.stringify(args.payload ?? {});
  const output = await runChildJson(bin, procArgs, payloadText, args.timeoutMs);
  const result = normalizeBridgeResult(output, args.guard);
  return result;
}

async function runChildJson(
  command: string,
  args: string[],
  stdinPayload: string,
  timeoutMs: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`wasm bridge timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) {
        reject(new Error(`wasm bridge terminated with signal ${signal}: ${stderr || stdout}`));
        return;
      }
      if (code === null || code > 2) {
        reject(new Error(`wasm bridge failed with exit code ${String(code)}: ${stderr || stdout}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(new Error(`wasm bridge returned non-JSON output: ${stdout || stderr || String(error)}`));
      }
    });

    child.stdin.write(stdinPayload);
    child.stdin.end();
  });
}

function normalizeBridgeResult(
  output: unknown,
  guardFallback: string,
): {
  allowed: boolean;
  guard: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details?: Record<string, unknown>;
} {
  if (!isPlainObject(output)) {
    throw new Error('wasm bridge returned invalid payload');
  }
  if (isPlainObject(output.error)) {
    const message = typeof output.error.message === 'string'
      ? output.error.message
      : 'wasm bridge error';
    throw new Error(message);
  }
  if (!isPlainObject(output.result)) {
    throw new Error('wasm bridge returned payload without result');
  }

  const r = output.result as Record<string, unknown>;
  const allowed = typeof r.allowed === 'boolean' ? r.allowed : false;
  const guard = typeof r.guard === 'string' && r.guard.length > 0 ? r.guard : guardFallback;
  const message = typeof r.message === 'string' && r.message.length > 0
    ? r.message
    : allowed ? 'Allowed' : 'Denied';
  const severity = toCanonicalSeverity(r.severity, allowed);
  const details = isPlainObject(r.details) ? (r.details as Record<string, unknown>) : undefined;

  return { allowed, guard, severity, message, details };
}

function toCanonicalSeverity(
  value: unknown,
  allowed: boolean,
): 'low' | 'medium' | 'high' | 'critical' {
  const raw = typeof value === 'string' ? value.toLowerCase() : '';
  if (raw === 'critical') return 'critical';
  if (raw === 'high' || raw === 'error') return 'high';
  if (raw === 'medium' || raw === 'warning' || raw === 'warn') return 'medium';
  if (raw === 'low' || raw === 'info') return 'low';
  return allowed ? 'low' : 'high';
}

function mapPolicyEventToGuardHandle(eventType: unknown): string {
  switch (String(eventType ?? '')) {
    case 'file_read':
      return 'file_read';
    case 'file_write':
      return 'file_write';
    case 'command_exec':
      return 'command_exec';
    case 'network_egress':
      return 'network_egress';
    case 'tool_call':
      return 'tool_call';
    case 'patch_apply':
      return 'patch_apply';
    case 'secret_access':
      return 'secret_access';
    default:
      return 'custom';
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
