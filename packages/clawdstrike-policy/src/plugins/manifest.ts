export type PluginTrustLevel = 'trusted' | 'untrusted';
export type PluginTrustSandbox = 'node' | 'wasm';
export type PluginGuardHandle =
  | 'file_read'
  | 'file_write'
  | 'command_exec'
  | 'network_egress'
  | 'tool_call'
  | 'patch_apply'
  | 'secret_access'
  | 'custom';

export interface PluginGuardManifestEntry {
  name: string;
  entrypoint: string;
  handles?: PluginGuardHandle[];
  configSchema?: string;
}

export interface PluginVersionCompatibility {
  minVersion?: string;
  maxVersion?: string;
}

export interface PluginCapabilities {
  network: boolean;
  subprocess: boolean;
  filesystem: {
    read: string[];
    write: boolean;
  };
  secrets: {
    access: boolean;
  };
}

export interface PluginResourceLimits {
  maxMemoryMb: number;
  maxCpuMs: number;
  maxTimeoutMs: number;
}

export interface PluginManifest {
  schema?: string;
  version: string;
  name: string;
  displayName?: string;
  description?: string;
  author?: string;
  license?: string;
  clawdstrike?: PluginVersionCompatibility;
  guards: PluginGuardManifestEntry[];
  capabilities: PluginCapabilities;
  resources: PluginResourceLimits;
  trust: {
    level: PluginTrustLevel;
    sandbox: PluginTrustSandbox;
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
  const sandboxRaw = (trust as any).sandbox;
  if (sandboxRaw !== undefined && sandboxRaw !== 'node' && sandboxRaw !== 'wasm') {
    throw new Error('plugin manifest.trust.sandbox must be "node" or "wasm"');
  }
  const sandbox: PluginTrustSandbox = sandboxRaw ?? 'node';

  const compatibility = parseCompatibility((value as any).clawdstrike);
  const capabilities = parseCapabilities((value as any).capabilities);
  const resources = parseResources((value as any).resources);

  const guards = (value as any).guards;
  if (!Array.isArray(guards) || guards.length === 0) {
    throw new Error('plugin manifest.guards must be a non-empty array');
  }

  const guardNames = new Set<string>();
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
    if (guardNames.has(guardName)) {
      throw new Error(`${base}.name duplicates guard: ${guardName}`);
    }
    guardNames.add(guardName);

    const entrypoint = (g as any).entrypoint;
    if (typeof entrypoint !== 'string' || entrypoint.trim() === '') {
      throw new Error(`${base}.entrypoint must be a non-empty string`);
    }

    const handlesRaw = (g as any).handles;
    const handles = parseHandles(handlesRaw, `${base}.handles`);

    const configSchema = (g as any).configSchema;
    if (configSchema !== undefined && (typeof configSchema !== 'string' || configSchema.trim() === '')) {
      throw new Error(`${base}.configSchema must be a non-empty string when provided`);
    }

    parsedGuards.push({
      name: guardName,
      entrypoint,
      handles,
      configSchema,
    });
  }

  return {
    schema:
      typeof (value as any).$schema === 'string' && (value as any).$schema.trim() !== ''
        ? String((value as any).$schema)
        : undefined,
    version,
    name,
    displayName: parseOptionalString((value as any).displayName, 'plugin manifest.displayName'),
    description: parseOptionalString((value as any).description, 'plugin manifest.description'),
    author: parseOptionalString((value as any).author, 'plugin manifest.author'),
    license: parseOptionalString((value as any).license, 'plugin manifest.license'),
    clawdstrike: compatibility,
    guards: parsedGuards,
    capabilities,
    resources,
    trust: { level, sandbox },
  };
}

function parseHandles(value: unknown, base: string): PluginGuardHandle[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${base} must be an array when provided`);
  }

  const out: PluginGuardHandle[] = [];
  for (let i = 0; i < value.length; i++) {
    const v = value[i];
    if (!isPluginGuardHandle(v)) {
      throw new Error(`${base}[${i}] must be a valid handle event type`);
    }
    out.push(v);
  }
  return out;
}

function parseCompatibility(value: unknown): PluginVersionCompatibility | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isPlainObject(value)) {
    throw new Error('plugin manifest.clawdstrike must be an object when provided');
  }

  const minVersion = parseOptionalString(value.minVersion, 'plugin manifest.clawdstrike.minVersion');
  if (minVersion !== undefined && !isStrictSemver(minVersion)) {
    throw new Error('plugin manifest.clawdstrike.minVersion must be strict semver (x.y.z)');
  }

  const maxVersion = parseOptionalString(value.maxVersion, 'plugin manifest.clawdstrike.maxVersion');
  if (maxVersion !== undefined && !isSemverRange(maxVersion)) {
    throw new Error('plugin manifest.clawdstrike.maxVersion must be semver or wildcard range (e.g. 1.x)');
  }

  return { minVersion, maxVersion };
}

function parseCapabilities(value: unknown): PluginCapabilities {
  if (value === undefined) {
    return defaultCapabilities();
  }
  if (!isPlainObject(value)) {
    throw new Error('plugin manifest.capabilities must be an object when provided');
  }

  const network = parseOptionalBoolean(value.network, 'plugin manifest.capabilities.network') ?? false;
  const subprocess =
    parseOptionalBoolean(value.subprocess, 'plugin manifest.capabilities.subprocess') ?? false;

  const filesystemRaw = value.filesystem;
  let filesystem = { read: [] as string[], write: false };
  if (filesystemRaw !== undefined) {
    if (!isPlainObject(filesystemRaw)) {
      throw new Error('plugin manifest.capabilities.filesystem must be an object when provided');
    }

    const readRaw = filesystemRaw.read;
    let read: string[] = [];
    if (readRaw !== undefined) {
      if (readRaw === false) {
        read = [];
      } else if (Array.isArray(readRaw)) {
        read = readRaw.map((v, i) => {
          if (typeof v !== 'string' || v.trim() === '') {
            throw new Error(`plugin manifest.capabilities.filesystem.read[${i}] must be a non-empty string`);
          }
          return v;
        });
      } else {
        throw new Error('plugin manifest.capabilities.filesystem.read must be false or an array of strings');
      }
    }

    const write = parseOptionalBoolean(
      filesystemRaw.write,
      'plugin manifest.capabilities.filesystem.write',
    ) ?? false;
    filesystem = { read, write };
  }

  const secretsRaw = value.secrets;
  let secretsAccess = false;
  if (secretsRaw !== undefined) {
    if (typeof secretsRaw === 'boolean') {
      secretsAccess = secretsRaw;
    } else if (isPlainObject(secretsRaw)) {
      secretsAccess =
        parseOptionalBoolean(secretsRaw.access, 'plugin manifest.capabilities.secrets.access')
        ?? false;
    } else {
      throw new Error('plugin manifest.capabilities.secrets must be a boolean or object');
    }
  }

  return {
    network,
    subprocess,
    filesystem,
    secrets: {
      access: secretsAccess,
    },
  };
}

function parseResources(value: unknown): PluginResourceLimits {
  const defaults = defaultResources();
  if (value === undefined) {
    return defaults;
  }
  if (!isPlainObject(value)) {
    throw new Error('plugin manifest.resources must be an object when provided');
  }

  const maxMemoryMb = parseOptionalPositiveInt(
    value.maxMemoryMb,
    'plugin manifest.resources.maxMemoryMb',
  ) ?? defaults.maxMemoryMb;
  const maxCpuMs = parseOptionalPositiveInt(value.maxCpuMs, 'plugin manifest.resources.maxCpuMs')
    ?? defaults.maxCpuMs;
  const maxTimeoutMs = parseOptionalPositiveInt(
    value.maxTimeoutMs,
    'plugin manifest.resources.maxTimeoutMs',
  ) ?? defaults.maxTimeoutMs;

  return {
    maxMemoryMb,
    maxCpuMs,
    maxTimeoutMs,
  };
}

function parseOptionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${field} must be a non-empty string when provided`);
  }
  return value;
}

function parseOptionalBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'boolean') {
    throw new Error(`${field} must be a boolean when provided`);
  }
  return value;
}

function parseOptionalPositiveInt(value: unknown, field: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new Error(`${field} must be a positive integer when provided`);
  }
  return value;
}

function isPluginGuardHandle(value: unknown): value is PluginGuardHandle {
  return (
    value === 'file_read'
    || value === 'file_write'
    || value === 'command_exec'
    || value === 'network_egress'
    || value === 'tool_call'
    || value === 'patch_apply'
    || value === 'secret_access'
    || value === 'custom'
  );
}

function isStrictSemver(value: string): boolean {
  return /^(\d+)\.(\d+)\.(\d+)$/.test(value);
}

function isSemverRange(value: string): boolean {
  return /^(\d+)\.(\d+)\.(\d+)$/.test(value) || /^(\d+)\.x$/.test(value) || /^(\d+)\.(\d+)\.x$/.test(value);
}

function defaultCapabilities(): PluginCapabilities {
  return {
    network: false,
    subprocess: false,
    filesystem: {
      read: [],
      write: false,
    },
    secrets: {
      access: false,
    },
  };
}

function defaultResources(): PluginResourceLimits {
  return {
    maxMemoryMb: 64,
    maxCpuMs: 100,
    maxTimeoutMs: 5000,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
