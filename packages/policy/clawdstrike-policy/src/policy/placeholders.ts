const PLACEHOLDER_RE = /\$\{([^}]+)\}/g;

export function resolvePlaceholdersInString(input: string): string {
  return input.replaceAll(PLACEHOLDER_RE, (_, raw: string) => {
    const envName = envVarForPlaceholder(raw);
    const value = process.env[envName];
    if (value === undefined) {
      throw new Error(`missing environment variable ${envName}`);
    }
    return value;
  });
}

export function resolvePlaceholders(value: unknown): unknown {
  if (typeof value === 'string') {
    return resolvePlaceholdersInString(value);
  }
  if (Array.isArray(value)) {
    return value.map((v) => resolvePlaceholders(v));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = resolvePlaceholders(v);
    }
    return out;
  }
  return value;
}

function envVarForPlaceholder(raw: string): string {
  if (raw.startsWith('secrets.')) {
    const name = raw.slice('secrets.'.length);
    if (!name) {
      throw new Error('placeholder ${secrets.} is invalid');
    }
    return name;
  }
  if (!raw) {
    throw new Error('placeholder ${} is invalid');
  }
  return raw;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

