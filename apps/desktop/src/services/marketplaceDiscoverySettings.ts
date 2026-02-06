export interface MarketplaceDiscoverySettings {
  enabled: boolean;
  listenPort: number | null;
  bootstrap: string[];
  topic: string | null;
}

const STORAGE_KEY = "sdr:marketplace:discovery";

export const DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS: MarketplaceDiscoverySettings = {
  enabled: false,
  listenPort: null,
  bootstrap: [],
  topic: null,
};

function uniq(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

function normalizeBootstrap(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const items = value
    .filter((v) => typeof v === "string")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return uniq(items).slice(0, 64);
}

function normalizeListenPort(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const n = Math.trunc(value);
  if (n <= 0 || n > 65535) return null;
  return n;
}

function normalizeTopic(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed.slice(0, 128) : null;
}

function normalizeSettings(value: unknown): MarketplaceDiscoverySettings {
  if (typeof value !== "object" || value === null) return { ...DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS };
  const v = value as Record<string, unknown>;
  return {
    enabled: Boolean(v.enabled),
    listenPort: normalizeListenPort(v.listenPort),
    bootstrap: normalizeBootstrap(v.bootstrap),
    topic: normalizeTopic(v.topic),
  };
}

export function loadMarketplaceDiscoverySettings(): MarketplaceDiscoverySettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS };
    const parsed = JSON.parse(raw) as unknown;
    return normalizeSettings(parsed);
  } catch {
    return { ...DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS };
  }
}

export function saveMarketplaceDiscoverySettings(settings: MarketplaceDiscoverySettings): void {
  const normalized = normalizeSettings(settings);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // ignore
  }
}

export function parseMarketplaceDiscoveryBootstrapInput(input: string): string[] {
  const lines = input.split(/\r?\n/g);
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("#")) continue;
    out.push(trimmed);
  }
  return normalizeBootstrap(out);
}

export function formatMarketplaceDiscoveryBootstrapInput(bootstrap: string[]): string {
  return normalizeBootstrap(bootstrap).join("\n");
}

