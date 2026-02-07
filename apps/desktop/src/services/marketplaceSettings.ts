const STORAGE_KEY = "sdr:marketplace:sources";

export const DEFAULT_MARKETPLACE_FEED_SOURCES = ["builtin"];

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

function normalizeSources(value: unknown): string[] {
  if (!Array.isArray(value)) return DEFAULT_MARKETPLACE_FEED_SOURCES.slice();

  const sources = value
    .filter((v) => typeof v === "string")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  return uniq(sources).slice(0, 16);
}

export function loadMarketplaceFeedSources(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_MARKETPLACE_FEED_SOURCES.slice();
    const parsed = JSON.parse(raw) as unknown;
    const sources = normalizeSources(parsed);
    return sources.length > 0 ? sources : DEFAULT_MARKETPLACE_FEED_SOURCES.slice();
  } catch {
    return DEFAULT_MARKETPLACE_FEED_SOURCES.slice();
  }
}

export function saveMarketplaceFeedSources(sources: string[]): void {
  const normalized = normalizeSources(sources);
  const value = normalized.length > 0 ? normalized : DEFAULT_MARKETPLACE_FEED_SOURCES.slice();
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    // ignore
  }
}

export function parseMarketplaceFeedSourcesInput(input: string): string[] {
  const lines = input.split(/\r?\n/g);
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("#")) continue;
    out.push(trimmed);
  }
  return normalizeSources(out);
}

export function formatMarketplaceFeedSourcesInput(sources: string[]): string {
  return normalizeSources(sources).join("\n");
}

// ---------------------------------------------------------------------------
// IPFS gateway settings
// ---------------------------------------------------------------------------

const IPFS_GATEWAY_STORAGE_KEY = "sdr:marketplace:ipfs-gateways";

export interface IpfsGatewaySettings {
  /** Ordered list of IPFS gateway base URLs */
  gateways: string[];
  /** Timeout per gateway in ms */
  timeoutMs: number;
}

export const DEFAULT_IPFS_GATEWAY_SETTINGS: IpfsGatewaySettings = {
  gateways: [
    "https://gateway.pinata.cloud/ipfs/",
    "https://dweb.link/ipfs/",
    "https://ipfs.io/ipfs/",
  ],
  timeoutMs: 10000,
};

function normalizeGateways(value: unknown): string[] {
  if (!Array.isArray(value)) return DEFAULT_IPFS_GATEWAY_SETTINGS.gateways.slice();
  return uniq(
    value
      .filter((v) => typeof v === "string")
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && (s.startsWith("https://") || s.startsWith("http://")))
  ).slice(0, 16);
}

export function loadIpfsGatewaySettings(): IpfsGatewaySettings {
  try {
    const raw = localStorage.getItem(IPFS_GATEWAY_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_IPFS_GATEWAY_SETTINGS, gateways: DEFAULT_IPFS_GATEWAY_SETTINGS.gateways.slice() };
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const gateways = normalizeGateways(parsed.gateways);
    const timeoutMs =
      typeof parsed.timeoutMs === "number" && parsed.timeoutMs > 0
        ? parsed.timeoutMs
        : DEFAULT_IPFS_GATEWAY_SETTINGS.timeoutMs;
    return {
      gateways: gateways.length > 0 ? gateways : DEFAULT_IPFS_GATEWAY_SETTINGS.gateways.slice(),
      timeoutMs,
    };
  } catch {
    return { ...DEFAULT_IPFS_GATEWAY_SETTINGS, gateways: DEFAULT_IPFS_GATEWAY_SETTINGS.gateways.slice() };
  }
}

export function saveIpfsGatewaySettings(settings: IpfsGatewaySettings): void {
  const gateways = normalizeGateways(settings.gateways);
  const timeoutMs =
    typeof settings.timeoutMs === "number" && settings.timeoutMs > 0
      ? settings.timeoutMs
      : DEFAULT_IPFS_GATEWAY_SETTINGS.timeoutMs;
  try {
    localStorage.setItem(
      IPFS_GATEWAY_STORAGE_KEY,
      JSON.stringify({
        gateways: gateways.length > 0 ? gateways : DEFAULT_IPFS_GATEWAY_SETTINGS.gateways.slice(),
        timeoutMs,
      })
    );
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Spine mode settings (marketplace-to-Spine unification)
// ---------------------------------------------------------------------------

const SPINE_MODE_STORAGE_KEY = "sdr:marketplace:spine-mode";

export interface SpineModeSettings {
  /** NATS server URL for Spine head subscriptions (null = disabled). */
  natsUrl: string | null;
  /** Whether to prefer Spine-mode feed loading over legacy HTTP/IPFS. */
  preferSpineMode: boolean;
}

export const DEFAULT_SPINE_MODE_SETTINGS: SpineModeSettings = {
  natsUrl: null,
  preferSpineMode: false,
};

function normalizeNatsUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed.slice(0, 512) : null;
}

function normalizeSpineModeSettings(value: unknown): SpineModeSettings {
  if (typeof value !== "object" || value === null) return { ...DEFAULT_SPINE_MODE_SETTINGS };
  const v = value as Record<string, unknown>;
  return {
    natsUrl: normalizeNatsUrl(v.natsUrl),
    preferSpineMode: v.preferSpineMode !== undefined ? Boolean(v.preferSpineMode) : false,
  };
}

export function loadSpineModeSettings(): SpineModeSettings {
  try {
    const raw = localStorage.getItem(SPINE_MODE_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SPINE_MODE_SETTINGS };
    const parsed = JSON.parse(raw) as unknown;
    return normalizeSpineModeSettings(parsed);
  } catch {
    return { ...DEFAULT_SPINE_MODE_SETTINGS };
  }
}

export function saveSpineModeSettings(settings: SpineModeSettings): void {
  const normalized = normalizeSpineModeSettings(settings);
  try {
    localStorage.setItem(SPINE_MODE_STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // ignore
  }
}

