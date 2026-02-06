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

