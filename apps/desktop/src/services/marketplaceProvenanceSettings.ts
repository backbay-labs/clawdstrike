export interface MarketplaceProvenanceSettings {
  notaryUrl: string | null;
  trustedAttesters: string[];
  requireVerified: boolean;
}

const STORAGE_KEY = "sdr:marketplace:provenance";

export const DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS: MarketplaceProvenanceSettings = {
  notaryUrl: null,
  trustedAttesters: [],
  requireVerified: false,
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

function normalizeTrustedAttesters(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const items = value
    .filter((v) => typeof v === "string")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return uniq(items).slice(0, 64);
}

function normalizeNotaryUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed.slice(0, 512) : null;
}

function normalizeSettings(value: unknown): MarketplaceProvenanceSettings {
  if (typeof value !== "object" || value === null) return { ...DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS };
  const v = value as Record<string, unknown>;
  return {
    notaryUrl: normalizeNotaryUrl(v.notaryUrl),
    trustedAttesters: normalizeTrustedAttesters(v.trustedAttesters),
    requireVerified: Boolean(v.requireVerified),
  };
}

export function loadMarketplaceProvenanceSettings(): MarketplaceProvenanceSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS };
    const parsed = JSON.parse(raw) as unknown;
    return normalizeSettings(parsed);
  } catch {
    return { ...DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS };
  }
}

export function saveMarketplaceProvenanceSettings(settings: MarketplaceProvenanceSettings): void {
  const normalized = normalizeSettings(settings);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // ignore
  }
}

export function parseMarketplaceTrustedAttestersInput(input: string): string[] {
  const lines = input.split(/\r?\n/g);
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("#")) continue;
    out.push(trimmed);
  }
  return normalizeTrustedAttesters(out);
}

export function formatMarketplaceTrustedAttestersInput(attesters: string[]): string {
  return normalizeTrustedAttesters(attesters).join("\n");
}

