import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS,
  formatMarketplaceTrustedAttestersInput,
  loadMarketplaceProvenanceSettings,
  parseMarketplaceTrustedAttestersInput,
  saveMarketplaceProvenanceSettings,
} from "./marketplaceProvenanceSettings";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  clear(): void {
    this.store.clear();
  }
}

beforeEach(() => {
  (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
});

describe("marketplaceProvenanceSettings", () => {
  it("parses one attester per line and ignores comments", () => {
    const attesters = parseMarketplaceTrustedAttestersInput(["", "# comment", " 0xabc ", "0xdef"].join("\n"));
    expect(attesters).toEqual(["0xabc", "0xdef"]);
  });

  it("formats attesters as newline-separated", () => {
    expect(formatMarketplaceTrustedAttestersInput(["0xabc", "0xdef"])).toBe("0xabc\n0xdef");
  });

  it("round-trips save/load", () => {
    saveMarketplaceProvenanceSettings({
      notaryUrl: "https://notary.example.com",
      proofsApiUrl: "https://proofs.example.com",
      trustedAttesters: ["0xabc"],
      requireVerified: true,
      preferSpine: true,
      trustedWitnessKeys: ["0xdef"],
    });

    expect(loadMarketplaceProvenanceSettings()).toEqual({
      notaryUrl: "https://notary.example.com",
      proofsApiUrl: "https://proofs.example.com",
      trustedAttesters: ["0xabc"],
      requireVerified: true,
      preferSpine: true,
      trustedWitnessKeys: ["0xdef"],
    });
  });

  it("falls back to defaults on invalid storage content", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem("sdr:marketplace:provenance", "{not-json");
    expect(loadMarketplaceProvenanceSettings()).toEqual(DEFAULT_MARKETPLACE_PROVENANCE_SETTINGS);
  });
});

