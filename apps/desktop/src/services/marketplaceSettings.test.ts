import { describe, expect, it, beforeEach } from "vitest";

import {
  DEFAULT_MARKETPLACE_FEED_SOURCES,
  formatMarketplaceFeedSourcesInput,
  loadMarketplaceFeedSources,
  parseMarketplaceFeedSourcesInput,
  saveMarketplaceFeedSources,
} from "./marketplaceSettings";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

beforeEach(() => {
  (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
});

describe("marketplaceSettings", () => {
  it("parses one source per line and ignores comments", () => {
    const sources = parseMarketplaceFeedSourcesInput(
      ["", "# comment", " builtin ", "ipfs://bafy...", "https://example.com/feed.json"].join("\n")
    );
    expect(sources).toEqual(["builtin", "ipfs://bafy...", "https://example.com/feed.json"]);
  });

  it("formats sources as newline-separated", () => {
    expect(formatMarketplaceFeedSourcesInput(["builtin", "ipfs://cid"])).toBe("builtin\nipfs://cid");
  });

  it("round-trips save/load", () => {
    saveMarketplaceFeedSources(["builtin", "ipfs://cid"]);
    expect(loadMarketplaceFeedSources()).toEqual(["builtin", "ipfs://cid"]);
  });

  it("falls back to default sources on invalid storage content", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem("sdr:marketplace:sources", "{not-json");
    expect(loadMarketplaceFeedSources()).toEqual(DEFAULT_MARKETPLACE_FEED_SOURCES);
  });
});

