import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS,
  formatMarketplaceDiscoveryBootstrapInput,
  loadMarketplaceDiscoverySettings,
  parseMarketplaceDiscoveryBootstrapInput,
  saveMarketplaceDiscoverySettings,
} from "./marketplaceDiscoverySettings";

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

describe("marketplaceDiscoverySettings", () => {
  it("parses one bootstrap peer per line and ignores comments", () => {
    const bootstrap = parseMarketplaceDiscoveryBootstrapInput(
      ["", "# comment", "/ip4/1.2.3.4/tcp/1234/p2p/12D3KooW...", " /dns4/example.com/tcp/1/p2p/abc "].join("\n")
    );
    expect(bootstrap).toEqual([
      "/ip4/1.2.3.4/tcp/1234/p2p/12D3KooW...",
      "/dns4/example.com/tcp/1/p2p/abc",
    ]);
  });

  it("formats bootstrap peers as newline-separated", () => {
    expect(formatMarketplaceDiscoveryBootstrapInput(["/ip4/1.2.3.4/tcp/1234/p2p/abc"])).toBe(
      "/ip4/1.2.3.4/tcp/1234/p2p/abc"
    );
  });

  it("round-trips save/load", () => {
    saveMarketplaceDiscoverySettings({
      enabled: true,
      listenPort: 12345,
      bootstrap: ["/ip4/1.2.3.4/tcp/1234/p2p/abc"],
      topic: "clawdstrike/marketplace/v1/discovery",
    });

    expect(loadMarketplaceDiscoverySettings()).toEqual({
      enabled: true,
      listenPort: 12345,
      bootstrap: ["/ip4/1.2.3.4/tcp/1234/p2p/abc"],
      topic: "clawdstrike/marketplace/v1/discovery",
    });
  });

  it("falls back to defaults on invalid storage content", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem("sdr:marketplace:discovery", "{not-json");
    expect(loadMarketplaceDiscoverySettings()).toEqual(DEFAULT_MARKETPLACE_DISCOVERY_SETTINGS);
  });
});

