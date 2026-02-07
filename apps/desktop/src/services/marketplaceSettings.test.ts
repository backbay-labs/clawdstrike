import { describe, expect, it, beforeEach } from "vitest";

import {
  DEFAULT_MARKETPLACE_FEED_SOURCES,
  DEFAULT_IPFS_GATEWAY_SETTINGS,
  DEFAULT_SPINE_MODE_SETTINGS,
  formatMarketplaceFeedSourcesInput,
  loadMarketplaceFeedSources,
  loadIpfsGatewaySettings,
  loadSpineModeSettings,
  parseMarketplaceFeedSourcesInput,
  saveMarketplaceFeedSources,
  saveIpfsGatewaySettings,
  saveSpineModeSettings,
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

describe("ipfsGatewaySettings", () => {
  it("returns defaults when nothing stored", () => {
    const settings = loadIpfsGatewaySettings();
    expect(settings.gateways).toEqual(DEFAULT_IPFS_GATEWAY_SETTINGS.gateways);
    expect(settings.timeoutMs).toBe(DEFAULT_IPFS_GATEWAY_SETTINGS.timeoutMs);
  });

  it("round-trips save/load", () => {
    const custom = {
      gateways: ["https://my-gateway.example.com/ipfs/", "https://dweb.link/ipfs/"],
      timeoutMs: 5000,
    };
    saveIpfsGatewaySettings(custom);
    const loaded = loadIpfsGatewaySettings();
    expect(loaded.gateways).toEqual(custom.gateways);
    expect(loaded.timeoutMs).toBe(5000);
  });

  it("falls back to defaults on invalid storage content", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem("sdr:marketplace:ipfs-gateways", "{broken");
    const settings = loadIpfsGatewaySettings();
    expect(settings.gateways).toEqual(DEFAULT_IPFS_GATEWAY_SETTINGS.gateways);
  });

  it("rejects non-http(s) gateway URLs", () => {
    saveIpfsGatewaySettings({
      gateways: ["ftp://bad.example.com", "https://good.example.com/ipfs/"],
      timeoutMs: 10000,
    });
    const loaded = loadIpfsGatewaySettings();
    expect(loaded.gateways).toEqual(["https://good.example.com/ipfs/"]);
  });

  it("deduplicates gateway URLs", () => {
    saveIpfsGatewaySettings({
      gateways: ["https://gw.example.com/ipfs/", "https://gw.example.com/ipfs/"],
      timeoutMs: 10000,
    });
    const loaded = loadIpfsGatewaySettings();
    expect(loaded.gateways).toEqual(["https://gw.example.com/ipfs/"]);
  });
});

describe("spineModeSettings", () => {
  it("returns defaults when nothing stored", () => {
    const settings = loadSpineModeSettings();
    expect(settings).toEqual(DEFAULT_SPINE_MODE_SETTINGS);
  });

  it("round-trips save/load", () => {
    saveSpineModeSettings({
      natsUrl: "nats://localhost:4222",
      preferSpineMode: true,
    });
    const loaded = loadSpineModeSettings();
    expect(loaded.natsUrl).toBe("nats://localhost:4222");
    expect(loaded.preferSpineMode).toBe(true);
  });

  it("falls back to defaults on invalid storage content", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem("sdr:marketplace:spine-mode", "{broken");
    expect(loadSpineModeSettings()).toEqual(DEFAULT_SPINE_MODE_SETTINGS);
  });

  it("normalizes empty natsUrl to null", () => {
    saveSpineModeSettings({
      natsUrl: "  ",
      preferSpineMode: true,
    });
    const loaded = loadSpineModeSettings();
    expect(loaded.natsUrl).toBeNull();
    expect(loaded.preferSpineMode).toBe(true);
  });
});

