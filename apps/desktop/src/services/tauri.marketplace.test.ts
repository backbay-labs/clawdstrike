import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import {
  installMarketplacePolicy,
  saveMarketplaceProvenanceConfig,
  verifyMarketplaceAttestation,
} from "./tauri";

describe("tauri marketplace helpers", () => {
  const originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalWindow = (globalThis as unknown as { window?: Record<string, unknown> }).window;
  const originalHasWindow = !!originalWindowDescriptor;
  const originalHasTauri = !!originalWindow && "__TAURI__" in originalWindow;
  const originalTauri = originalHasTauri ? originalWindow.__TAURI__ : undefined;

  beforeEach(() => {
    invokeMock.mockReset();
    if (originalWindow && typeof originalWindow === "object" && "__TAURI__" in originalWindow) {
      delete originalWindow.__TAURI__;
    }
    if (!originalHasWindow) delete (globalThis as unknown as { window?: unknown }).window;
  });

  afterEach(() => {
    if (originalWindow && typeof originalWindow === "object") {
      if (originalHasTauri) originalWindow.__TAURI__ = originalTauri;
      else if ("__TAURI__" in originalWindow) delete originalWindow.__TAURI__;
      return;
    }
    if (originalHasWindow) return;
    delete (globalThis as unknown as { window?: unknown }).window;
  });

  it("throws when not running in Tauri", async () => {
    await expect(
      installMarketplacePolicy("http://localhost:9876", "feed-1", "entry-1", "hash-1", "sig-1"),
    ).rejects.toThrow("Marketplace requires Tauri");
    await expect(verifyMarketplaceAttestation("uid-123")).rejects.toThrow(
      "Marketplace requires Tauri",
    );
    await expect(
      saveMarketplaceProvenanceConfig({
        notaryUrl: "https://notary.example",
        proofsApiUrl: null,
        trustedAttesters: [],
        requireVerified: false,
        preferSpine: true,
        trustedWitnessKeys: [],
      }),
    ).rejects.toThrow("Marketplace requires Tauri");
  });

  it("invokes marketplace commands when in Tauri", async () => {
    const win =
      (globalThis as unknown as { window?: Record<string, unknown> }).window ??
      ((globalThis as unknown as { window?: Record<string, unknown> }).window = {});
    win.__TAURI__ = {};

    invokeMock.mockResolvedValueOnce(undefined);
    await expect(
      installMarketplacePolicy("http://localhost:9876", "feed-1", "entry-1", "hash-1", "sig-1"),
    ).resolves.toBeUndefined();
    expect(invokeMock).toHaveBeenLastCalledWith("marketplace_install_policy", {
      daemon_url: "http://localhost:9876",
      feed_id: "feed-1",
      entry_id: "entry-1",
      policy_hash: "hash-1",
      bundle_signature: "sig-1",
    });

    invokeMock.mockResolvedValueOnce(undefined);
    await expect(
      saveMarketplaceProvenanceConfig({
        notaryUrl: "https://notary.example",
        proofsApiUrl: "https://proofs.example",
        trustedAttesters: ["clawdstrike-official"],
        requireVerified: true,
        preferSpine: true,
        trustedWitnessKeys: ["witness-1"],
      }),
    ).resolves.toBeUndefined();
    expect(invokeMock).toHaveBeenLastCalledWith("marketplace_save_provenance_settings", {
      settings: {
        notaryUrl: "https://notary.example",
        proofsApiUrl: "https://proofs.example",
        trustedAttesters: ["clawdstrike-official"],
        requireVerified: true,
        preferSpine: true,
        trustedWitnessKeys: ["witness-1"],
      },
    });

    invokeMock.mockResolvedValueOnce({ valid: true, attester: "clawdstrike-official" });
    await expect(verifyMarketplaceAttestation("uid-123")).resolves.toEqual({
      valid: true,
      attester: "clawdstrike-official",
    });
    expect(invokeMock).toHaveBeenLastCalledWith("marketplace_verify_attestation", {
      uid: "uid-123",
    });
  });
});
