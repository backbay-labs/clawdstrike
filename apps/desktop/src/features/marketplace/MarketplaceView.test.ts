// @vitest-environment jsdom

import { describe, expect, it, vi } from "vitest";

vi.mock("@backbay/glia/primitives", () => ({
  Badge: () => null,
  GlassCard: () => null,
  GlowButton: () => null,
  GlowInput: () => null,
}));

vi.mock("@/context/ConnectionContext", () => ({
  useConnection: () => ({ status: "connected", daemonUrl: "http://localhost:9876" }),
}));

vi.mock("@/services/marketplaceProvenanceSettings", () => ({
  loadMarketplaceProvenanceSettings: () => ({
    notaryUrl: null,
    proofsApiUrl: null,
    trustedAttesters: [],
    requireVerified: false,
    preferSpine: true,
    trustedWitnessKeys: [],
  }),
}));

vi.mock("@/services/marketplaceSettings", () => ({
  loadMarketplaceFeedSources: () => [],
  saveMarketplaceFeedSources: vi.fn(),
}));

vi.mock("@/services/tauri", () => ({
  getMarketplaceDiscoveryStatus: vi.fn(),
  installMarketplacePolicy: vi.fn(),
  isTauri: () => true,
  listMarketplacePolicies: vi.fn(),
  saveMarketplaceProvenanceConfig: vi.fn(),
  verifyMarketplaceAttestation: vi.fn(),
}));

import type { MarketplacePolicyDto } from "@/services/tauri";
import { resolveAttestationPointer } from "./MarketplaceView";

function makePolicy(overrides: Partial<MarketplacePolicyDto> = {}): MarketplacePolicyDto {
  return {
    entry_id: "policy-1",
    bundle_uri: "builtin://bundles/default.signed_bundle.json",
    title: "Default Policy",
    description: "Policy description",
    category: "enterprise",
    tags: ["enterprise"],
    author: "BackBay",
    author_url: null,
    icon: null,
    created_at: null,
    updated_at: null,
    attestation_uid: null,
    notary_url: null,
    spine_envelope_hash: null,
    bundle_public_key: "pubkey",
    curator_name: "BackBay Official",
    curator_trust_level: "full",
    install_allowed: true,
    signed_bundle: {
      bundle: {
        version: "1",
        bundle_id: "bundle-1",
        compiled_at: "2026-01-01T00:00:00Z",
        policy: {
          version: "1",
          name: "Default Policy",
          description: "Policy description",
        },
        policy_hash: "hash-1",
        metadata: null,
      },
      signature: "sig",
    },
    ...overrides,
  };
}

describe("resolveAttestationPointer", () => {
  it("uses the configured default notary instead of a feed-provided entry notary", () => {
    const policy = makePolicy({
      attestation_uid: "uid-entry",
      notary_url: "https://feed.notary.example",
    });

    expect(resolveAttestationPointer(policy, "https://trusted.notary.example")).toEqual({
      uid: "uid-entry",
      notaryUrl: "https://trusted.notary.example",
    });
  });

  it("uses the configured default notary instead of metadata notary overrides", () => {
    const policy = makePolicy({
      signed_bundle: {
        bundle: {
          version: "1",
          bundle_id: "bundle-2",
          compiled_at: "2026-01-01T00:00:00Z",
          policy: {
            version: "1",
            name: "Default Policy",
            description: "Policy description",
          },
          policy_hash: "hash-2",
          metadata: {
            marketplace: {
              attestation_uid: "uid-metadata",
              notary_url: "https://feed.notary.example",
            },
          },
        },
        signature: "sig",
      },
    });

    expect(resolveAttestationPointer(policy, "https://trusted.notary.example")).toEqual({
      uid: "uid-metadata",
      notaryUrl: "https://trusted.notary.example",
    });
  });

  it("requires a configured default notary even when feed metadata provides one", () => {
    const policy = makePolicy({
      signed_bundle: {
        bundle: {
          version: "1",
          bundle_id: "bundle-3",
          compiled_at: "2026-01-01T00:00:00Z",
          policy: {
            version: "1",
            name: "Default Policy",
            description: "Policy description",
          },
          policy_hash: "hash-3",
          metadata: {
            attestation_uid: "uid-metadata",
            notary_url: "https://feed.notary.example",
          },
        },
        signature: "sig",
      },
    });

    expect(resolveAttestationPointer(policy, null)).toBeNull();
  });
});
