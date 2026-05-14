/**
 * Plugin Trust Verification Tests
 *
 * Tests for verifyPluginTrust() — Ed25519 signature verification on plugin
 * manifests. Uses real Web Crypto Ed25519 key pairs (no mocks).
 */

import { describe, it, expect } from "vitest";
import { verifyPluginTrust } from "../plugin-trust";
import { createTestManifest } from "../manifest-validation";
import {
  generateOperatorKeypair,
  signCanonical,
} from "../../workbench/operator-crypto";
import type { PluginManifest, InstallationMetadata } from "../types";

/**
 * Helper: create a manifest with a valid Ed25519 signature.
 * Signs the manifest (without the signature field) using the provided secret key,
 * then attaches the signature into installation.signature.
 */
async function createSignedManifest(
  secretKeyHex: string,
  overrides?: Partial<PluginManifest>,
): Promise<PluginManifest> {
  const base = createTestManifest({
    trust: "community",
    installation: {
      downloadUrl: "https://plugins.clawdstrike.dev/test-plugin-1.0.0.tgz",
      size: 12345,
      checksum: "a".repeat(64),
      signature: "", // placeholder, will be replaced
    },
    ...overrides,
  });

  // Build the object to sign: manifest without installation.signature
  const toSign = structuredClone(base);
  delete (toSign.installation as Partial<InstallationMetadata>).signature;

  const signature = await signCanonical(toSign, secretKeyHex);
  base.installation!.signature = signature;
  return base;
}

describe("verifyPluginTrust", () => {
  // Test 1: internal trust tier bypasses signature check
  it('returns { trusted: true, reason: "internal" } for manifest with trust="internal"', async () => {
    const manifest = createTestManifest({ trust: "internal" });

    const result = await verifyPluginTrust(manifest);

    expect(result.trusted).toBe(true);
    expect(result.reason).toBe("internal");
  });

  // Test 2: valid Ed25519 signature passes
  it('returns { trusted: true, reason: "signature_valid" } when signature is valid', async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const manifest = await createSignedManifest(secretKeyHex);

    const result = await verifyPluginTrust(manifest, {
      publisherKey: publicKeyHex,
    });

    expect(result.trusted).toBe(true);
    expect(result.reason).toBe("signature_valid");
  });

  // Test 3: tampered manifest fails signature verification
  it('returns { trusted: false, reason: "signature_invalid" } when manifest is tampered', async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const manifest = await createSignedManifest(secretKeyHex);

    // Tamper with the manifest after signing
    manifest.description = "TAMPERED DESCRIPTION";

    const result = await verifyPluginTrust(manifest, {
      publisherKey: publicKeyHex,
    });

    expect(result.trusted).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  // Test 4: missing signature is rejected
  it('returns { trusted: false, reason: "signature_missing" } when no installation or no signature', async () => {
    // Case A: no installation at all
    const manifestNoInstall = createTestManifest({ trust: "community" });

    const resultA = await verifyPluginTrust(manifestNoInstall);

    expect(resultA.trusted).toBe(false);
    expect(resultA.reason).toBe("signature_missing");

    // Case B: installation present but no signature
    const manifestNoSig = createTestManifest({
      trust: "community",
      installation: {
        downloadUrl: "https://example.com/plugin.tgz",
        size: 100,
        checksum: "b".repeat(64),
        signature: "",
      },
    });

    const resultB = await verifyPluginTrust(manifestNoSig);

    expect(resultB.trusted).toBe(false);
    expect(resultB.reason).toBe("signature_missing");
  });

  // Test 5: missing publisher key is rejected
  it('returns { trusted: false, reason: "publisher_key_missing" } when publisherKey is not provided', async () => {
    const { secretKeyHex } = await generateOperatorKeypair();
    const manifest = await createSignedManifest(secretKeyHex);

    // No publisherKey in options
    const result = await verifyPluginTrust(manifest);

    expect(result.trusted).toBe(false);
    expect(result.reason).toBe("publisher_key_missing");
  });

  // Test 6: allowUnsigned bypasses signature check
  it('returns { trusted: true, reason: "unsigned_allowed" } when allowUnsigned is true and no signature', async () => {
    const manifest = createTestManifest({ trust: "community" });

    const result = await verifyPluginTrust(manifest, { allowUnsigned: true });

    expect(result.trusted).toBe(true);
    expect(result.reason).toBe("unsigned_allowed");
  });

  // Test 7: installation.publisherKey is used when options.publisherKey is omitted
  it('returns { trusted: true, reason: "signature_valid" } when installation.publisherKey is present', async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const manifest = await createSignedManifest(secretKeyHex, {
      installation: {
        downloadUrl: "https://plugins.clawdstrike.dev/test-plugin-1.0.0.tgz",
        size: 12345,
        checksum: "a".repeat(64),
        signature: "",
        publisherKey: publicKeyHex,
      },
    });

    const result = await verifyPluginTrust(manifest);

    expect(result.trusted).toBe(true);
    expect(result.reason).toBe("signature_valid");
  });

  // Test 8: signature signed with wrong key is rejected
  it('returns { trusted: false, reason: "signature_invalid" } when signed with a different key', async () => {
    const signerKeys = await generateOperatorKeypair();
    const verifierKeys = await generateOperatorKeypair();

    // Sign with signerKeys, verify with verifierKeys
    const manifest = await createSignedManifest(signerKeys.secretKeyHex);

    const result = await verifyPluginTrust(manifest, {
      publisherKey: verifierKeys.publicKeyHex,
    });

    expect(result.trusted).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });
});
