import { describe, expect, it } from "vitest";

import { canonicalize } from "../src/canonical";
import { generateKeypair, signMessage } from "../src/crypto/sign";
import {
  type CertificationBadge,
  verifyCertificationBadge,
} from "../src/certification-badge";

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function signBadge(badge: CertificationBadge, privateKey: Uint8Array): Promise<CertificationBadge> {
  const issuerWithoutSig = {
    id: badge.issuer.id,
    name: badge.issuer.name,
    publicKey: badge.issuer.publicKey,
    signedAt: badge.issuer.signedAt,
  };

  const unsigned = {
    certificationId: badge.certificationId,
    version: badge.version,
    subject: badge.subject,
    certification: badge.certification,
    policy: badge.policy,
    evidence: badge.evidence,
    issuer: issuerWithoutSig,
  };

  const canonical = canonicalize(unsigned);
  const message = new TextEncoder().encode(canonical);
  const sig = await signMessage(message, privateKey);

  return {
    ...badge,
    issuer: {
      ...badge.issuer,
      signature: toBase64Url(sig),
    },
  };
}

describe("certification badge", () => {
  it("verifies a signed badge", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const badge: CertificationBadge = {
      certificationId: "cert_test_1",
      version: "1.0.0",
      subject: { type: "agent", id: "agent_1", name: "test-agent" },
      certification: {
        tier: "silver",
        issueDate: "2026-02-04T00:00:00Z",
        expiryDate: "2026-03-06T00:00:00Z",
        frameworks: ["soc2"],
      },
      policy: { hash: "sha256:deadbeef", version: "1.0.0", ruleset: "clawdstrike:strict" },
      evidence: { receiptCount: 0 },
      issuer: {
        id: "iss_clawdstrike",
        name: "Clawdstrike Certification Authority",
        publicKey: toBase64Url(publicKey),
        signature: "",
        signedAt: "2026-02-04T00:00:00Z",
      },
    };

    const signed = await signBadge(badge, privateKey);
    expect(await verifyCertificationBadge(signed)).toBe(true);

    const tampered: CertificationBadge = {
      ...signed,
      subject: { ...signed.subject, name: "tampered" },
    };
    expect(await verifyCertificationBadge(tampered)).toBe(false);
  });
});

