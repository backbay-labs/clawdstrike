import { canonicalize } from "./canonical";
import { verifySignature } from "./crypto/sign";

export type CertificationTier = "certified" | "silver" | "gold" | "platinum";

export interface CertificationBadgeIssuer {
  id: string;
  name: string;
  publicKey: string; // base64url (32 bytes)
  signature: string; // base64url (64 bytes)
  signedAt: string; // RFC3339
}

export interface CertificationBadgeSubject {
  type: string;
  id: string;
  name: string;
  metadata?: unknown;
}

export interface CertificationBadgePolicyBinding {
  hash: string;
  version: string;
  ruleset?: string;
}

export interface CertificationBadgeEvidenceBinding {
  receiptCount: number;
  merkleRoot?: string;
  auditLogRef?: string;
}

export interface CertificationBadgeCertificationBinding {
  tier: CertificationTier;
  issueDate: string;
  expiryDate: string;
  frameworks: string[];
}

export interface CertificationBadge {
  certificationId: string;
  version: string;
  subject: CertificationBadgeSubject;
  certification: CertificationBadgeCertificationBinding;
  policy: CertificationBadgePolicyBinding;
  evidence: CertificationBadgeEvidenceBinding;
  issuer: CertificationBadgeIssuer;
}

function unsignedBadgePayload(badge: CertificationBadge): any {
  const issuerWithoutSig = {
    id: badge.issuer.id,
    name: badge.issuer.name,
    publicKey: badge.issuer.publicKey,
    signedAt: badge.issuer.signedAt,
  };

  return {
    certificationId: badge.certificationId,
    version: badge.version,
    subject: badge.subject,
    certification: badge.certification,
    policy: badge.policy,
    evidence: badge.evidence,
    issuer: issuerWithoutSig,
  };
}

export async function verifyCertificationBadge(badge: CertificationBadge): Promise<boolean> {
  try {
    const unsigned = unsignedBadgePayload(badge);
    const canonical = canonicalize(unsigned);
    const message = new TextEncoder().encode(canonical);

    const publicKey = new Uint8Array(Buffer.from(badge.issuer.publicKey, "base64url"));
    if (publicKey.length !== 32) return false;

    const signature = new Uint8Array(Buffer.from(badge.issuer.signature, "base64url"));
    if (signature.length !== 64) return false;

    return await verifySignature(message, signature, publicKey);
  } catch {
    return false;
  }
}

