import {
  FINDING_ENVELOPE_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  extractFindingEnvelopeSignableFields,
  extractRevocationEnvelopeSignableFields,
  hashProtocolPayload,
  matchesIssuerAttestation,
  type DurablePublishMetadata,
  type FindingEnvelope,
  type HubTrustPolicy,
  type RevocationEnvelope,
} from "./swarm-protocol";
import { verifyDetachedPayload } from "./signature-adapter";

export type FindingTrustPolicyRejectionReason =
  | "blocked_issuer"
  | "untrusted_issuer"
  | "disallowed_schema"
  | "missing_attestation"
  | "invalid_attestation"
  | "missing_witness_proofs";

export type FindingTrustPolicyDecision =
  | { accepted: true }
  | { accepted: false; reason: FindingTrustPolicyRejectionReason };

export const DEFAULT_HUB_TRUST_POLICY: HubTrustPolicy = Object.freeze({
  trustedIssuers: [],
  blockedIssuers: [],
  requireAttestation: false,
  requireWitnessProofs: false,
  allowedSchemas: [FINDING_ENVELOPE_SCHEMA, REVOCATION_ENVELOPE_SCHEMA],
});

export const FAIL_CLOSED_HUB_TRUST_POLICY: HubTrustPolicy = Object.freeze({
  trustedIssuers: [],
  blockedIssuers: [],
  requireAttestation: false,
  requireWitnessProofs: false,
  allowedSchemas: [],
});

function hasWitnessProofs(publish: DurablePublishMetadata | undefined): boolean {
  return Array.isArray(publish?.witnessProofs) && publish.witnessProofs.length > 0;
}

function findingHasWitnessProofs(finding: FindingEnvelope): boolean {
  return (
    hasWitnessProofs(finding.publish) ||
    finding.blobRefs.some((blobRef) => hasWitnessProofs(blobRef.publish))
  );
}

function revocationHasWitnessProofs(revocation: RevocationEnvelope): boolean {
  return hasWitnessProofs(revocation.publish);
}

function requiresVerifiedAttestation(policy: HubTrustPolicy): boolean {
  return (
    policy.requireAttestation ||
    policy.trustedIssuers.length > 0 ||
    policy.blockedIssuers.length > 0
  );
}

async function verifyFindingAttestation(finding: FindingEnvelope): Promise<boolean> {
  if (finding.attestation === undefined) {
    return false;
  }

  if (!matchesIssuerAttestation(finding.issuerId, finding.attestation)) {
    return false;
  }

  try {
    const digest = await hashProtocolPayload(extractFindingEnvelopeSignableFields(finding));
    return verifyDetachedPayload(
      new TextEncoder().encode(digest),
      finding.attestation.signature,
      finding.attestation.publicKey,
    );
  } catch {
    return false;
  }
}

async function verifyRevocationAttestation(revocation: RevocationEnvelope): Promise<boolean> {
  if (revocation.attestation === undefined) {
    return false;
  }

  if (!matchesIssuerAttestation(revocation.issuerId, revocation.attestation)) {
    return false;
  }

  try {
    const digest = await hashProtocolPayload(extractRevocationEnvelopeSignableFields(revocation));
    return verifyDetachedPayload(
      new TextEncoder().encode(digest),
      revocation.attestation.signature,
      revocation.attestation.publicKey,
    );
  } catch {
    return false;
  }
}

function evaluateSignedEnvelopeTrustPolicy(
  policy: HubTrustPolicy,
  envelope:
    | Pick<FindingEnvelope, "issuerId" | "schema" | "attestation">
    | Pick<RevocationEnvelope, "issuerId" | "schema" | "attestation">,
  options: {
    hasWitnessProofs: boolean;
    verifyAttestation: () => Promise<boolean>;
  },
): FindingTrustPolicyDecision | Promise<FindingTrustPolicyDecision> {
  if (policy.blockedIssuers.includes(envelope.issuerId)) {
    return { accepted: false, reason: "blocked_issuer" };
  }

  if (policy.trustedIssuers.length > 0 && !policy.trustedIssuers.includes(envelope.issuerId)) {
    return { accepted: false, reason: "untrusted_issuer" };
  }

  if (!policy.allowedSchemas.includes(envelope.schema)) {
    return { accepted: false, reason: "disallowed_schema" };
  }

  if (requiresVerifiedAttestation(policy) && envelope.attestation === undefined) {
    return { accepted: false, reason: "missing_attestation" };
  }

  if (policy.requireWitnessProofs && !options.hasWitnessProofs) {
    return { accepted: false, reason: "missing_witness_proofs" };
  }

  if (!requiresVerifiedAttestation(policy)) {
    return { accepted: true };
  }

  return options.verifyAttestation().then((verified) =>
    verified
      ? { accepted: true }
      : { accepted: false, reason: "invalid_attestation" },
  );
}

export function evaluateFindingTrustPolicy(
  policy: HubTrustPolicy,
  finding: FindingEnvelope,
): FindingTrustPolicyDecision | Promise<FindingTrustPolicyDecision> {
  return evaluateSignedEnvelopeTrustPolicy(policy, finding, {
    hasWitnessProofs: findingHasWitnessProofs(finding),
    verifyAttestation: () => verifyFindingAttestation(finding),
  });
}

export function evaluateRevocationTrustPolicy(
  policy: HubTrustPolicy,
  revocation: RevocationEnvelope,
): FindingTrustPolicyDecision | Promise<FindingTrustPolicyDecision> {
  return evaluateSignedEnvelopeTrustPolicy(policy, revocation, {
    hasWitnessProofs: revocationHasWitnessProofs(revocation),
    verifyAttestation: () => verifyRevocationAttestation(revocation),
  });
}

/**
 * Synchronous trust policy evaluation for use in contexts that cannot await
 * (e.g., React reducers, localStorage reload). Performs all checks that do not
 * require async attestation verification. If the policy requires attestation
 * verification (async crypto), the decision is fail-closed: the record is
 * denied with reason "invalid_attestation" and should remain quarantined until
 * it can be re-evaluated asynchronously.
 */
export function evaluateFindingTrustPolicySync(
  policy: HubTrustPolicy,
  finding: FindingEnvelope,
): FindingTrustPolicyDecision {
  return evaluateSignedEnvelopeTrustPolicySync(policy, finding, {
    hasWitnessProofs: findingHasWitnessProofs(finding),
  });
}

export function evaluateRevocationTrustPolicySync(
  policy: HubTrustPolicy,
  revocation: RevocationEnvelope,
): FindingTrustPolicyDecision {
  return evaluateSignedEnvelopeTrustPolicySync(policy, revocation, {
    hasWitnessProofs: revocationHasWitnessProofs(revocation),
  });
}

function evaluateSignedEnvelopeTrustPolicySync(
  policy: HubTrustPolicy,
  envelope:
    | Pick<FindingEnvelope, "issuerId" | "schema" | "attestation">
    | Pick<RevocationEnvelope, "issuerId" | "schema" | "attestation">,
  options: {
    hasWitnessProofs: boolean;
  },
): FindingTrustPolicyDecision {
  if (policy.blockedIssuers.includes(envelope.issuerId)) {
    return { accepted: false, reason: "blocked_issuer" };
  }

  if (policy.trustedIssuers.length > 0 && !policy.trustedIssuers.includes(envelope.issuerId)) {
    return { accepted: false, reason: "untrusted_issuer" };
  }

  if (!policy.allowedSchemas.includes(envelope.schema)) {
    return { accepted: false, reason: "disallowed_schema" };
  }

  if (requiresVerifiedAttestation(policy) && envelope.attestation === undefined) {
    return { accepted: false, reason: "missing_attestation" };
  }

  if (policy.requireWitnessProofs && !options.hasWitnessProofs) {
    return { accepted: false, reason: "missing_witness_proofs" };
  }

  // If the policy requires attestation verification, we cannot verify async
  // in a synchronous context. Fail-closed: deny and keep quarantined.
  if (requiresVerifiedAttestation(policy)) {
    return { accepted: false, reason: "invalid_attestation" };
  }

  return { accepted: true };
}
