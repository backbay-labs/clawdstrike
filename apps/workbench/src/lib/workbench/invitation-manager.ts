import type {
  InvitationClaims,
  SignedInvitation,
  AcceptedInvitation,
  OperatorIdentity,
  SwarmOperatorRole,
  OperatorCapability,
} from "./operator-types";
import {
  INVITATION_AUDIENCE,
  MAX_INVITATION_DEPTH,
  ROLE_HIERARCHY,
  ROLE_CAPABILITIES,
} from "./operator-types";
import { signCanonical, verifyCanonical } from "./operator-crypto";

export interface CreateInvitationParams {
  inviterIdentity: OperatorIdentity;
  inviterSecretKey: string;
  inviterRole: SwarmOperatorRole;
  swarmId: string;
  grantedRole: SwarmOperatorRole;
  capabilities?: OperatorCapability[];
  expiresInMs?: number; // default 7 days
  message?: string;
  parentChain?: string[]; // JTIs of parent invitations
  depth?: number; // current depth, default 0
}

export function isRoleAttenuation(
  inviterRole: SwarmOperatorRole,
  grantedRole: SwarmOperatorRole,
): boolean {
  return ROLE_HIERARCHY[grantedRole] <= ROLE_HIERARCHY[inviterRole];
}

export async function createInvitation(
  params: CreateInvitationParams,
): Promise<SignedInvitation> {
  const depth = params.depth ?? 0;
  if (depth >= MAX_INVITATION_DEPTH) {
    throw new Error(
      `Invitation depth ${depth} exceeds maximum ${MAX_INVITATION_DEPTH}`,
    );
  }
  if (!isRoleAttenuation(params.inviterRole, params.grantedRole)) {
    throw new Error(
      `Cannot grant role "${params.grantedRole}" — inviter role "${params.inviterRole}" is insufficient`,
    );
  }

  const roleCaps = ROLE_CAPABILITIES[params.grantedRole];
  const capabilities = params.capabilities
    ? params.capabilities.filter((c) => roleCaps.includes(c))
    : [...roleCaps];

  const claims: InvitationClaims = {
    iss: params.inviterIdentity.fingerprint,
    sub: null,
    aud: INVITATION_AUDIENCE,
    iat: Date.now(),
    exp: Date.now() + (params.expiresInMs ?? 7 * 24 * 60 * 60 * 1000),
    jti: crypto.randomUUID(),
    swarmId: params.swarmId,
    grantedRole: params.grantedRole,
    capabilities,
    chain: params.parentChain ?? [],
    depth,
    ...(params.message ? { message: params.message } : {}),
  };

  const signature = await signCanonical(claims, params.inviterSecretKey);

  return {
    claims,
    signature,
    issuerPublicKey: params.inviterIdentity.publicKey,
  };
}

export function isExpired(claims: InvitationClaims): boolean {
  return Date.now() > claims.exp;
}

export function isDepthExceeded(claims: InvitationClaims): boolean {
  return claims.depth >= MAX_INVITATION_DEPTH;
}

export async function validateInvitation(
  signed: SignedInvitation,
): Promise<{ valid: boolean; error?: string }> {
  if (!signed.claims || !signed.signature || !signed.issuerPublicKey) {
    return { valid: false, error: "Missing required fields" };
  }
  if (signed.claims.aud !== INVITATION_AUDIENCE) {
    return { valid: false, error: `Invalid audience: ${signed.claims.aud}` };
  }
  if (isExpired(signed.claims)) {
    return { valid: false, error: "Invitation has expired" };
  }
  if (isDepthExceeded(signed.claims)) {
    return {
      valid: false,
      error: `Depth ${signed.claims.depth} exceeds maximum ${MAX_INVITATION_DEPTH}`,
    };
  }

  const valid = await verifyCanonical(
    signed.claims,
    signed.signature,
    signed.issuerPublicKey,
  );
  if (!valid) {
    return { valid: false, error: "Invalid signature" };
  }

  return { valid: true };
}

export async function acceptInvitation(
  signed: SignedInvitation,
  acceptorIdentity: OperatorIdentity,
  acceptorSecretKey: string,
): Promise<AcceptedInvitation> {
  if (signed.claims.sub !== null) {
    throw new Error("Invitation has already been accepted");
  }

  const validation = await validateInvitation(signed);
  if (!validation.valid) {
    throw new Error(`Invalid invitation: ${validation.error}`);
  }

  const boundClaims: InvitationClaims = {
    ...signed.claims,
    sub: acceptorIdentity.publicKey,
  };
  const boundInvitation: SignedInvitation = { ...signed, claims: boundClaims };

  const acceptorSignature = await signCanonical(
    boundClaims,
    acceptorSecretKey,
  );

  return {
    invitation: boundInvitation,
    acceptorPublicKey: acceptorIdentity.publicKey,
    acceptorSignature,
    acceptedAt: Date.now(),
  };
}

export async function verifyAcceptedInvitation(
  accepted: AcceptedInvitation,
): Promise<{ valid: boolean; error?: string }> {
  const originalClaims = { ...accepted.invitation.claims, sub: null };
  const issuerOriginalValid = await verifyCanonical(
    originalClaims,
    accepted.invitation.signature,
    accepted.invitation.issuerPublicKey,
  );
  if (!issuerOriginalValid) {
    return { valid: false, error: "Issuer signature invalid" };
  }

  const acceptorValid = await verifyCanonical(
    accepted.invitation.claims,
    accepted.acceptorSignature,
    accepted.acceptorPublicKey,
  );
  if (!acceptorValid) {
    return { valid: false, error: "Acceptor signature invalid" };
  }

  return { valid: true };
}

export function serializeInvitation(signed: SignedInvitation): string {
  const json = JSON.stringify(signed);
  return btoa(Array.from(new TextEncoder().encode(json), b => String.fromCharCode(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function deserializeInvitation(encoded: string): SignedInvitation {
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const json = new TextDecoder().decode(Uint8Array.from(atob(base64), c => c.charCodeAt(0)));
  const parsed = JSON.parse(json);

  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof parsed.signature !== "string" ||
    typeof parsed.issuerPublicKey !== "string" ||
    !parsed.claims ||
    typeof parsed.claims !== "object" ||
    typeof parsed.claims.iss !== "string" ||
    typeof parsed.claims.aud !== "string" ||
    typeof parsed.claims.jti !== "string" ||
    typeof parsed.claims.swarmId !== "string" ||
    typeof parsed.claims.grantedRole !== "string" ||
    typeof parsed.claims.iat !== "number" ||
    typeof parsed.claims.exp !== "number" ||
    typeof parsed.claims.depth !== "number" ||
    !Array.isArray(parsed.claims.capabilities) ||
    !Array.isArray(parsed.claims.chain)
  ) {
    throw new Error("Invalid invitation structure");
  }

  return parsed as SignedInvitation;
}
