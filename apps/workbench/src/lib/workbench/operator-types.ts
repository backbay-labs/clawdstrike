/**
 * Operator Identity types for the Sentinel Swarm system.
 *
 * Operators are the human (or service) identities that own and control
 * sentinels, participate in swarms, and issue invitations. Each operator
 * has an Ed25519 keypair, a fingerprint, and an optional IdP binding.
 */


export type IdpProvider = "oidc" | "saml" | "okta" | "auth0" | "azure_ad";

export interface IdpClaims {
  provider: IdpProvider;
  issuer: string;
  subject: string;
  email: string | null;
  emailVerified: boolean;
  organizationId: string | null;
  teams: string[];
  roles: string[];
  boundAt: number;
  lastRefreshed: number;
  expiresAt: number;
}


export interface OperatorDevice {
  deviceId: string;
  deviceName: string;
  addedAt: number;
  lastSeenAt: number;
}


export interface OperatorIdentity {
  publicKey: string;        // 64-char hex (32 bytes)
  fingerprint: string;      // 16-char hex
  sigil: string;            // derived from fingerprint
  nickname: string;
  displayName: string;
  idpClaims: IdpClaims | null;
  createdAt: number;
  originDeviceId: string;
  devices: OperatorDevice[];
  /** Epoch-ms timestamp when this identity was revoked, if applicable. */
  revokedAt?: number;
  /** Human-readable reason for revocation, if applicable. */
  revocationReason?: string;
}


export type OperatorCapability =
  | "swarm:publish_intel"
  | "swarm:vote_reputation"
  | "swarm:share_detections"
  | "swarm:invite_members"
  | "swarm:manage_speakeasies"
  | "swarm:admin";

export type SwarmOperatorRole = "observer" | "contributor" | "admin";

export const ROLE_HIERARCHY: Record<SwarmOperatorRole, number> = {
  observer: 0,
  contributor: 1,
  admin: 2,
};

export const ROLE_CAPABILITIES: Record<SwarmOperatorRole, OperatorCapability[]> = {
  observer: ["swarm:share_detections"],
  contributor: [
    "swarm:publish_intel",
    "swarm:vote_reputation",
    "swarm:share_detections",
    "swarm:invite_members",
  ],
  admin: [
    "swarm:publish_intel",
    "swarm:vote_reputation",
    "swarm:share_detections",
    "swarm:invite_members",
    "swarm:manage_speakeasies",
    "swarm:admin",
  ],
};


export const INVITATION_AUDIENCE = "clawdstrike:swarm-invitation" as const;
export const MAX_INVITATION_DEPTH = 5;

export interface InvitationClaims {
  iss: string;                    // inviter fingerprint
  sub: string | null;             // null until acceptance, then acceptor pubkey
  aud: typeof INVITATION_AUDIENCE;
  iat: number;
  exp: number;
  jti: string;                    // UUID
  swarmId: string;
  grantedRole: SwarmOperatorRole;
  capabilities: OperatorCapability[];
  chain: string[];                // parent invitation JTIs
  depth: number;
  message?: string;
}

export interface SignedInvitation {
  claims: InvitationClaims;
  signature: string;              // hex-encoded Ed25519 signature
  issuerPublicKey: string;        // hex-encoded public key
}

export interface AcceptedInvitation {
  invitation: SignedInvitation;   // with sub now bound
  acceptorPublicKey: string;
  acceptorSignature: string;
  acceptedAt: number;
}
