# Delegation Tokens Specification

## Problem Statement

In multi-agent systems, agents often need to temporarily share capabilities with other agents. Without a secure delegation mechanism:

1. **All-or-Nothing Access**: Agents must either grant full access or no access
2. **No Revocation**: Once access is shared, it cannot be withdrawn
3. **No Audit Trail**: No evidence of who delegated what to whom
4. **Privilege Accumulation**: Delegated privileges persist indefinitely

Delegation tokens provide a cryptographically secure mechanism for Agent A to grant Agent B time-limited, scoped access to specific resources or capabilities.

## Threat Model

### Attack Scenarios

#### Scenario 1: Token Theft and Replay

```
Agent A delegates to Agent B (legitimate)
            |
            v
Malicious Agent C intercepts token
            |
            v
Agent C replays token to access resources
```

**Mitigation**: Token binding to recipient identity, audience claim verification

#### Scenario 2: Privilege Escalation via Delegation Chain

```
Agent A delegates {read, write} to Agent B
            |
            v
Agent B delegates {read, write, execute} to Agent C
            |
            v
Agent C has privileges Agent A never intended to grant
```

**Mitigation**: Attenuation-only delegation, privilege ceiling enforcement

#### Scenario 3: Token Forgery

```
Malicious Agent creates fake delegation token
            |
            v
Claims to have delegation from high-privilege agent
            |
            v
Accesses protected resources
```

**Mitigation**: Cryptographic signature verification, issuer identity attestation

#### Scenario 4: Time-of-Check to Time-of-Use (TOCTOU)

```
Token validated at time T
            |
            v
Token revoked at time T+1
            |
            v
Token used at time T+2 (after revocation)
```

**Mitigation**: Short-lived tokens, real-time revocation checking, nonce tracking

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Compromised Agent | Full control of one agent | Access resources beyond their permissions |
| Network Observer | Passive observation | Capture and replay tokens |
| Malicious Orchestrator | Deploy agents | Forge delegation chains |
| Rogue Insider | Access to key material | Create unlimited delegations |

## Architecture

### Delegation Token Structure

```
+------------------------------------------------------------------+
|                     Delegation Token                              |
+------------------------------------------------------------------+
| Header (COSE Protected Header)                                    |
| +--------------------------------------------------------------+ |
| | alg: EdDSA (or ES384)                                        | |
| | kid: issuer-key-id                                           | |
| | crit: ["exp", "aud"]                                         | |
| +--------------------------------------------------------------+ |
|                                                                   |
| Payload (CBOR-encoded claims)                                     |
| +--------------------------------------------------------------+ |
| | iss: "agent:research-agent-001"           (issuer)           | |
| | sub: "agent:code-agent-001"               (subject/grantee)  | |
| | aud: "clawdstrike:delegation"             (audience)         | |
| | iat: 1705312200                           (issued at)        | |
| | exp: 1705315800                           (expiration)       | |
| | nbf: 1705312200                           (not before)       | |
| | jti: "dlg-abc123-xyz789"                  (token id)         | |
| | cap: ["file:read:/workspace/research/**"] (capabilities)     | |
| | chn: ["dlg-parent-token-id"]              (delegation chain) | |
| | cel: ["file:read", "file:write"]          (capability ceiling)| |
| | pur: "Code generation from research"      (purpose)          | |
| | ctx: { "traceId": "trace-xyz" }           (context)          | |
| +--------------------------------------------------------------+ |
|                                                                   |
| Signature (Ed25519 or ECDSA P-384)                               |
| +--------------------------------------------------------------+ |
| | 64 bytes (Ed25519) or 96 bytes (ECDSA P-384)                 | |
| +--------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

### Token Lifecycle

```
+-------------+     +----------------+     +----------------+
| Token       | --> | Token          | --> | Token          |
| Creation    |     | Verification   |     | Use            |
+------+------+     +-------+--------+     +-------+--------+
       |                    |                      |
       v                    v                      v
+-------------+     +----------------+     +----------------+
| Sign with   |     | Verify         |     | Check          |
| issuer key  |     | signature      |     | revocation     |
+-------------+     +----------------+     +----------------+
       |                    |                      |
       v                    v                      v
+-------------+     +----------------+     +----------------+
| Set claims  |     | Validate       |     | Verify         |
| (cap, exp)  |     | claims         |     | capability     |
+-------------+     +----------------+     +----------------+
       |                    |                      |
       v                    v                      v
+-------------+     +----------------+     +----------------+
| Emit audit  |     | Check          |     | Emit audit     |
| event       |     | ceiling        |     | event          |
+-------------+     +----------------+     +----------------+
```

### Revocation Architecture

```
+------------------------------------------------------------------+
|                      Revocation System                            |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------+    +------------------+                     |
|  | Revocation       |    | Token            |                     |
|  | Registry         |<-->| Verifier         |                     |
|  | (Redis/etcd)     |    |                  |                     |
|  +--------+---------+    +--------+---------+                     |
|           |                       |                               |
|           v                       v                               |
|  +------------------+    +------------------+                     |
|  | Bloom Filter     |    | CRL Distribution |                     |
|  | (Fast negative)  |    | (Push updates)   |                     |
|  +------------------+    +------------------+                     |
|                                                                   |
+------------------------------------------------------------------+
```

## API Design

### TypeScript Interface

```typescript
import { SigningKey, VerifyingKey } from '@clawdstrike/crypto';

/**
 * Delegation token claims
 */
export interface DelegationClaims {
  /** Issuer (delegating agent) */
  iss: AgentId;

  /** Subject (receiving agent) */
  sub: AgentId;

  /** Audience (expected verifier) */
  aud: string;

  /** Issued at (Unix timestamp) */
  iat: number;

  /** Expiration (Unix timestamp) */
  exp: number;

  /** Not before (Unix timestamp) */
  nbf?: number;

  /** Token ID (unique identifier) */
  jti: string;

  /** Delegated capabilities */
  cap: Capability[];

  /** Delegation chain (parent token IDs) */
  chn?: string[];

  /** Capability ceiling (max privileges for re-delegation) */
  cel?: Capability[];

  /** Purpose description */
  pur?: string;

  /** Additional context */
  ctx?: Record<string, unknown>;
}

/**
 * Delegation token (signed)
 */
export interface DelegationToken {
  /** Raw token bytes (COSE Sign1) */
  raw: Uint8Array;

  /** Decoded claims (for convenience) */
  claims: DelegationClaims;

  /** Token ID */
  id: string;

  /** Issuer agent ID */
  issuer: AgentId;

  /** Subject agent ID */
  subject: AgentId;

  /** Expiration time */
  expiresAt: Date;

  /** Whether token is currently valid (not expired, not revoked) */
  isValid(): Promise<boolean>;

  /** Serialize to string (base64url) */
  toString(): string;
}

/**
 * Request to create a delegation
 */
export interface DelegationRequest {
  /** Target agent to receive delegation */
  to: AgentId;

  /** Capabilities to delegate */
  capabilities: Capability[];

  /** Time-to-live */
  ttl: Duration;

  /** Purpose description (for audit) */
  purpose?: string;

  /** Additional context */
  context?: Record<string, unknown>;

  /** Whether recipient can re-delegate */
  allowRedelegation?: boolean;

  /** Maximum re-delegation depth */
  maxChainLength?: number;
}

/**
 * Delegation token service
 */
export class DelegationService {
  private signingKey: SigningKey;
  private verifyingKeys: Map<AgentId, VerifyingKey>;
  private revocationRegistry: RevocationRegistry;
  private agentIdentity: AgentIdentity;

  constructor(config: DelegationServiceConfig) {
    this.signingKey = config.signingKey;
    this.verifyingKeys = new Map();
    this.revocationRegistry = config.revocationRegistry;
    this.agentIdentity = config.agentIdentity;
  }

  /**
   * Create a new delegation token
   */
  async createDelegation(
    request: DelegationRequest
  ): Promise<DelegationToken> {
    // Validate request
    this.validateRequest(request);

    // Check that we have the capabilities we're delegating
    const ourCaps = await this.agentIdentity.getCapabilities();
    for (const cap of request.capabilities) {
      if (!this.hasCapability(ourCaps, cap)) {
        throw new Error(`Cannot delegate capability not possessed: ${cap}`);
      }
    }

    // Build claims
    const now = Math.floor(Date.now() / 1000);
    const claims: DelegationClaims = {
      iss: this.agentIdentity.id,
      sub: request.to,
      aud: 'clawdstrike:delegation',
      iat: now,
      exp: now + durationToSeconds(request.ttl),
      nbf: now,
      jti: this.generateTokenId(),
      cap: request.capabilities,
      pur: request.purpose,
      ctx: request.context,
    };

    // Set capability ceiling if re-delegation allowed
    if (request.allowRedelegation) {
      claims.cel = request.capabilities;
      claims.ctx = {
        ...claims.ctx,
        maxChainLength: request.maxChainLength ?? 3,
      };
    }

    // Sign token (COSE Sign1)
    const raw = await this.signToken(claims);

    const token: DelegationToken = {
      raw,
      claims,
      id: claims.jti,
      issuer: claims.iss,
      subject: claims.sub,
      expiresAt: new Date(claims.exp * 1000),
      isValid: () => this.checkValidity(claims.jti),
      toString: () => base64url.encode(raw),
    };

    // Emit audit event
    await this.emitAuditEvent('delegation_created', {
      tokenId: token.id,
      issuer: token.issuer,
      subject: token.subject,
      capabilities: claims.cap,
      expiresAt: token.expiresAt.toISOString(),
      purpose: claims.pur,
    });

    return token;
  }

  /**
   * Verify a delegation token
   */
  async verifyToken(
    tokenStr: string,
    expectedSubject?: AgentId
  ): Promise<VerificationResult> {
    try {
      // Decode token
      const raw = base64url.decode(tokenStr);
      const { claims, signature } = this.decodeToken(raw);

      // Check basic validity
      const now = Math.floor(Date.now() / 1000);

      if (claims.exp <= now) {
        return { valid: false, reason: 'Token expired' };
      }

      if (claims.nbf && claims.nbf > now) {
        return { valid: false, reason: 'Token not yet valid' };
      }

      if (claims.aud !== 'clawdstrike:delegation') {
        return { valid: false, reason: 'Invalid audience' };
      }

      if (expectedSubject && claims.sub !== expectedSubject) {
        return { valid: false, reason: 'Subject mismatch' };
      }

      // Check revocation
      const isRevoked = await this.revocationRegistry.isRevoked(claims.jti);
      if (isRevoked) {
        return { valid: false, reason: 'Token revoked' };
      }

      // Verify signature
      const issuerKey = await this.getVerifyingKey(claims.iss);
      if (!issuerKey) {
        return { valid: false, reason: 'Unknown issuer' };
      }

      const signatureValid = await this.verifySignature(raw, signature, issuerKey);
      if (!signatureValid) {
        return { valid: false, reason: 'Invalid signature' };
      }

      // Verify delegation chain if present
      if (claims.chn && claims.chn.length > 0) {
        const chainValid = await this.verifyChain(claims);
        if (!chainValid.valid) {
          return chainValid;
        }
      }

      return {
        valid: true,
        claims,
        issuer: claims.iss,
        subject: claims.sub,
        capabilities: claims.cap,
        expiresAt: new Date(claims.exp * 1000),
      };
    } catch (error) {
      return { valid: false, reason: `Verification error: ${error}` };
    }
  }

  /**
   * Re-delegate capabilities (with attenuation)
   */
  async redelegate(
    parentToken: string,
    request: RedelegationRequest
  ): Promise<DelegationToken> {
    // Verify parent token
    const parentResult = await this.verifyToken(parentToken, this.agentIdentity.id);
    if (!parentResult.valid) {
      throw new Error(`Invalid parent token: ${parentResult.reason}`);
    }

    const parentClaims = parentResult.claims!;

    // Check re-delegation is allowed
    if (!parentClaims.cel) {
      throw new Error('Parent token does not allow re-delegation');
    }

    // Check chain length
    const chainLength = (parentClaims.chn?.length ?? 0) + 1;
    const maxChainLength = (parentClaims.ctx?.maxChainLength as number) ?? 3;
    if (chainLength >= maxChainLength) {
      throw new Error(`Maximum delegation chain length (${maxChainLength}) exceeded`);
    }

    // Verify attenuation (capabilities must be subset of ceiling)
    for (const cap of request.capabilities) {
      if (!this.capabilityWithinCeiling(cap, parentClaims.cel)) {
        throw new Error(`Capability ${cap} exceeds delegation ceiling`);
      }
    }

    // TTL cannot exceed parent TTL
    const parentExpiry = parentClaims.exp;
    const requestedExpiry = Math.floor(Date.now() / 1000) + durationToSeconds(request.ttl);
    const actualExpiry = Math.min(requestedExpiry, parentExpiry);

    // Build claims
    const now = Math.floor(Date.now() / 1000);
    const claims: DelegationClaims = {
      iss: this.agentIdentity.id,
      sub: request.to,
      aud: 'clawdstrike:delegation',
      iat: now,
      exp: actualExpiry,
      nbf: now,
      jti: this.generateTokenId(),
      cap: request.capabilities,
      chn: [...(parentClaims.chn ?? []), parentClaims.jti],
      cel: request.allowRedelegation
        ? this.attenuateCeiling(request.capabilities, parentClaims.cel)
        : undefined,
      pur: request.purpose,
      ctx: {
        ...request.context,
        parentTokenId: parentClaims.jti,
        maxChainLength,
      },
    };

    // Sign and return
    const raw = await this.signToken(claims);

    const token: DelegationToken = {
      raw,
      claims,
      id: claims.jti,
      issuer: claims.iss,
      subject: claims.sub,
      expiresAt: new Date(claims.exp * 1000),
      isValid: () => this.checkValidity(claims.jti),
      toString: () => base64url.encode(raw),
    };

    // Emit audit event
    await this.emitAuditEvent('delegation_redelegated', {
      tokenId: token.id,
      parentTokenId: parentClaims.jti,
      issuer: token.issuer,
      subject: token.subject,
      capabilities: claims.cap,
      chainLength,
    });

    return token;
  }

  /**
   * Revoke a delegation token
   */
  async revoke(tokenId: string, reason?: string): Promise<void> {
    // Verify we are the issuer
    const tokenInfo = await this.revocationRegistry.getTokenInfo(tokenId);
    if (tokenInfo && tokenInfo.issuer !== this.agentIdentity.id) {
      throw new Error('Only issuer can revoke token');
    }

    await this.revocationRegistry.revoke(tokenId, {
      revokedAt: new Date(),
      revokedBy: this.agentIdentity.id,
      reason,
    });

    // Emit audit event
    await this.emitAuditEvent('delegation_revoked', {
      tokenId,
      revokedBy: this.agentIdentity.id,
      reason,
    });
  }

  /**
   * Revoke all tokens issued by this agent
   */
  async revokeAll(reason?: string): Promise<number> {
    const count = await this.revocationRegistry.revokeByIssuer(
      this.agentIdentity.id,
      { reason, revokedAt: new Date() }
    );

    await this.emitAuditEvent('delegation_revoked_all', {
      issuer: this.agentIdentity.id,
      count,
      reason,
    });

    return count;
  }

  private async signToken(claims: DelegationClaims): Promise<Uint8Array> {
    const payload = cbor.encode(claims);

    const protectedHeader = cbor.encode({
      alg: 'EdDSA',
      kid: this.signingKey.keyId,
      crit: ['exp', 'aud'],
    });

    const signatureInput = this.buildSignatureInput(protectedHeader, payload);
    const signature = await this.signingKey.sign(signatureInput);

    // COSE Sign1 structure
    return cbor.encode([
      protectedHeader,
      {}, // unprotected header
      payload,
      signature,
    ]);
  }

  private decodeToken(raw: Uint8Array): {
    claims: DelegationClaims;
    signature: Uint8Array;
  } {
    const [protectedHeader, , payload, signature] = cbor.decode(raw) as [
      Uint8Array,
      unknown,
      Uint8Array,
      Uint8Array
    ];

    const claims = cbor.decode(payload) as DelegationClaims;
    return { claims, signature };
  }

  private buildSignatureInput(
    protectedHeader: Uint8Array,
    payload: Uint8Array
  ): Uint8Array {
    // COSE Sig_structure
    return cbor.encode([
      'Signature1',
      protectedHeader,
      new Uint8Array(0), // external_aad
      payload,
    ]);
  }

  private async verifySignature(
    raw: Uint8Array,
    signature: Uint8Array,
    key: VerifyingKey
  ): Promise<boolean> {
    const [protectedHeader, , payload] = cbor.decode(raw) as [
      Uint8Array,
      unknown,
      Uint8Array
    ];

    const signatureInput = this.buildSignatureInput(protectedHeader, payload);
    return key.verify(signatureInput, signature);
  }

  private async verifyChain(claims: DelegationClaims): Promise<VerificationResult> {
    if (!claims.chn || claims.chn.length === 0) {
      return { valid: true };
    }

    // Verify each token in chain is not revoked
    for (const tokenId of claims.chn) {
      const isRevoked = await this.revocationRegistry.isRevoked(tokenId);
      if (isRevoked) {
        return {
          valid: false,
          reason: `Token in delegation chain revoked: ${tokenId}`,
        };
      }
    }

    return { valid: true };
  }

  private capabilityWithinCeiling(
    capability: Capability,
    ceiling: Capability[]
  ): boolean {
    return ceiling.some((ceil) => this.capabilitySubsetOf(capability, ceil));
  }

  private capabilitySubsetOf(cap: Capability, ceiling: Capability): boolean {
    const [capType, capAction, capResource] = cap.split(':');
    const [ceilType, ceilAction, ceilResource] = ceiling.split(':');

    if (capType !== ceilType) return false;
    if (capAction !== ceilAction) return false;

    // Resource must be within ceiling resource scope
    return this.resourceWithin(capResource, ceilResource);
  }

  private resourceWithin(resource: string, ceiling: string): boolean {
    if (ceiling === '*') return true;
    if (ceiling.endsWith('/**')) {
      const prefix = ceiling.slice(0, -3);
      return resource.startsWith(prefix);
    }
    return resource === ceiling;
  }

  private attenuateCeiling(
    capabilities: Capability[],
    parentCeiling: Capability[]
  ): Capability[] {
    // New ceiling is intersection of requested caps and parent ceiling
    return capabilities.filter((cap) =>
      this.capabilityWithinCeiling(cap, parentCeiling)
    );
  }

  private hasCapability(ourCaps: Capability[], cap: Capability): boolean {
    return ourCaps.some((c) => this.capabilitySubsetOf(cap, c));
  }

  private validateRequest(request: DelegationRequest): void {
    if (!request.to) {
      throw new Error('Delegation target required');
    }
    if (!request.capabilities || request.capabilities.length === 0) {
      throw new Error('At least one capability required');
    }
    if (!request.ttl) {
      throw new Error('TTL required');
    }
  }

  private generateTokenId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(12).toString('base64url');
    return `dlg-${timestamp}-${random}`;
  }

  private async checkValidity(tokenId: string): Promise<boolean> {
    return !(await this.revocationRegistry.isRevoked(tokenId));
  }

  private async getVerifyingKey(agentId: AgentId): Promise<VerifyingKey | null> {
    if (this.verifyingKeys.has(agentId)) {
      return this.verifyingKeys.get(agentId)!;
    }

    // Fetch from key registry
    const key = await this.agentIdentity.getPublicKey(agentId);
    if (key) {
      this.verifyingKeys.set(agentId, key);
    }
    return key;
  }

  private async emitAuditEvent(
    type: string,
    data: Record<string, unknown>
  ): Promise<void> {
    // Integration with audit system
    console.log(`[AUDIT] ${type}:`, data);
  }
}

/**
 * Revocation registry interface
 */
export interface RevocationRegistry {
  isRevoked(tokenId: string): Promise<boolean>;
  revoke(tokenId: string, info: RevocationInfo): Promise<void>;
  revokeByIssuer(issuer: AgentId, info: RevocationInfo): Promise<number>;
  getTokenInfo(tokenId: string): Promise<TokenInfo | null>;
}

export interface RevocationInfo {
  revokedAt: Date;
  revokedBy: AgentId;
  reason?: string;
}

export interface TokenInfo {
  tokenId: string;
  issuer: AgentId;
  subject: AgentId;
  expiresAt: Date;
  revokedAt?: Date;
}

/**
 * Verification result
 */
export interface VerificationResult {
  valid: boolean;
  reason?: string;
  claims?: DelegationClaims;
  issuer?: AgentId;
  subject?: AgentId;
  capabilities?: Capability[];
  expiresAt?: Date;
}

/**
 * Re-delegation request
 */
export interface RedelegationRequest {
  to: AgentId;
  capabilities: Capability[];
  ttl: Duration;
  purpose?: string;
  context?: Record<string, unknown>;
  allowRedelegation?: boolean;
}
```

### Rust Interface

```rust
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Delegation token claims
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationClaims {
    /// Issuer (delegating agent)
    pub iss: AgentId,
    /// Subject (receiving agent)
    pub sub: AgentId,
    /// Audience
    pub aud: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Not before (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Token ID
    pub jti: String,
    /// Delegated capabilities
    pub cap: Vec<Capability>,
    /// Delegation chain
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chn: Vec<String>,
    /// Capability ceiling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cel: Option<Vec<Capability>>,
    /// Purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pur: Option<String>,
    /// Context
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ctx: HashMap<String, serde_json::Value>,
}

/// Signed delegation token
#[derive(Clone, Debug)]
pub struct DelegationToken {
    /// Raw token bytes (COSE Sign1)
    pub raw: Vec<u8>,
    /// Decoded claims
    pub claims: DelegationClaims,
}

impl DelegationToken {
    pub fn id(&self) -> &str {
        &self.claims.jti
    }

    pub fn issuer(&self) -> &AgentId {
        &self.claims.iss
    }

    pub fn subject(&self) -> &AgentId {
        &self.claims.sub
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.claims.exp, 0).unwrap_or_else(Utc::now)
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.claims.cap
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.claims.exp
    }

    pub fn to_base64(&self) -> String {
        base64::encode_config(&self.raw, base64::URL_SAFE_NO_PAD)
    }

    pub fn from_base64(s: &str) -> Result<Self, Error> {
        let raw = base64::decode_config(s, base64::URL_SAFE_NO_PAD)?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: Vec<u8>) -> Result<Self, Error> {
        let claims = decode_cose_claims(&raw)?;
        Ok(Self { raw, claims })
    }
}

/// Delegation request
#[derive(Clone, Debug)]
pub struct DelegationRequest {
    pub to: AgentId,
    pub capabilities: Vec<Capability>,
    pub ttl: Duration,
    pub purpose: Option<String>,
    pub context: HashMap<String, serde_json::Value>,
    pub allow_redelegation: bool,
    pub max_chain_length: Option<u32>,
}

impl DelegationRequest {
    pub fn new(to: AgentId, capabilities: Vec<Capability>, ttl: Duration) -> Self {
        Self {
            to,
            capabilities,
            ttl,
            purpose: None,
            context: HashMap::new(),
            allow_redelegation: false,
            max_chain_length: None,
        }
    }

    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    pub fn allow_redelegation(mut self, max_depth: u32) -> Self {
        self.allow_redelegation = true;
        self.max_chain_length = Some(max_depth);
        self
    }
}

/// Delegation service
pub struct DelegationService {
    signing_key: Arc<dyn SigningKey>,
    agent_identity: Arc<AgentIdentity>,
    revocation_registry: Arc<dyn RevocationRegistry>,
    key_registry: Arc<dyn KeyRegistry>,
}

impl DelegationService {
    pub fn new(
        signing_key: Arc<dyn SigningKey>,
        agent_identity: Arc<AgentIdentity>,
        revocation_registry: Arc<dyn RevocationRegistry>,
        key_registry: Arc<dyn KeyRegistry>,
    ) -> Self {
        Self {
            signing_key,
            agent_identity,
            revocation_registry,
            key_registry,
        }
    }

    /// Create a new delegation token
    pub async fn create_delegation(
        &self,
        request: DelegationRequest,
    ) -> Result<DelegationToken, Error> {
        // Validate request
        self.validate_request(&request)?;

        // Verify we have the capabilities
        let our_caps = self.agent_identity.capabilities();
        for cap in &request.capabilities {
            if !self.has_capability(our_caps, cap) {
                return Err(Error::InsufficientCapabilities(cap.clone()));
            }
        }

        // Build claims
        let now = Utc::now().timestamp();
        let exp = now + request.ttl.num_seconds();

        let mut claims = DelegationClaims {
            iss: self.agent_identity.id().clone(),
            sub: request.to.clone(),
            aud: "clawdstrike:delegation".to_string(),
            iat: now,
            exp,
            nbf: Some(now),
            jti: self.generate_token_id(),
            cap: request.capabilities.clone(),
            chn: vec![],
            cel: None,
            pur: request.purpose,
            ctx: request.context,
        };

        if request.allow_redelegation {
            claims.cel = Some(request.capabilities.clone());
            claims.ctx.insert(
                "maxChainLength".to_string(),
                serde_json::json!(request.max_chain_length.unwrap_or(3)),
            );
        }

        // Sign token
        let raw = self.sign_token(&claims).await?;

        let token = DelegationToken { raw, claims };

        // Emit audit event
        self.emit_audit_event("delegation_created", &token).await;

        Ok(token)
    }

    /// Verify a delegation token
    pub async fn verify_token(
        &self,
        token_str: &str,
        expected_subject: Option<&AgentId>,
    ) -> Result<VerificationResult, Error> {
        // Decode
        let token = DelegationToken::from_base64(token_str)?;
        let claims = &token.claims;

        // Check expiration
        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return Ok(VerificationResult::invalid("Token expired"));
        }

        if let Some(nbf) = claims.nbf {
            if nbf > now {
                return Ok(VerificationResult::invalid("Token not yet valid"));
            }
        }

        // Check audience
        if claims.aud != "clawdstrike:delegation" {
            return Ok(VerificationResult::invalid("Invalid audience"));
        }

        // Check subject
        if let Some(expected) = expected_subject {
            if claims.sub != *expected {
                return Ok(VerificationResult::invalid("Subject mismatch"));
            }
        }

        // Check revocation
        if self.revocation_registry.is_revoked(&claims.jti).await? {
            return Ok(VerificationResult::invalid("Token revoked"));
        }

        // Verify signature
        let issuer_key = self.key_registry.get_public_key(&claims.iss).await?
            .ok_or(Error::UnknownIssuer)?;

        if !self.verify_signature(&token.raw, &issuer_key).await? {
            return Ok(VerificationResult::invalid("Invalid signature"));
        }

        // Verify chain
        if !claims.chn.is_empty() {
            for chain_token_id in &claims.chn {
                if self.revocation_registry.is_revoked(chain_token_id).await? {
                    return Ok(VerificationResult::invalid(
                        "Token in delegation chain revoked",
                    ));
                }
            }
        }

        Ok(VerificationResult::valid(token))
    }

    /// Re-delegate capabilities
    pub async fn redelegate(
        &self,
        parent_token_str: &str,
        request: RedelegationRequest,
    ) -> Result<DelegationToken, Error> {
        // Verify parent
        let parent_result = self
            .verify_token(parent_token_str, Some(self.agent_identity.id()))
            .await?;

        if !parent_result.is_valid() {
            return Err(Error::InvalidParentToken(parent_result.reason.unwrap_or_default()));
        }

        let parent = parent_result.token.unwrap();
        let parent_claims = &parent.claims;

        // Check re-delegation allowed
        let ceiling = parent_claims.cel.as_ref()
            .ok_or(Error::RedelegationNotAllowed)?;

        // Check chain length
        let chain_length = parent_claims.chn.len() + 1;
        let max_chain = parent_claims.ctx
            .get("maxChainLength")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;

        if chain_length >= max_chain {
            return Err(Error::ChainLengthExceeded);
        }

        // Verify attenuation
        for cap in &request.capabilities {
            if !self.capability_within_ceiling(cap, ceiling) {
                return Err(Error::CapabilityExceedsCeiling(cap.clone()));
            }
        }

        // Calculate expiry
        let now = Utc::now().timestamp();
        let requested_exp = now + request.ttl.num_seconds();
        let actual_exp = requested_exp.min(parent_claims.exp);

        // Build claims
        let claims = DelegationClaims {
            iss: self.agent_identity.id().clone(),
            sub: request.to.clone(),
            aud: "clawdstrike:delegation".to_string(),
            iat: now,
            exp: actual_exp,
            nbf: Some(now),
            jti: self.generate_token_id(),
            cap: request.capabilities.clone(),
            chn: {
                let mut chain = parent_claims.chn.clone();
                chain.push(parent_claims.jti.clone());
                chain
            },
            cel: if request.allow_redelegation {
                Some(self.attenuate_ceiling(&request.capabilities, ceiling))
            } else {
                None
            },
            pur: request.purpose,
            ctx: {
                let mut ctx = request.context;
                ctx.insert("parentTokenId".to_string(), serde_json::json!(parent_claims.jti));
                ctx.insert("maxChainLength".to_string(), serde_json::json!(max_chain));
                ctx
            },
        };

        let raw = self.sign_token(&claims).await?;
        let token = DelegationToken { raw, claims };

        self.emit_audit_event("delegation_redelegated", &token).await;

        Ok(token)
    }

    /// Revoke a delegation token
    pub async fn revoke(&self, token_id: &str, reason: Option<&str>) -> Result<(), Error> {
        self.revocation_registry.revoke(
            token_id,
            RevocationInfo {
                revoked_at: Utc::now(),
                revoked_by: self.agent_identity.id().clone(),
                reason: reason.map(String::from),
            },
        ).await?;

        self.emit_audit_event_simple("delegation_revoked", token_id).await;

        Ok(())
    }

    async fn sign_token(&self, claims: &DelegationClaims) -> Result<Vec<u8>, Error> {
        let payload = serde_cbor::to_vec(claims)?;

        let protected_header = serde_cbor::to_vec(&serde_json::json!({
            "alg": "EdDSA",
            "kid": self.signing_key.key_id(),
            "crit": ["exp", "aud"]
        }))?;

        let sig_input = self.build_sig_input(&protected_header, &payload);
        let signature = self.signing_key.sign(&sig_input).await?;

        // COSE Sign1
        Ok(serde_cbor::to_vec(&(
            protected_header,
            serde_cbor::Value::Map(vec![]), // unprotected
            payload,
            signature,
        ))?)
    }

    async fn verify_signature(&self, raw: &[u8], key: &dyn VerifyingKey) -> Result<bool, Error> {
        let (protected_header, _, payload, signature): (Vec<u8>, serde_cbor::Value, Vec<u8>, Vec<u8>) =
            serde_cbor::from_slice(raw)?;

        let sig_input = self.build_sig_input(&protected_header, &payload);
        key.verify(&sig_input, &signature).await
    }

    fn build_sig_input(&self, protected_header: &[u8], payload: &[u8]) -> Vec<u8> {
        serde_cbor::to_vec(&(
            "Signature1",
            protected_header,
            Vec::<u8>::new(), // external_aad
            payload,
        ))
        .unwrap()
    }

    fn has_capability(&self, our_caps: &[Capability], cap: &Capability) -> bool {
        our_caps.iter().any(|c| self.capability_subset_of(cap, c))
    }

    fn capability_within_ceiling(&self, cap: &Capability, ceiling: &[Capability]) -> bool {
        ceiling.iter().any(|c| self.capability_subset_of(cap, c))
    }

    fn capability_subset_of(&self, cap: &Capability, ceiling: &Capability) -> bool {
        let cap_parts: Vec<&str> = cap.0.split(':').collect();
        let ceil_parts: Vec<&str> = ceiling.0.split(':').collect();

        if cap_parts.len() < 3 || ceil_parts.len() < 3 {
            return false;
        }

        if cap_parts[0] != ceil_parts[0] || cap_parts[1] != ceil_parts[1] {
            return false;
        }

        self.resource_within(cap_parts[2], ceil_parts[2])
    }

    fn resource_within(&self, resource: &str, ceiling: &str) -> bool {
        if ceiling == "*" {
            return true;
        }
        if ceiling.ends_with("/**") {
            let prefix = &ceiling[..ceiling.len() - 3];
            return resource.starts_with(prefix);
        }
        resource == ceiling
    }

    fn attenuate_ceiling(&self, caps: &[Capability], parent: &[Capability]) -> Vec<Capability> {
        caps.iter()
            .filter(|c| self.capability_within_ceiling(c, parent))
            .cloned()
            .collect()
    }

    fn validate_request(&self, request: &DelegationRequest) -> Result<(), Error> {
        if request.capabilities.is_empty() {
            return Err(Error::NoCapabilities);
        }
        if request.ttl.num_seconds() <= 0 {
            return Err(Error::InvalidTtl);
        }
        Ok(())
    }

    fn generate_token_id(&self) -> String {
        let timestamp = Utc::now().timestamp_millis();
        let random: [u8; 12] = rand::random();
        format!("dlg-{:x}-{}", timestamp, base64::encode_config(&random, base64::URL_SAFE_NO_PAD))
    }

    async fn emit_audit_event(&self, event_type: &str, token: &DelegationToken) {
        tracing::info!(
            event = event_type,
            token_id = %token.id(),
            issuer = %token.issuer(),
            subject = %token.subject(),
            "Delegation event"
        );
    }

    async fn emit_audit_event_simple(&self, event_type: &str, token_id: &str) {
        tracing::info!(
            event = event_type,
            token_id = %token_id,
            "Delegation event"
        );
    }
}

/// Verification result
#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub token: Option<DelegationToken>,
}

impl VerificationResult {
    pub fn valid(token: DelegationToken) -> Self {
        Self {
            valid: true,
            reason: None,
            token: Some(token),
        }
    }

    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
            token: None,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

/// Re-delegation request
#[derive(Clone, Debug)]
pub struct RedelegationRequest {
    pub to: AgentId,
    pub capabilities: Vec<Capability>,
    pub ttl: Duration,
    pub purpose: Option<String>,
    pub context: HashMap<String, serde_json::Value>,
    pub allow_redelegation: bool,
}

/// Revocation registry trait
#[async_trait::async_trait]
pub trait RevocationRegistry: Send + Sync {
    async fn is_revoked(&self, token_id: &str) -> Result<bool, Error>;
    async fn revoke(&self, token_id: &str, info: RevocationInfo) -> Result<(), Error>;
    async fn revoke_by_issuer(&self, issuer: &AgentId, info: RevocationInfo) -> Result<u64, Error>;
}

/// Key registry trait
#[async_trait::async_trait]
pub trait KeyRegistry: Send + Sync {
    async fn get_public_key(&self, agent_id: &AgentId) -> Result<Option<Arc<dyn VerifyingKey>>, Error>;
}

/// Signing key trait
#[async_trait::async_trait]
pub trait SigningKey: Send + Sync {
    fn key_id(&self) -> &str;
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Verifying key trait
#[async_trait::async_trait]
pub trait VerifyingKey: Send + Sync {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

/// Revocation info
#[derive(Clone, Debug)]
pub struct RevocationInfo {
    pub revoked_at: DateTime<Utc>,
    pub revoked_by: AgentId,
    pub reason: Option<String>,
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Insufficient capabilities: {0:?}")]
    InsufficientCapabilities(Capability),
    #[error("No capabilities specified")]
    NoCapabilities,
    #[error("Invalid TTL")]
    InvalidTtl,
    #[error("Unknown issuer")]
    UnknownIssuer,
    #[error("Invalid parent token: {0}")]
    InvalidParentToken(String),
    #[error("Re-delegation not allowed")]
    RedelegationNotAllowed,
    #[error("Chain length exceeded")]
    ChainLengthExceeded,
    #[error("Capability exceeds ceiling: {0:?}")]
    CapabilityExceedsCeiling(Capability),
    #[error("Encoding error: {0}")]
    Encoding(#[from] serde_cbor::Error),
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Crypto error: {0}")]
    Crypto(String),
}
```

## Cryptographic Primitives

### Signature Algorithm

**Primary**: Ed25519 (EdDSA over Curve25519)
- 64-byte signatures
- 32-byte public keys
- Fast signing and verification
- Deterministic signatures (no random nonce)

**Alternative**: ECDSA P-384 (secp384r1)
- Signature size:
  - Raw (R || S): 96 bytes (48 + 48)
  - ASN.1 DER encoded: 102-104 bytes (variable due to integer encoding)
  - COSE uses raw format by default
- 97-byte public keys (uncompressed: 0x04 || X || Y)
- 49-byte public keys (compressed: 0x02/0x03 || X)
- NIST-approved for government/compliance use cases
- Requires secure random nonce (use RFC 6979 for deterministic nonces)

### Token Encoding

**COSE Sign1** (RFC 9052):
- Compact binary format
- Standard structure for signed messages
- Algorithm agility built-in

```
COSE_Sign1 = [
    protected : bstr .cbor Protected_Header,
    unprotected : Unprotected_Header,
    payload : bstr,
    signature : bstr
]
```

### Key Derivation (for token binding)

```
binding_key = HKDF-SHA256(
    IKM = master_secret,
    salt = token_id,
    info = "clawdstrike-delegation-binding"
)
```

## Token/Capability Formats

### Capability Syntax

```
capability = type ":" action ":" resource

type     = "file" | "network" | "exec" | "secret" | "tool"
action   = "read" | "write" | "execute" | "delete" | "grant" | "invoke" | "egress"
resource = path_pattern | host_pattern | tool_name

path_pattern = absolute_path | glob_pattern
  absolute_path = "/" segment ("/" segment)*
  glob_pattern  = path_with_wildcards
    "*"    = matches any single segment
    "**"   = matches any number of segments

host_pattern = domain | domain_glob
  domain      = label ("." label)*
  domain_glob = ("*" | label) ("." ("*" | label))*

Examples:
  file:read:/workspace/research/**
  file:write:/workspace/dist/*.js
  network:egress:*.github.com
  network:egress:api.openai.com
  exec:execute:kubectl
  secret:read:api-keys/*
  tool:invoke:web_search
```

### Serialized Token (Base64URL)

```
eyJhbGciOiJFZERTQSIsImtpZCI6InJlc2VhcmNoLWFnZW50LTAwMS1rZXkiLCJjcml0IjpbImV4cCIsImF1ZCJdfQ.
omFpc3MiOiJhZ2VudDpyZXNlYXJjaC1hZ2VudC0wMDEiLCJzdWIiOiJhZ2VudDpjb2RlLWFnZW50LTAwMSIsImF1
ZCI6ImNsYXdkc3RyaWtlOmRlbGVnYXRpb24iLCJpYXQiOjE3MDUzMTIyMDAsImV4cCI6MTcwNTMxNTgwMCwianRp
IjoiZGxnLWFiYzEyMy14eXo3ODkiLCJjYXAiOlsiZmlsZTpyZWFkOi93b3Jrc3BhY2UvcmVzZWFyY2gvKioiXX0.
dGhpcyBpcyBhIHNpZ25hdHVyZQ
```

## Attack Scenarios and Mitigations

### Attack 1: Token Theft via Logging

**Attack**: Delegation token logged in plaintext, extracted by attacker

**Mitigation**:
- Automatic redaction of tokens in logs
- Token binding to client identity
- Short TTLs reduce exposure window

### Attack 2: Delegation Bomb

**Attack**: Attacker creates exponential delegation chains to exhaust resources

**Mitigation**:
- Maximum chain length (default 3)
- Rate limiting on delegation creation
- Per-agent delegation quota

### Attack 3: Clock Skew Exploitation

**Attack**: Agent with misconfigured clock accepts expired tokens

**Mitigation**:
- Mandatory NTP sync for all agents
- Clock skew tolerance window (max 60 seconds)
- Server-side expiration checking

### Attack 4: Capability Inflation via Ambiguous Globs

**Attack**: Request `file:read:/*` claiming it's within ceiling `file:read:/workspace/**`

**Mitigation**:
- Strict glob containment checking
- Explicit prefix matching for `**`
- Reject ambiguous patterns

## Implementation Phases

### Phase 1: Basic Delegation
- Token format and signing
- Single-level delegation
- Time-based expiration

### Phase 2: Verification and Revocation
- Signature verification
- Revocation registry
- Audience validation

### Phase 3: Re-delegation
- Capability ceiling
- Chain tracking
- Attenuation enforcement

### Phase 4: Advanced Features
- Distributed revocation (CRL distribution)
- Token binding
- Hardware key support (HSM/TPM)

## Trust Model and Assumptions

### Trusted
- Clawdstrike delegation service implementation
- Cryptographic libraries (ed25519-dalek, ring)
- Revocation registry integrity

### Untrusted
- Individual agents (may be compromised)
- Network transport (may be observed)
- Clock synchronization (bounded skew assumed)

### Security Invariants

1. **Attenuation Only**: Delegated capabilities are always subset of delegator's
2. **Signature Binding**: Tokens cannot be forged without private key
3. **Temporal Bounds**: Tokens cannot extend beyond issuer's authority period
4. **Revocation Finality**: Once revoked, token cannot be un-revoked

### Implementation Security Notes

1. **Constant-Time Comparison**: All signature and token comparisons MUST use
   constant-time comparison functions to prevent timing attacks:
   - TypeScript: Use `crypto.timingSafeEqual()` from Node.js crypto module
   - Rust: Use `subtle::ConstantTimeEq` from the `subtle` crate

2. **Nonce Generation**: Use cryptographically secure random number generators:
   - TypeScript: `crypto.getRandomValues()` or `crypto.randomBytes()`
   - Rust: `getrandom` crate or `rand::rngs::OsRng`

3. **Key Zeroization**: Clear private key material from memory after use:
   - Rust: Use `zeroize` crate with `Zeroize` derive macro
   - TypeScript: Overwrite Uint8Array with zeros (less reliable due to GC)

4. **Side-Channel Resistance**: Avoid branching on secret data in critical paths
