# Agent Identity Attestation Specification

## Problem Statement

In multi-agent systems, establishing and verifying agent identity is foundational to all security guarantees. Without cryptographic identity attestation:

1. **Impersonation**: Malicious agents can claim to be trusted agents
2. **Repudiation**: Agents can deny actions they performed
3. **Ghost Agents**: Unregistered agents can operate without accountability
4. **Identity Confusion**: Multiple agents may claim the same identity

Agent identity attestation provides cryptographic proof of:
- **Who** the agent is (identity binding)
- **What** code the agent is running (code attestation)
- **When** the agent was registered (temporal binding)
- **Where** the agent is executing (environment attestation)

## Threat Model

### Attack Scenarios

#### Scenario 1: Agent Impersonation

```
Legitimate Agent A: ID = "code-agent-001"
                    |
                    v
Malicious Agent A': Claims ID = "code-agent-001"
                    |
                    v
System trusts A' with A's permissions
```

**Mitigation**: Cryptographic identity binding - only holder of private key can prove identity

#### Scenario 2: Code Substitution

```
Agent registered with hash(trusted_code)
                    |
                    v
Attacker replaces code at runtime
                    |
                    v
Agent executes malicious code under trusted identity
```

**Mitigation**: Code measurement and remote attestation, runtime integrity monitoring

#### Scenario 3: Replay of Registration

```
Agent A registered at time T
Agent A decommissioned at time T+1
                    |
                    v
Attacker replays registration at time T+2
                    |
                    v
Zombie agent with old credentials
```

**Mitigation**: Temporal binding with nonces, registration revocation lists

#### Scenario 4: Sybil Attack

```
Attacker registers agents:
  malicious-agent-001
  malicious-agent-002
  ...
  malicious-agent-999
                    |
                    v
Overwhelms legitimate agents in consensus
```

**Mitigation**: Registration rate limiting, proof-of-work, identity verification

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Rogue Agent | Generate keypairs, attempt registration | Access protected resources |
| Compromised Orchestrator | Issue identities | Create agents with elevated privileges |
| Network Attacker | Intercept registration | Steal identity credentials |
| Insider | Access to identity infrastructure | Create backdoor identities |

## Architecture

### Identity Hierarchy

```
+------------------------------------------------------------------+
|                    Root of Trust                                  |
|  +------------------------------------------------------------+  |
|  | Clawdstrike Identity Authority                              |  |
|  | - Issues organization certificates                          |  |
|  | - Offline root key (HSM-protected)                          |  |
|  +---------------------------+--------------------------------+  |
|                              |                                    |
+------------------------------+------------------------------------+
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
+---------------------------+    +---------------------------+
| Organization CA           |    | Organization CA           |
| (Acme Corp)               |    | (Beta Inc)                |
| - Issues agent certs      |    | - Issues agent certs      |
| - Online intermediate     |    | - Online intermediate     |
+-------------+-------------+    +-------------+-------------+
              |                                |
    +---------+---------+            +---------+---------+
    |                   |            |                   |
    v                   v            v                   v
+----------+    +----------+    +----------+    +----------+
| Agent    |    | Agent    |    | Agent    |    | Agent    |
| research |    | code     |    | analysis |    | deploy   |
+----------+    +----------+    +----------+    +----------+
```

### Attestation Components

```
+------------------------------------------------------------------+
|                    Agent Identity                                 |
+------------------------------------------------------------------+
| Public Identity:                                                  |
|   - Agent ID (unique identifier)                                  |
|   - Public Key (Ed25519 or ECDSA)                                |
|   - Certificate (X.509 or custom)                                |
|   - Capabilities (declared permissions)                          |
|   - Metadata (name, description, version)                        |
|                                                                   |
| Private Identity (held by agent only):                           |
|   - Private Key (Ed25519 or ECDSA)                               |
|   - Key Handle (if using HSM/TPM)                                |
|                                                                   |
| Attestation Evidence:                                            |
|   - Code Hash (SHA-256 of agent binary/script)                   |
|   - Environment Hash (runtime configuration)                     |
|   - Registration Timestamp                                       |
|   - Registration Nonce                                           |
|   - Platform Attestation (TPM quote, SGX report)                 |
+------------------------------------------------------------------+
```

### Registration Flow

```
+-------------+     +------------------+     +------------------+
| Agent       |     | Orchestrator     |     | Identity         |
|             |     |                  |     | Authority        |
+------+------+     +--------+---------+     +--------+---------+
       |                     |                        |
       | 1. Generate keypair |                        |
       |-------------------->|                        |
       |                     |                        |
       | 2. Attestation req  |                        |
       |    (pubkey, code_h) |                        |
       |-------------------->|                        |
       |                     |                        |
       |                     | 3. Verify orchestrator |
       |                     |----------------------->|
       |                     |                        |
       |                     | 4. Challenge           |
       |                     |<-----------------------|
       |                     |                        |
       | 5. Challenge        |                        |
       |<--------------------|                        |
       |                     |                        |
       | 6. Signed response  |                        |
       |-------------------->|                        |
       |                     |                        |
       |                     | 7. Response + evidence |
       |                     |----------------------->|
       |                     |                        |
       |                     | 8. Certificate         |
       |                     |<-----------------------|
       |                     |                        |
       | 9. Certificate      |                        |
       |<--------------------|                        |
       |                     |                        |
```

## API Design

### TypeScript Interface

```typescript
import { KeyPair, PublicKey, PrivateKey, Signature } from '@clawdstrike/crypto';

/**
 * Agent identity information
 */
export interface AgentIdentity {
  /** Unique agent identifier */
  id: AgentId;

  /** Agent's public key */
  publicKey: PublicKey;

  /** X.509 certificate (DER-encoded) */
  certificate: Uint8Array;

  /** Declared capabilities */
  capabilities: Capability[];

  /** Agent metadata */
  metadata: AgentMetadata;

  /** Attestation evidence */
  attestation: AttestationEvidence;

  /** Registration timestamp */
  registeredAt: Date;

  /** Certificate expiration */
  expiresAt: Date;

  /** Verify a signature from this agent */
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /** Get capabilities */
  getCapabilities(): Capability[];

  /** Check if identity is still valid */
  isValid(): boolean;
}

/**
 * Agent metadata
 */
export interface AgentMetadata {
  /** Human-readable name */
  name: string;

  /** Description */
  description?: string;

  /** Agent version */
  version: string;

  /** Agent type/role */
  role?: string;

  /** Custom labels */
  labels?: Record<string, string>;
}

/**
 * Attestation evidence
 */
export interface AttestationEvidence {
  /** Hash of agent code */
  codeHash: Uint8Array;

  /** Hash of runtime environment */
  environmentHash?: Uint8Array;

  /** Registration nonce (for freshness) */
  nonce: Uint8Array;

  /** Platform attestation (TPM/SGX) */
  platformAttestation?: PlatformAttestation;

  /** Measurement log */
  measurementLog?: MeasurementEntry[];
}

/**
 * Platform-specific attestation
 */
export interface PlatformAttestation {
  /** Attestation type */
  type: 'tpm2' | 'sgx' | 'sev' | 'none';

  /** Quote or report */
  quote: Uint8Array;

  /** Signature over quote */
  signature: Uint8Array;

  /** Certificate chain for signature verification */
  certChain?: Uint8Array[];
}

/**
 * Measurement log entry
 */
export interface MeasurementEntry {
  /** PCR index (for TPM) or measurement type */
  index: number;

  /** Hash algorithm */
  algorithm: 'sha256' | 'sha384';

  /** Measurement value */
  value: Uint8Array;

  /** Event description */
  event: string;
}

/**
 * Registration request
 */
export interface RegistrationRequest {
  /** Requested agent ID */
  agentId: AgentId;

  /** Agent's public key */
  publicKey: PublicKey;

  /** Agent metadata */
  metadata: AgentMetadata;

  /** Requested capabilities */
  capabilities: Capability[];

  /** Attestation evidence */
  attestation: AttestationEvidence;

  /** Signature over request (proves key possession) */
  signature: Uint8Array;
}

/**
 * Challenge for registration
 */
export interface RegistrationChallenge {
  /** Challenge nonce */
  nonce: Uint8Array;

  /** Timestamp */
  timestamp: number;

  /** Additional data to sign */
  data?: Uint8Array;

  /** Challenge expiration */
  expiresAt: Date;
}

/**
 * Challenge response
 */
export interface ChallengeResponse {
  /** Original challenge nonce */
  nonce: Uint8Array;

  /** Signature over challenge */
  signature: Uint8Array;

  /** Additional attestation (if requested) */
  additionalEvidence?: AttestationEvidence;
}

/**
 * Agent identity service (client-side)
 */
export class AgentIdentityClient {
  private keypair: KeyPair;
  private identity: AgentIdentity | null = null;
  private authorityUrl: string;

  constructor(config: IdentityClientConfig) {
    this.authorityUrl = config.authorityUrl;
    this.keypair = config.keypair ?? KeyPair.generate();
  }

  /**
   * Generate attestation evidence
   */
  async generateAttestation(): Promise<AttestationEvidence> {
    const codeHash = await this.measureCode();
    const envHash = await this.measureEnvironment();
    const nonce = crypto.getRandomValues(new Uint8Array(32));

    const evidence: AttestationEvidence = {
      codeHash,
      environmentHash: envHash,
      nonce,
    };

    // Add platform attestation if available
    if (this.hasTpm()) {
      evidence.platformAttestation = await this.getTpmQuote(nonce);
    }

    return evidence;
  }

  /**
   * Register with identity authority
   */
  async register(
    agentId: AgentId,
    metadata: AgentMetadata,
    capabilities: Capability[]
  ): Promise<AgentIdentity> {
    // Generate attestation
    const attestation = await this.generateAttestation();

    // Create registration request
    const request: RegistrationRequest = {
      agentId,
      publicKey: this.keypair.publicKey,
      metadata,
      capabilities,
      attestation,
      signature: new Uint8Array(0), // Will be filled
    };

    // Sign request
    const requestBytes = this.serializeRequest(request);
    request.signature = await this.keypair.sign(requestBytes);

    // Submit to authority
    const response = await fetch(`${this.authorityUrl}/v1/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: cbor.encode(request),
    });

    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    // Handle challenge if required
    const result = cbor.decode(await response.arrayBuffer());

    if (result.challenge) {
      const challenge = result.challenge as RegistrationChallenge;
      return this.handleChallenge(challenge, request);
    }

    // Parse certificate
    this.identity = this.parseIdentityResponse(result);
    return this.identity;
  }

  /**
   * Handle registration challenge
   */
  private async handleChallenge(
    challenge: RegistrationChallenge,
    originalRequest: RegistrationRequest
  ): Promise<AgentIdentity> {
    // Verify challenge freshness
    if (new Date() > challenge.expiresAt) {
      throw new Error('Challenge expired');
    }

    // Sign challenge
    const dataToSign = new Uint8Array([
      ...challenge.nonce,
      ...new Uint8Array(new BigUint64Array([BigInt(challenge.timestamp)]).buffer),
      ...(challenge.data ?? []),
    ]);

    const signature = await this.keypair.sign(dataToSign);

    const response: ChallengeResponse = {
      nonce: challenge.nonce,
      signature,
    };

    // Submit response
    const result = await fetch(`${this.authorityUrl}/v1/agents/register/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: cbor.encode({
        agentId: originalRequest.agentId,
        response,
      }),
    });

    if (!result.ok) {
      throw new Error(`Challenge response failed: ${result.statusText}`);
    }

    this.identity = this.parseIdentityResponse(
      cbor.decode(await result.arrayBuffer())
    );
    return this.identity;
  }

  /**
   * Sign a message as this agent
   */
  async sign(message: Uint8Array): Promise<Uint8Array> {
    return this.keypair.sign(message);
  }

  /**
   * Create an attestation statement
   */
  async attest(statement: string): Promise<AttestationStatement> {
    if (!this.identity) {
      throw new Error('Agent not registered');
    }

    const timestamp = Date.now();
    const data = new TextEncoder().encode(
      JSON.stringify({
        statement,
        agentId: this.identity.id,
        timestamp,
      })
    );

    const signature = await this.sign(data);

    return {
      agentId: this.identity.id,
      statement,
      timestamp,
      signature,
      certificate: this.identity.certificate,
    };
  }

  /**
   * Get current identity
   */
  getIdentity(): AgentIdentity | null {
    return this.identity;
  }

  /**
   * Refresh identity (renew certificate)
   */
  async refresh(): Promise<AgentIdentity> {
    if (!this.identity) {
      throw new Error('Agent not registered');
    }

    // Re-attest and request new certificate
    const attestation = await this.generateAttestation();
    const signature = await this.keypair.sign(
      this.serializeRefreshRequest(this.identity.id, attestation)
    );

    const response = await fetch(`${this.authorityUrl}/v1/agents/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: cbor.encode({
        agentId: this.identity.id,
        attestation,
        signature,
      }),
    });

    if (!response.ok) {
      throw new Error(`Refresh failed: ${response.statusText}`);
    }

    this.identity = this.parseIdentityResponse(
      cbor.decode(await response.arrayBuffer())
    );
    return this.identity;
  }

  private async measureCode(): Promise<Uint8Array> {
    // In Node.js: hash the main script and dependencies
    // In browser: hash loaded scripts
    // Placeholder implementation
    const encoder = new TextEncoder();
    return crypto.subtle.digest(
      'SHA-256',
      encoder.encode(process.argv[1] ?? 'unknown')
    ).then(buf => new Uint8Array(buf));
  }

  private async measureEnvironment(): Promise<Uint8Array> {
    const env = {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
    };
    return crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(JSON.stringify(env))
    ).then(buf => new Uint8Array(buf));
  }

  private hasTpm(): boolean {
    // Check for TPM availability
    return false; // Placeholder
  }

  private async getTpmQuote(nonce: Uint8Array): Promise<PlatformAttestation> {
    // Get TPM quote - platform specific
    throw new Error('TPM not available');
  }

  private serializeRequest(request: RegistrationRequest): Uint8Array {
    // Canonical serialization for signing
    return cbor.encode({
      agentId: request.agentId,
      publicKey: request.publicKey.raw,
      metadata: request.metadata,
      capabilities: request.capabilities,
      attestation: request.attestation,
    });
  }

  private serializeRefreshRequest(
    agentId: AgentId,
    attestation: AttestationEvidence
  ): Uint8Array {
    return cbor.encode({ agentId, attestation, timestamp: Date.now() });
  }

  private parseIdentityResponse(response: any): AgentIdentity {
    return {
      id: response.agentId,
      publicKey: PublicKey.fromRaw(response.publicKey),
      certificate: response.certificate,
      capabilities: response.capabilities,
      metadata: response.metadata,
      attestation: response.attestation,
      registeredAt: new Date(response.registeredAt),
      expiresAt: new Date(response.expiresAt),
      verify: async (msg, sig) => {
        const key = PublicKey.fromRaw(response.publicKey);
        return key.verify(msg, sig);
      },
      getCapabilities: () => response.capabilities,
      isValid: () => new Date() < new Date(response.expiresAt),
    };
  }
}

/**
 * Attestation statement (for audit/proof)
 */
export interface AttestationStatement {
  agentId: AgentId;
  statement: string;
  timestamp: number;
  signature: Uint8Array;
  certificate: Uint8Array;
}

/**
 * Identity authority service (server-side)
 */
export class IdentityAuthority {
  private ca: CertificateAuthority;
  private registry: IdentityRegistry;
  private challenges: Map<string, RegistrationChallenge> = new Map();

  constructor(config: IdentityAuthorityConfig) {
    this.ca = new CertificateAuthority(config.caKey, config.caCert);
    this.registry = config.registry;
  }

  /**
   * Handle registration request
   */
  async handleRegistration(
    request: RegistrationRequest
  ): Promise<RegistrationResult> {
    // Verify request signature
    const requestBytes = this.serializeForVerification(request);
    const pubKey = PublicKey.fromRaw(request.publicKey);
    if (!await pubKey.verify(requestBytes, request.signature)) {
      return { error: 'Invalid request signature' };
    }

    // Check if agent ID already exists
    if (await this.registry.exists(request.agentId)) {
      return { error: 'Agent ID already registered' };
    }

    // Validate attestation
    const attestationValid = await this.validateAttestation(request.attestation);
    if (!attestationValid.valid) {
      return { error: `Attestation invalid: ${attestationValid.reason}` };
    }

    // Validate requested capabilities
    const capabilitiesValid = await this.validateCapabilities(
      request.agentId,
      request.capabilities
    );
    if (!capabilitiesValid.valid) {
      return { error: `Capabilities invalid: ${capabilitiesValid.reason}` };
    }

    // Issue challenge for additional verification
    const challenge = this.createChallenge();
    this.challenges.set(request.agentId, challenge);

    return { challenge };
  }

  /**
   * Handle challenge response
   */
  async handleChallengeResponse(
    agentId: AgentId,
    response: ChallengeResponse,
    originalRequest: RegistrationRequest
  ): Promise<RegistrationResult> {
    // Get original challenge
    const challenge = this.challenges.get(agentId);
    if (!challenge) {
      return { error: 'No pending challenge' };
    }

    // Check expiration
    if (new Date() > challenge.expiresAt) {
      this.challenges.delete(agentId);
      return { error: 'Challenge expired' };
    }

    // Verify nonce matches
    if (!this.arrayEquals(response.nonce, challenge.nonce)) {
      return { error: 'Nonce mismatch' };
    }

    // Verify signature
    const dataToSign = new Uint8Array([
      ...challenge.nonce,
      ...new Uint8Array(new BigUint64Array([BigInt(challenge.timestamp)]).buffer),
      ...(challenge.data ?? []),
    ]);

    const pubKey = PublicKey.fromRaw(originalRequest.publicKey);
    if (!await pubKey.verify(dataToSign, response.signature)) {
      return { error: 'Invalid challenge response signature' };
    }

    // Issue certificate
    const certificate = await this.ca.issueCertificate({
      subject: agentId,
      publicKey: originalRequest.publicKey,
      capabilities: originalRequest.capabilities,
      validityDays: 30,
    });

    // Store in registry
    const identity: AgentIdentity = {
      id: agentId,
      publicKey: pubKey,
      certificate: certificate.der,
      capabilities: originalRequest.capabilities,
      metadata: originalRequest.metadata,
      attestation: originalRequest.attestation,
      registeredAt: new Date(),
      expiresAt: certificate.notAfter,
      verify: (msg, sig) => pubKey.verify(msg, sig),
      getCapabilities: () => originalRequest.capabilities,
      isValid: () => new Date() < certificate.notAfter,
    };

    await this.registry.store(identity);

    // Cleanup challenge
    this.challenges.delete(agentId);

    return { identity };
  }

  /**
   * Verify an agent's identity
   */
  async verifyIdentity(
    agentId: AgentId,
    publicKey: PublicKey
  ): Promise<VerificationResult> {
    const stored = await this.registry.get(agentId);
    if (!stored) {
      return { valid: false, reason: 'Agent not registered' };
    }

    // Check key matches
    if (!this.arrayEquals(stored.publicKey.raw, publicKey.raw)) {
      return { valid: false, reason: 'Public key mismatch' };
    }

    // Check certificate validity
    if (new Date() > stored.expiresAt) {
      return { valid: false, reason: 'Certificate expired' };
    }

    // Verify certificate chain
    const chainValid = await this.ca.verifyCertificate(stored.certificate);
    if (!chainValid) {
      return { valid: false, reason: 'Certificate chain invalid' };
    }

    return { valid: true, identity: stored };
  }

  /**
   * Revoke an agent's identity
   */
  async revokeIdentity(
    agentId: AgentId,
    reason: string
  ): Promise<void> {
    const identity = await this.registry.get(agentId);
    if (!identity) {
      throw new Error('Agent not found');
    }

    await this.ca.revokeCertificate(identity.certificate, reason);
    await this.registry.revoke(agentId, reason);
  }

  private createChallenge(): RegistrationChallenge {
    return {
      nonce: crypto.getRandomValues(new Uint8Array(32)),
      timestamp: Date.now(),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    };
  }

  private async validateAttestation(
    attestation: AttestationEvidence
  ): Promise<{ valid: boolean; reason?: string }> {
    // Verify code hash is in allowlist
    // Verify platform attestation if present
    // Verify nonce freshness
    return { valid: true };
  }

  private async validateCapabilities(
    agentId: AgentId,
    capabilities: Capability[]
  ): Promise<{ valid: boolean; reason?: string }> {
    // Check capabilities against policy
    // Ensure no privilege escalation
    return { valid: true };
  }

  private serializeForVerification(request: RegistrationRequest): Uint8Array {
    return cbor.encode({
      agentId: request.agentId,
      publicKey: request.publicKey.raw,
      metadata: request.metadata,
      capabilities: request.capabilities,
      attestation: request.attestation,
    });
  }

  private arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return a.every((val, i) => val === b[i]);
  }
}

/**
 * Identity registry interface
 */
export interface IdentityRegistry {
  exists(agentId: AgentId): Promise<boolean>;
  get(agentId: AgentId): Promise<AgentIdentity | null>;
  store(identity: AgentIdentity): Promise<void>;
  revoke(agentId: AgentId, reason: string): Promise<void>;
  list(): Promise<AgentIdentity[]>;
}

/**
 * Registration result
 */
export interface RegistrationResult {
  identity?: AgentIdentity;
  challenge?: RegistrationChallenge;
  error?: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
  valid: boolean;
  reason?: string;
  identity?: AgentIdentity;
}
```

### Rust Interface

```rust
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Agent identifier
pub type AgentId = String;

/// Public key wrapper
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub algorithm: KeyAlgorithm,
    pub raw: Vec<u8>,
}

/// Key algorithm
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP384,
}

/// Agent identity
#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub public_key: PublicKey,
    pub certificate: Vec<u8>,
    pub capabilities: Vec<Capability>,
    pub metadata: AgentMetadata,
    pub attestation: AttestationEvidence,
    pub registered_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AgentIdentity {
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    pub async fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        match self.public_key.algorithm {
            KeyAlgorithm::Ed25519 => {
                use ed25519_dalek::{Signature, VerifyingKey};
                let key = VerifyingKey::try_from(self.public_key.raw.as_slice())?;
                let sig = Signature::try_from(signature)?;
                Ok(key.verify_strict(message, &sig).is_ok())
            }
            KeyAlgorithm::EcdsaP384 => {
                // P-384 verification
                todo!()
            }
        }
    }
}

/// Agent metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub name: String,
    pub description: Option<String>,
    pub version: String,
    pub role: Option<String>,
    pub labels: std::collections::HashMap<String, String>,
}

/// Attestation evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub code_hash: Vec<u8>,
    pub environment_hash: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub platform_attestation: Option<PlatformAttestation>,
    pub measurement_log: Vec<MeasurementEntry>,
}

/// Platform attestation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformAttestation {
    pub attestation_type: PlatformType,
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PlatformType {
    Tpm2,
    Sgx,
    Sev,
    None,
}

/// Measurement entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeasurementEntry {
    pub index: u32,
    pub algorithm: HashAlgorithm,
    pub value: Vec<u8>,
    pub event: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

/// Registration request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub agent_id: AgentId,
    pub public_key: Vec<u8>,
    pub key_algorithm: KeyAlgorithm,
    pub metadata: AgentMetadata,
    pub capabilities: Vec<Capability>,
    pub attestation: AttestationEvidence,
    pub signature: Vec<u8>,
}

/// Registration challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub nonce: Vec<u8>,
    pub timestamp: i64,
    pub data: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
}

/// Challenge response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub additional_evidence: Option<AttestationEvidence>,
}

/// Agent identity client
pub struct AgentIdentityClient {
    keypair: Arc<dyn SigningKeypair>,
    identity: Option<AgentIdentity>,
    authority_url: String,
    http_client: reqwest::Client,
}

impl AgentIdentityClient {
    pub fn new(authority_url: String, keypair: Arc<dyn SigningKeypair>) -> Self {
        Self {
            keypair,
            identity: None,
            authority_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate attestation evidence
    pub async fn generate_attestation(&self) -> Result<AttestationEvidence, Error> {
        let code_hash = self.measure_code().await?;
        let env_hash = self.measure_environment().await?;
        let nonce = generate_random_bytes(32);

        Ok(AttestationEvidence {
            code_hash,
            environment_hash: Some(env_hash),
            nonce,
            platform_attestation: self.get_platform_attestation().await.ok(),
            measurement_log: vec![],
        })
    }

    /// Register with identity authority
    pub async fn register(
        &mut self,
        agent_id: AgentId,
        metadata: AgentMetadata,
        capabilities: Vec<Capability>,
    ) -> Result<AgentIdentity, Error> {
        let attestation = self.generate_attestation().await?;

        let mut request = RegistrationRequest {
            agent_id: agent_id.clone(),
            public_key: self.keypair.public_key_bytes(),
            key_algorithm: self.keypair.algorithm(),
            metadata,
            capabilities,
            attestation,
            signature: vec![],
        };

        // Sign request
        let request_bytes = serde_cbor::to_vec(&request)?;
        request.signature = self.keypair.sign(&request_bytes).await?;

        // Submit to authority
        let response = self
            .http_client
            .post(format!("{}/v1/agents/register", self.authority_url))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::to_vec(&request)?)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::RegistrationFailed(response.status().to_string()));
        }

        let result: RegistrationResult = serde_cbor::from_slice(&response.bytes().await?)?;

        match result {
            RegistrationResult::Challenge(challenge) => {
                self.handle_challenge(challenge, request).await
            }
            RegistrationResult::Identity(identity) => {
                self.identity = Some(identity.clone());
                Ok(identity)
            }
            RegistrationResult::Error(e) => Err(Error::RegistrationFailed(e)),
        }
    }

    /// Handle registration challenge
    async fn handle_challenge(
        &mut self,
        challenge: RegistrationChallenge,
        original_request: RegistrationRequest,
    ) -> Result<AgentIdentity, Error> {
        if Utc::now() > challenge.expires_at {
            return Err(Error::ChallengeExpired);
        }

        // Build data to sign
        let mut data_to_sign = challenge.nonce.clone();
        data_to_sign.extend_from_slice(&challenge.timestamp.to_le_bytes());
        if let Some(ref extra) = challenge.data {
            data_to_sign.extend_from_slice(extra);
        }

        let signature = self.keypair.sign(&data_to_sign).await?;

        let response = ChallengeResponse {
            nonce: challenge.nonce,
            signature,
            additional_evidence: None,
        };

        let result = self
            .http_client
            .post(format!("{}/v1/agents/register/challenge", self.authority_url))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::to_vec(&(original_request.agent_id.clone(), response))?)
            .send()
            .await?;

        if !result.status().is_success() {
            return Err(Error::ChallengeResponseFailed(result.status().to_string()));
        }

        let identity: AgentIdentity = serde_cbor::from_slice(&result.bytes().await?)?;
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    /// Sign a message
    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.keypair.sign(message).await
    }

    /// Create attestation statement
    pub async fn attest(&self, statement: &str) -> Result<AttestationStatement, Error> {
        let identity = self.identity.as_ref().ok_or(Error::NotRegistered)?;

        let timestamp = Utc::now().timestamp();
        let data = serde_json::json!({
            "statement": statement,
            "agentId": identity.id,
            "timestamp": timestamp,
        });

        let data_bytes = serde_json::to_vec(&data)?;
        let signature = self.sign(&data_bytes).await?;

        Ok(AttestationStatement {
            agent_id: identity.id.clone(),
            statement: statement.to_string(),
            timestamp,
            signature,
            certificate: identity.certificate.clone(),
        })
    }

    /// Get current identity
    pub fn identity(&self) -> Option<&AgentIdentity> {
        self.identity.as_ref()
    }

    async fn measure_code(&self) -> Result<Vec<u8>, Error> {
        // Hash the current executable
        let exe_path = std::env::current_exe()?;
        let exe_bytes = tokio::fs::read(&exe_path).await?;
        Ok(sha256(&exe_bytes))
    }

    async fn measure_environment(&self) -> Result<Vec<u8>, Error> {
        let env_info = serde_json::json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "family": std::env::consts::FAMILY,
        });
        Ok(sha256(serde_json::to_string(&env_info)?.as_bytes()))
    }

    async fn get_platform_attestation(&self) -> Result<PlatformAttestation, Error> {
        // Platform-specific attestation
        Err(Error::PlatformAttestationUnavailable)
    }
}

/// Attestation statement
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationStatement {
    pub agent_id: AgentId,
    pub statement: String,
    pub timestamp: i64,
    pub signature: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// Registration result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RegistrationResult {
    Identity(AgentIdentity),
    Challenge(RegistrationChallenge),
    Error(String),
}

/// Signing keypair trait
#[async_trait]
pub trait SigningKeypair: Send + Sync {
    fn public_key_bytes(&self) -> Vec<u8>;
    fn algorithm(&self) -> KeyAlgorithm;
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Identity registry trait
#[async_trait]
pub trait IdentityRegistry: Send + Sync {
    async fn exists(&self, agent_id: &AgentId) -> Result<bool, Error>;
    async fn get(&self, agent_id: &AgentId) -> Result<Option<AgentIdentity>, Error>;
    async fn store(&self, identity: &AgentIdentity) -> Result<(), Error>;
    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<(), Error>;
    async fn list(&self) -> Result<Vec<AgentIdentity>, Error>;
}

/// Identity authority
pub struct IdentityAuthority {
    ca: CertificateAuthority,
    registry: Arc<dyn IdentityRegistry>,
    pending_challenges: tokio::sync::RwLock<std::collections::HashMap<AgentId, RegistrationChallenge>>,
}

impl IdentityAuthority {
    pub fn new(ca: CertificateAuthority, registry: Arc<dyn IdentityRegistry>) -> Self {
        Self {
            ca,
            registry,
            pending_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn handle_registration(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationResult, Error> {
        // Verify signature
        let request_for_verify = RegistrationRequest {
            signature: vec![],
            ..request.clone()
        };
        let request_bytes = serde_cbor::to_vec(&request_for_verify)?;

        if !self.verify_signature(&request.public_key, &request_bytes, &request.signature).await? {
            return Ok(RegistrationResult::Error("Invalid request signature".into()));
        }

        // Check agent ID availability
        if self.registry.exists(&request.agent_id).await? {
            return Ok(RegistrationResult::Error("Agent ID already registered".into()));
        }

        // Validate attestation
        self.validate_attestation(&request.attestation).await?;

        // Create challenge
        let challenge = RegistrationChallenge {
            nonce: generate_random_bytes(32),
            timestamp: Utc::now().timestamp(),
            data: None,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        let mut challenges = self.pending_challenges.write().await;
        challenges.insert(request.agent_id.clone(), challenge.clone());

        Ok(RegistrationResult::Challenge(challenge))
    }

    pub async fn handle_challenge_response(
        &self,
        agent_id: &AgentId,
        response: ChallengeResponse,
        original_request: &RegistrationRequest,
    ) -> Result<RegistrationResult, Error> {
        // Get and remove challenge
        let challenge = {
            let mut challenges = self.pending_challenges.write().await;
            challenges.remove(agent_id)
        };

        let challenge = challenge.ok_or(Error::NoPendingChallenge)?;

        if Utc::now() > challenge.expires_at {
            return Ok(RegistrationResult::Error("Challenge expired".into()));
        }

        if response.nonce != challenge.nonce {
            return Ok(RegistrationResult::Error("Nonce mismatch".into()));
        }

        // Verify signature
        let mut data_to_sign = challenge.nonce.clone();
        data_to_sign.extend_from_slice(&challenge.timestamp.to_le_bytes());
        if let Some(ref extra) = challenge.data {
            data_to_sign.extend_from_slice(extra);
        }

        if !self.verify_signature(
            &original_request.public_key,
            &data_to_sign,
            &response.signature,
        ).await? {
            return Ok(RegistrationResult::Error("Invalid challenge response".into()));
        }

        // Issue certificate
        let certificate = self.ca.issue_certificate(
            agent_id,
            &original_request.public_key,
            &original_request.capabilities,
            Duration::days(30),
        ).await?;

        let public_key = PublicKey {
            algorithm: original_request.key_algorithm.clone(),
            raw: original_request.public_key.clone(),
        };

        let identity = AgentIdentity {
            id: agent_id.clone(),
            public_key,
            certificate: certificate.der,
            capabilities: original_request.capabilities.clone(),
            metadata: original_request.metadata.clone(),
            attestation: original_request.attestation.clone(),
            registered_at: Utc::now(),
            expires_at: certificate.not_after,
        };

        self.registry.store(&identity).await?;

        Ok(RegistrationResult::Identity(identity))
    }

    pub async fn verify_identity(
        &self,
        agent_id: &AgentId,
        public_key: &[u8],
    ) -> Result<Option<AgentIdentity>, Error> {
        let stored = self.registry.get(agent_id).await?;

        match stored {
            Some(identity) => {
                if identity.public_key.raw != public_key {
                    return Ok(None);
                }
                if !identity.is_valid() {
                    return Ok(None);
                }
                if !self.ca.verify_certificate(&identity.certificate).await? {
                    return Ok(None);
                }
                Ok(Some(identity))
            }
            None => Ok(None),
        }
    }

    async fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let key = VerifyingKey::try_from(public_key)?;
        let sig = Signature::try_from(signature)?;
        Ok(key.verify_strict(message, &sig).is_ok())
    }

    async fn validate_attestation(&self, attestation: &AttestationEvidence) -> Result<(), Error> {
        // Validate code hash against allowlist
        // Validate platform attestation if present
        // Verify nonce freshness
        Ok(())
    }
}

/// Certificate authority (minimal interface)
pub struct CertificateAuthority {
    // CA implementation details
}

pub struct Certificate {
    pub der: Vec<u8>,
    pub not_after: DateTime<Utc>,
}

impl CertificateAuthority {
    pub async fn issue_certificate(
        &self,
        subject: &str,
        public_key: &[u8],
        capabilities: &[Capability],
        validity: Duration,
    ) -> Result<Certificate, Error> {
        // X.509 certificate generation
        todo!()
    }

    pub async fn verify_certificate(&self, cert: &[u8]) -> Result<bool, Error> {
        // Certificate chain verification
        todo!()
    }

    pub async fn revoke_certificate(&self, cert: &[u8], reason: &str) -> Result<(), Error> {
        // Add to CRL
        todo!()
    }
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Not registered")]
    NotRegistered,
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge response failed: {0}")]
    ChallengeResponseFailed(String),
    #[error("No pending challenge")]
    NoPendingChallenge,
    #[error("Platform attestation unavailable")]
    PlatformAttestationUnavailable,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}
```

## Cryptographic Primitives

### Key Generation

**Ed25519** (primary):
```
seed = CSPRNG(32 bytes)
private_key = seed
public_key = Ed25519_ScalarMult(private_key, G)
```

**ECDSA P-384** (alternative):
```
private_key = CSPRNG(48 bytes) mod n
public_key = ECDSA_ScalarMult(private_key, G)
```

### Code Measurement

```
code_hash = SHA-256(executable_binary || loaded_modules)
```

For interpreted languages:
```
code_hash = SHA-256(main_script || imported_modules_sorted)
```

### Certificate Format

X.509v3 with custom extensions:
- Subject: `CN=<agent_id>, O=<organization>`
- Subject Public Key: Ed25519 or ECDSA P-384
- Validity: Configurable (default 30 days)
- Extensions:
  - `clawdstrike-capabilities`: List of granted capabilities
  - `clawdstrike-attestation-hash`: Hash of attestation evidence

## Attack Scenarios and Mitigations

### Attack 1: Key Extraction via Memory Dump

**Attack**: Attacker dumps agent memory to extract private key

**Mitigation**:
- Use platform key storage (Keychain, TPM, HSM)
- Memory protection (mlock, guard pages)
- Key zeroization on process exit

### Attack 2: Compromised Orchestrator Issues Rogue Identities

**Attack**: Compromised orchestrator registers malicious agents

**Mitigation**:
- Multi-party approval for high-privilege agents
- Audit log of all registrations
- Certificate transparency log

### Attack 3: Certificate Pinning Bypass

**Attack**: Attacker substitutes CA certificate to issue fake agent certs

**Mitigation**:
- CA key in HSM
- Certificate pinning in clients
- CT log monitoring

### Attack 4: Attestation Forgery

**Attack**: Agent claims false code hash

**Mitigation**:
- Hardware attestation (TPM/SGX)
- Signed measurement log
- Remote attestation verification

## Implementation Phases

### Phase 1: Basic Identity
- Key generation and storage
- Simple registration flow
- Certificate issuance

### Phase 2: Attestation
- Code measurement
- Environment measurement
- Challenge-response protocol

### Phase 3: Platform Attestation
- TPM integration
- SGX/SEV support
- Measurement log verification

### Phase 4: Certificate Management
- CRL distribution
- OCSP responder
- Certificate transparency

## Trust Model and Assumptions

### Trusted Components
- Identity Authority CA
- Cryptographic libraries
- Hardware security modules (if used)

### Untrusted Components
- Individual agents
- Network transport
- Orchestrator (partially - cannot forge signatures)

### Security Invariants
1. **Key Binding**: Only holder of private key can prove identity
2. **Attestation Freshness**: Attestation includes recent nonce
3. **Certificate Validity**: Expired/revoked certificates rejected
4. **Capability Binding**: Capabilities cryptographically bound to identity
