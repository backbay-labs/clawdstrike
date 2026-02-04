# OpenClaw Certified Badge Program

## Overview

The OpenClaw Certified Badge is a visual trust signal and cryptographic attestation that an AI agent deployment meets Clawdstrike security standards. This document specifies the badge design, cryptographic underpinnings, verification flow, and distribution mechanisms.

---

## Problem Statement

### The Trust Signal Gap

1. **No Visual Trust Indicator**: Users interacting with AI agents have no way to assess whether the agent has been security-vetted.

2. **Badge Fraud**: Without cryptographic verification, security badges can be copied, forged, or displayed after expiration.

3. **Stale Certifications**: Static badges don't reflect real-time compliance status; an agent could be certified in January and compromised in March.

4. **Verification Friction**: End users shouldn't need to understand cryptography to trust a badge.

5. **Multi-Stakeholder Needs**: Different audiences (end users, auditors, developers) need different levels of badge detail.

### Use Cases

| Persona | Badge Interaction | Need |
|---------|-------------------|------|
| End User | Sees badge in UI | Quick trust assessment |
| Developer | Embeds badge in docs | Show security commitment |
| Auditor | Verifies badge signature | Prove certification validity |
| Procurement | Checks badge tier | Evaluate vendor posture |
| Insurance | Queries badge API | Risk assessment input |
| Regulator | Audits badge history | Compliance verification |

---

## Badge Design

### Visual Hierarchy

```
CERTIFIED BADGE ANATOMY
========================

+--------------------------------------------------+
|                                                  |
|  [1. Shield Icon]  [2. OPENCLAW CERTIFIED]       |
|                                                  |
|  [3. Tier Badge: GOLD / SILVER / PLATINUM]       |
|                                                  |
|  [4. Agent/Organization Name]                    |
|                                                  |
|  [5. Valid: YYYY-MM-DD to YYYY-MM-DD]            |
|                                                  |
|  [6. Verification Fingerprint: a3f8b2c1...]      |
|                                                  |
|  [7. QR Code / Verification Link]                |
|                                                  |
+--------------------------------------------------+

1. Shield Icon: Visual trust anchor, varies by tier color
2. Program Name: "OPENCLAW CERTIFIED" branding
3. Tier Badge: Color-coded certification level
4. Subject: What/who is certified
5. Validity: Date range of certification
6. Fingerprint: First 8 chars of certification ID
7. Verification: Machine-readable verification path
```

### Tier Color Palette

| Tier | Primary Color | Secondary | Shield Style |
|------|---------------|-----------|--------------|
| Certified | #6B7280 (Gray) | #1F2937 | Outline |
| Silver | #9CA3AF (Silver) | #374151 | Filled |
| Gold | #F59E0B (Amber) | #D97706 | Filled + Glow |
| Platinum | #8B5CF6 (Violet) | #6D28D9 | Filled + Gradient |

### Badge Variants

```
VARIANT 1: Full Badge (Marketing/Documentation)
+--------------------------------------------------+
|  [Shield]  OPENCLAW CERTIFIED                    |
|            GOLD                                  |
|  finance-assistant-v2                            |
|  Valid: 2025-01-15 to 2026-01-14                 |
|  Verify: cert.openclaw.dev/a3f8b2c1              |
+--------------------------------------------------+

VARIANT 2: Compact Badge (UI Embed)
+----------------------------+
|  [Shield] GOLD CERTIFIED   |
+----------------------------+

VARIANT 3: Icon Only (Space Constrained)
+--------+
|[Shield]|
+--------+

VARIANT 4: Status Badge (CI/CD)
+--------------------------------------------------+
|  OpenClaw: PASSING | Tier: GOLD | Last: 2h ago   |
+--------------------------------------------------+
```

---

## Cryptographic Design

### Badge Data Structure

```typescript
interface CertificationBadge {
  // Core identity
  certificationId: string;        // UUID v4
  version: "1.0.0";               // Badge schema version

  // Subject
  subject: {
    type: "agent" | "organization" | "deployment";
    id: string;                   // Unique subject identifier
    name: string;                 // Human-readable name
    metadata?: Record<string, unknown>;
  };

  // Certification details
  certification: {
    tier: "certified" | "silver" | "gold" | "platinum";
    issueDate: string;            // RFC 3339
    expiryDate: string;           // RFC 3339
    frameworks: string[];         // ["hipaa", "pci-dss", "soc2"]
  };

  // Policy binding
  policy: {
    hash: string;                 // SHA-256 of policy at certification time
    version: string;              // Policy schema version
    ruleset?: string;             // Named ruleset if applicable
  };

  // Evidence reference
  evidence: {
    receiptCount: number;         // Number of signed receipts
    merkleRoot: string;           // Root hash of evidence tree
    auditLogRef: string;          // Pointer to audit storage
  };

  // Issuer signature
  issuer: {
    id: string;                   // Clawdstrike issuer ID
    publicKey: string;            // Ed25519 public key (base64)
    signature: string;            // Ed25519 signature (base64)
    signedAt: string;             // Signature timestamp
  };
}
```

### Signature Scheme

**Ed25519 Specification:**
- Algorithm: Ed25519 (EdDSA over Curve25519)
- Public Key: 32 bytes (256 bits)
- Signature: 64 bytes (512 bits)
- Hash: SHA-512 (internal to Ed25519, not SHA-256)
- Encoding: Base64url without padding (RFC 4648)

**Important:** Ed25519 uses SHA-512 internally for the signature computation. The message (canonical JSON) is signed directly without pre-hashing, as Ed25519 handles this internally.

```rust
// Signature creation flow (Ed25519 - RFC 8032)
fn sign_badge(badge: &CertificationBadge, keypair: &Ed25519Keypair) -> SignedBadge {
    // 1. Create badge data without signature field
    let badge_without_sig = BadgeForSigning {
        certificationId: badge.certificationId.clone(),
        version: badge.version.clone(),
        subject: badge.subject.clone(),
        certification: badge.certification.clone(),
        policy: badge.policy.clone(),
        evidence: badge.evidence.clone(),
        issuer: IssuerWithoutSig {
            id: badge.issuer.id.clone(),
            publicKey: badge.issuer.publicKey.clone(),
            signedAt: badge.issuer.signedAt.clone(),
        },
    };

    // 2. Serialize to canonical JSON (RFC 8785 - JCS)
    let canonical = json_canonicalize(&badge_without_sig);

    // 3. Sign directly with Ed25519 (no pre-hashing)
    // Ed25519 internally uses SHA-512 for the signature computation
    let signature = keypair.sign(canonical.as_bytes());

    // 4. Encode signature as base64url (no padding)
    let signature_b64 = base64url_encode_no_pad(&signature);

    // 5. Return complete badge with signature
    SignedBadge {
        badge: CertificationBadge {
            issuer: Issuer {
                signature: signature_b64,
                ..badge.issuer.clone()
            },
            ..badge.clone()
        },
    }
}

// Signature verification flow
fn verify_badge(badge: &SignedBadge) -> Result<bool, VerifyError> {
    // 1. Extract and decode public key (32 bytes)
    let pubkey_bytes = base64url_decode(&badge.badge.issuer.publicKey)?;
    if pubkey_bytes.len() != 32 {
        return Err(VerifyError::InvalidPublicKeyLength);
    }
    let pubkey = Ed25519PublicKey::from_bytes(&pubkey_bytes)?;

    // 2. Reconstruct canonical form (exclude signature)
    let badge_without_sig = BadgeForSigning::from(&badge.badge);
    let canonical = json_canonicalize(&badge_without_sig);

    // 3. Decode signature (64 bytes)
    let signature_bytes = base64url_decode(&badge.badge.issuer.signature)?;
    if signature_bytes.len() != 64 {
        return Err(VerifyError::InvalidSignatureLength);
    }
    let signature = Ed25519Signature::from_bytes(&signature_bytes)?;

    // 4. Verify signature
    pubkey.verify(canonical.as_bytes(), &signature)
        .map(|_| true)
        .map_err(|_| VerifyError::SignatureInvalid)
}
```

**Canonical JSON (RFC 8785 - JSON Canonicalization Scheme):**
- Sort object keys lexicographically
- No whitespace between tokens
- Numbers in their most compact form
- Unicode escaping for non-ASCII characters

### Key Management

```yaml
key_hierarchy:
  root_ca:
    algorithm: Ed25519
    purpose: "Sign intermediate CAs"
    storage: "HSM (offline)"
    rotation: "Never (revoke if compromised)"

  intermediate_ca:
    algorithm: Ed25519
    purpose: "Sign badge issuing keys"
    storage: "HSM (online)"
    rotation: "Annually"

  badge_issuer:
    algorithm: Ed25519
    purpose: "Sign individual badges"
    storage: "KMS (cloud)"
    rotation: "Quarterly"
    per_region: true

certificate_chain:
  - root_ca.pub
  - intermediate_ca.pub (signed by root)
  - badge_issuer.pub (signed by intermediate)
  - badge (signed by issuer)
```

### Revocation

```typescript
interface RevocationRecord {
  certificationId: string;
  revokedAt: string;              // RFC 3339
  reason: RevocationReason;
  revokedBy: string;              // Issuer or admin ID
  supersededBy?: string;          // New certification if renewed
}

enum RevocationReason {
  EXPIRED = "expired",
  SECURITY_INCIDENT = "security_incident",
  POLICY_VIOLATION = "policy_violation",
  VOLUNTARY = "voluntary",
  ADMINISTRATIVE = "administrative",
}

// Revocation check endpoint
GET /api/v1/certifications/{certificationId}/status
Response: {
  valid: boolean;
  revoked: boolean;
  revocation?: RevocationRecord;
  currentStatus: "active" | "expired" | "revoked" | "suspended";
}
```

---

## Verification Flow

### End User Verification

```
User clicks badge
       |
       v
+------------------+
| Redirect to      |
| verification URL |
+------------------+
       |
       v
+------------------+
| Fetch badge data |
| from API         |
+------------------+
       |
       v
+------------------+
| Display:         |
| - Subject name   |
| - Tier           |
| - Validity       |
| - Compliance     |
| - [Valid/Invalid]|
+------------------+
```

### Programmatic Verification

```typescript
// SDK usage
import { ClawdstrikeVerifier } from '@clawdstrike/verify';

const verifier = new ClawdstrikeVerifier({
  trustedRoots: ['https://cert.openclaw.dev/.well-known/ca.json'],
});

// Verify a badge
const result = await verifier.verifyBadge(badgeJson);

if (result.valid) {
  console.log(`Badge for ${result.badge.subject.name} is valid`);
  console.log(`Tier: ${result.badge.certification.tier}`);
  console.log(`Expires: ${result.badge.certification.expiryDate}`);
} else {
  console.error(`Verification failed: ${result.error}`);
}

// Verify inline (HTML embed)
const inlineResult = await verifier.verifyEmbed(
  document.querySelector('[data-openclaw-badge]')
);
```

### Offline Verification

```bash
# CLI verification without network
$ openclaw verify badge.json --offline --ca-bundle /path/to/roots.json

Badge Verification
==================
Subject: finance-assistant-v2
Tier: GOLD
Valid: 2025-01-15 to 2026-01-14

Signature: VALID (Ed25519)
Chain: VALID (3 certificates)
Expiry: VALID (362 days remaining)

Overall: VALID
```

---

## Distribution Mechanisms

### Embed Options

#### HTML Embed

```html
<!-- Standard embed with auto-verification -->
<div class="openclaw-badge"
     data-certification-id="a3f8b2c1-..."
     data-style="full"
     data-verify="true">
</div>
<script src="https://cert.openclaw.dev/embed.js" async></script>

<!-- Static image (no verification) -->
<a href="https://cert.openclaw.dev/verify/a3f8b2c1">
  <img src="https://cert.openclaw.dev/badge/a3f8b2c1.svg"
       alt="OpenClaw Certified - Gold"
       width="200" height="80" />
</a>
```

#### Markdown

```markdown
[![OpenClaw Certified](https://cert.openclaw.dev/badge/a3f8b2c1.svg)](https://cert.openclaw.dev/verify/a3f8b2c1)
```

#### React Component

```jsx
import { OpenClawBadge } from '@clawdstrike/react';

function AgentProfile({ agentId }) {
  return (
    <div>
      <h1>Finance Assistant</h1>
      <OpenClawBadge
        certificationId="a3f8b2c1-..."
        variant="full"
        onVerify={(result) => console.log('Verified:', result)}
      />
    </div>
  );
}
```

#### CLI Badge Generation

```bash
# Generate badge for certified agent
$ openclaw badge generate \
    --agent-id finance-assistant-v2 \
    --tier gold \
    --output badge.json

# Export as SVG
$ openclaw badge export badge.json --format svg > badge.svg

# Export as PNG
$ openclaw badge export badge.json --format png --size 2x > badge.png
```

### API-Based Distribution

```typescript
// Badge generation API
POST /api/v1/certifications/{certificationId}/badge
Content-Type: application/json

{
  "format": "svg" | "png" | "json",
  "variant": "full" | "compact" | "icon",
  "size": "1x" | "2x" | "3x",
  "theme": "light" | "dark" | "auto"
}

Response:
{
  "badge": "<svg>...</svg>",  // or base64 PNG, or JSON
  "contentType": "image/svg+xml",
  "cacheControl": "public, max-age=3600",
  "etag": "abc123"
}
```

---

## Badge Lifecycle

### Issuance Flow

```
1. Certification Request
   |-- Organization submits certification application
   |-- Selects target tier and compliance frameworks

2. Evidence Collection
   |-- System collects audit logs for review period
   |-- Generates signed receipts for all sessions
   |-- Computes Merkle root of evidence

3. Validation
   |-- Automated checks against tier requirements
   |-- Manual review for Gold/Platinum tiers
   |-- External auditor sign-off (if required)

4. Badge Issuance
   |-- Generate certification badge data
   |-- Sign with issuing key
   |-- Publish to verification service
   |-- Notify organization

5. Distribution
   |-- Provide embed codes
   |-- Update organization profile
   |-- Push to partner integrations
```

### Renewal Flow

```
1. Renewal Reminder (60 days before expiry)
   |-- Email notification
   |-- Dashboard alert
   |-- API webhook

2. Continuous Compliance Check
   |-- Verify no critical violations in period
   |-- Confirm policy version compatibility
   |-- Validate audit log retention

3. Renewal Decision
   |-- Auto-renew if all checks pass (Silver)
   |-- Manual approval for Gold/Platinum
   |-- Upgrade/downgrade tier if needed

4. New Badge Issuance
   |-- Issue new badge with extended validity
   |-- Mark old badge as superseded
   |-- Update all embed references
```

### Revocation Flow

```
1. Revocation Trigger
   |-- Security incident detected
   |-- Policy violation severity >= Error
   |-- Voluntary revocation request
   |-- Administrative decision

2. Revocation Record
   |-- Create revocation entry
   |-- Sign revocation with issuer key
   |-- Publish to revocation list (CRL)

3. Notification
   |-- Alert organization
   |-- Update verification endpoints
   |-- Push to partner integrations

4. Remediation Path
   |-- Provide incident details
   |-- Recommend corrective actions
   |-- Re-certification timeline
```

---

## Integration with Clawdstrike Guards

### Guard Status Mapping

| Guard | Certification Requirement | Evidence Type |
|-------|---------------------------|---------------|
| ForbiddenPathGuard | No Error/Critical violations | Access logs |
| EgressAllowlistGuard | Allowlist mode enforced | Egress logs |
| SecretLeakGuard | Enabled with redaction | Scan results |
| PatchIntegrityGuard | No dangerous patterns | Patch logs |
| McpToolGuard | Tool allowlist defined | Tool call logs |
| PromptInjectionGuard | Warn or Block mode | Injection reports |

### Badge Update Triggers

```yaml
badge_update_events:
  - event: "policy_change"
    action: "Re-validate certification"
    urgency: "24 hours"

  - event: "critical_violation"
    action: "Suspend badge"
    urgency: "Immediate"

  - event: "guard_disabled"
    action: "Downgrade tier"
    urgency: "1 hour"

  - event: "audit_gap"
    action: "Warning notice"
    urgency: "7 days"
```

---

## Pricing Considerations

### Badge Costs

| Item | Free Tier | Paid Tiers |
|------|-----------|------------|
| Badge Generation | 1 per org | Unlimited |
| Verification API | 1000/month | Unlimited |
| Custom Branding | No | Silver+ |
| White-Label | No | Platinum |
| Embed Analytics | No | Gold+ |

### Partner Revenue Share

- **Embedded in SaaS**: 20% rev share for platforms embedding OpenClaw badges
- **Auditor Referral**: 15% commission for referred certifications
- **Insurance Integration**: Per-verification fee for risk assessment queries

---

## Implementation Roadmap

### Phase 1: Core Badge (Q1 2025)
- [ ] Badge data structure and schema
- [ ] Ed25519 signing implementation
- [ ] Basic SVG/PNG generation
- [ ] Verification API endpoint
- [ ] CLI badge commands

### Phase 2: Distribution (Q2 2025)
- [ ] JavaScript embed library
- [ ] React/Vue components
- [ ] Markdown/HTML snippets
- [ ] CI/CD badge integration
- [ ] Analytics dashboard

### Phase 3: Ecosystem (Q3 2025)
- [ ] Partner API access
- [ ] Custom branding options
- [ ] Revocation list (CRL)
- [ ] OCSP responder
- [ ] Mobile SDK

### Phase 4: Enterprise (Q4 2025)
- [ ] White-label badges
- [ ] SSO integration
- [ ] Bulk operations API
- [ ] Advanced analytics
- [ ] SLA guarantees

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Badge forgery | Ed25519 signatures, key pinning |
| Key compromise | HSM storage, key rotation, revocation |
| Replay attacks | Timestamp validation, nonce in verification |
| Badge scraping | Rate limiting, authentication for high-volume |
| Phishing badges | Domain verification, embed integrity checks |

### Audit Requirements

- All badge issuance logged with full context
- Key usage audited and alerted
- Verification requests logged for anomaly detection
- Revocation actions require multi-party approval (Platinum)

---

## Appendix: Badge Schema (JSON Schema)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://openclaw.dev/schemas/badge/v1.json",
  "title": "OpenClaw Certification Badge",
  "type": "object",
  "required": ["certificationId", "version", "subject", "certification", "policy", "issuer"],
  "properties": {
    "certificationId": {
      "type": "string",
      "format": "uuid"
    },
    "version": {
      "type": "string",
      "const": "1.0.0"
    },
    "subject": {
      "type": "object",
      "required": ["type", "id", "name"],
      "properties": {
        "type": { "enum": ["agent", "organization", "deployment"] },
        "id": { "type": "string" },
        "name": { "type": "string" }
      }
    },
    "certification": {
      "type": "object",
      "required": ["tier", "issueDate", "expiryDate"],
      "properties": {
        "tier": { "enum": ["certified", "silver", "gold", "platinum"] },
        "issueDate": { "type": "string", "format": "date-time" },
        "expiryDate": { "type": "string", "format": "date-time" },
        "frameworks": { "type": "array", "items": { "type": "string" } }
      }
    },
    "policy": {
      "type": "object",
      "required": ["hash", "version"],
      "properties": {
        "hash": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
        "version": { "type": "string" },
        "ruleset": { "type": "string" }
      }
    },
    "issuer": {
      "type": "object",
      "required": ["id", "publicKey", "signature", "signedAt"],
      "properties": {
        "id": { "type": "string" },
        "publicKey": { "type": "string" },
        "signature": { "type": "string" },
        "signedAt": { "type": "string", "format": "date-time" }
      }
    }
  }
}
```
