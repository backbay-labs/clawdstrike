# Certification Verification API Specification

## Overview

This document specifies the Clawdstrike Certification API, a RESTful service for issuing, verifying, and managing OpenClaw certifications. The API enables programmatic verification of agent certifications, integration with CI/CD pipelines, and automated compliance workflows.

---

## Problem Statement

### The Verification Integration Gap

1. **Manual Verification**: Organizations manually check certifications, creating lag and human error.

2. **CI/CD Gaps**: No automated way to gate deployments on certification status.

3. **Stale Badges**: Displayed badges may not reflect current certification status.

4. **Cross-Organization Trust**: No standardized way for organizations to verify each other's agents.

5. **Auditor Access**: External auditors lack self-service access to evidence.

6. **Webhook Complexity**: Different consumers need different notification patterns.

### Use Cases

| Consumer | API Use Case | Integration Point |
|----------|--------------|-------------------|
| DevOps | Gate deployment on certification | CI/CD pipeline |
| Security | Continuous compliance monitoring | SIEM/SOAR |
| Procurement | Vendor certification check | Supplier portal |
| Marketing | Embed verified badge | Website/docs |
| Auditor | Evidence retrieval | Audit portal |
| Insurance | Risk assessment | Underwriting system |

---

## API Design Principles

### RESTful Conventions

```
Base URL: https://api.openclaw.dev/v1

Authentication: Bearer token (API key or OAuth2)
Content-Type: application/json
Rate Limiting: Token bucket (100 req/min default)
Versioning: URL path (/v1, /v2)
Pagination: Cursor-based
```

### Response Format

```json
{
  "data": { ... },           // Primary response data
  "meta": {                  // Metadata
    "requestId": "req_abc123",
    "timestamp": "2025-01-15T10:30:00Z"
  },
  "links": {                 // HATEOAS links
    "self": "https://api.openclaw.dev/v1/...",
    "next": "..."
  }
}
```

### Error Format

```json
{
  "error": {
    "code": "CERTIFICATION_NOT_FOUND",
    "message": "Certification with ID 'abc123' not found",
    "details": {
      "certificationId": "abc123"
    },
    "requestId": "req_xyz789"
  }
}
```

---

## Authentication

### API Key Authentication

```bash
# Header-based
curl -H "Authorization: Bearer cs_live_abc123..." \
  https://api.openclaw.dev/v1/certifications

# API keys have prefixes:
# cs_live_  - Production keys
# cs_test_  - Test/sandbox keys
# cs_pub_   - Public verification keys (limited scope)
```

### OAuth2 Authentication

```bash
# Token request
curl -X POST https://auth.openclaw.dev/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=certifications:read certifications:verify"

# Response
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "certifications:read certifications:verify"
}
```

### Scopes

| Scope | Description |
|-------|-------------|
| `certifications:read` | Read certification details |
| `certifications:verify` | Verify certification validity |
| `certifications:write` | Create/update certifications |
| `evidence:read` | Read audit evidence |
| `evidence:export` | Export evidence bundles |
| `badges:generate` | Generate badge assets |
| `webhooks:manage` | Manage webhook subscriptions |
| `admin` | Full administrative access |

---

## API Endpoints

### Certifications

#### List Certifications

```http
GET /v1/certifications
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `organization_id` | string | Filter by organization |
| `agent_id` | string | Filter by agent |
| `tier` | string | Filter by tier (certified, silver, gold, platinum) |
| `status` | string | Filter by status (active, expired, revoked) |
| `framework` | string | Filter by compliance framework |
| `limit` | integer | Page size (default: 20, max: 100) |
| `cursor` | string | Pagination cursor |

**Response:**

```json
{
  "data": [
    {
      "certificationId": "cert_abc123",
      "subject": {
        "type": "agent",
        "id": "agent_xyz789",
        "name": "finance-assistant-v2"
      },
      "certification": {
        "tier": "gold",
        "issueDate": "2025-01-15T00:00:00Z",
        "expiryDate": "2026-01-14T23:59:59Z",
        "frameworks": ["hipaa", "soc2"],
        "status": "active"
      },
      "policy": {
        "hash": "sha256:a1b2c3d4...",
        "version": "1.0.0",
        "ruleset": "clawdstrike:strict"
      },
      "issuer": {
        "id": "iss_clawdstrike",
        "name": "Clawdstrike Certification Authority"
      }
    }
  ],
  "meta": {
    "requestId": "req_abc123",
    "timestamp": "2025-01-15T10:30:00Z",
    "totalCount": 42
  },
  "links": {
    "self": "https://api.openclaw.dev/v1/certifications?limit=20",
    "next": "https://api.openclaw.dev/v1/certifications?cursor=eyJ..."
  }
}
```

#### Get Certification

```http
GET /v1/certifications/{certificationId}
Authorization: Bearer {token}
```

**Response:**

```json
{
  "data": {
    "certificationId": "cert_abc123",
    "version": "1.0.0",
    "subject": {
      "type": "agent",
      "id": "agent_xyz789",
      "name": "finance-assistant-v2",
      "organizationId": "org_acme",
      "metadata": {
        "description": "Financial analysis AI assistant",
        "version": "2.3.1"
      }
    },
    "certification": {
      "tier": "gold",
      "issueDate": "2025-01-15T00:00:00Z",
      "expiryDate": "2026-01-14T23:59:59Z",
      "frameworks": ["hipaa", "soc2"],
      "status": "active"
    },
    "policy": {
      "hash": "sha256:a1b2c3d4e5f6...",
      "version": "1.0.0",
      "ruleset": "clawdstrike:strict"
    },
    "evidence": {
      "receiptCount": 15234,
      "merkleRoot": "sha256:f1e2d3c4...",
      "auditLogRef": "s3://clawdstrike-audit/org_acme/2025/01/",
      "lastUpdated": "2025-01-15T10:00:00Z"
    },
    "issuer": {
      "id": "iss_clawdstrike",
      "name": "Clawdstrike Certification Authority",
      "publicKey": "ed25519:MCo...",
      "signature": "ed25519:XyZ...",
      "signedAt": "2025-01-15T00:00:00Z"
    }
  },
  "meta": {
    "requestId": "req_def456",
    "timestamp": "2025-01-15T10:30:00Z"
  },
  "links": {
    "self": "https://api.openclaw.dev/v1/certifications/cert_abc123",
    "verify": "https://api.openclaw.dev/v1/certifications/cert_abc123/verify",
    "badge": "https://api.openclaw.dev/v1/certifications/cert_abc123/badge",
    "evidence": "https://api.openclaw.dev/v1/certifications/cert_abc123/evidence"
  }
}
```

#### Create Certification (Internal/Partner)

```http
POST /v1/certifications
Authorization: Bearer {token}
Content-Type: application/json

{
  "subject": {
    "type": "agent",
    "id": "agent_xyz789",
    "name": "finance-assistant-v2",
    "organizationId": "org_acme"
  },
  "tier": "gold",
  "frameworks": ["hipaa", "soc2"],
  "policy": {
    "hash": "sha256:a1b2c3d4...",
    "version": "1.0.0"
  },
  "evidence": {
    "merkleRoot": "sha256:f1e2d3c4...",
    "auditLogRef": "s3://..."
  },
  "validityDays": 365
}
```

**Response:**

```json
{
  "data": {
    "certificationId": "cert_new123",
    "status": "active",
    "issueDate": "2025-01-15T00:00:00Z",
    "expiryDate": "2026-01-14T23:59:59Z"
  },
  "meta": {
    "requestId": "req_ghi789"
  }
}
```

### Verification

#### Verify Certification

```http
POST /v1/certifications/{certificationId}/verify
Authorization: Bearer {token}
Content-Type: application/json

{
  "verificationContext": {
    "requiredTier": "silver",        // Optional: minimum tier required
    "requiredFrameworks": ["hipaa"], // Optional: required frameworks
    "checkRevocation": true,         // Check revocation list
    "checkExpiry": true              // Check expiry date
  }
}
```

**Response (Valid):**

```json
{
  "data": {
    "valid": true,
    "certificationId": "cert_abc123",
    "subject": {
      "type": "agent",
      "id": "agent_xyz789",
      "name": "finance-assistant-v2"
    },
    "tier": "gold",
    "status": "active",
    "checks": {
      "signature": { "passed": true },
      "expiry": { "passed": true, "daysRemaining": 364 },
      "revocation": { "passed": true },
      "tierRequirement": { "passed": true, "actual": "gold", "required": "silver" },
      "frameworkRequirement": { "passed": true, "actual": ["hipaa", "soc2"], "required": ["hipaa"] }
    },
    "verifiedAt": "2025-01-15T10:30:00Z"
  },
  "meta": {
    "requestId": "req_ver123"
  }
}
```

**Response (Invalid):**

```json
{
  "data": {
    "valid": false,
    "certificationId": "cert_abc123",
    "checks": {
      "signature": { "passed": true },
      "expiry": { "passed": false, "reason": "Certification expired on 2024-12-31" },
      "revocation": { "passed": true },
      "tierRequirement": { "passed": true },
      "frameworkRequirement": { "passed": false, "reason": "Missing required framework: pci-dss" }
    },
    "failureReasons": [
      "Certification expired on 2024-12-31",
      "Missing required framework: pci-dss"
    ],
    "verifiedAt": "2025-01-15T10:30:00Z"
  },
  "meta": {
    "requestId": "req_ver124"
  }
}
```

#### Batch Verification

```http
POST /v1/certifications/verify-batch
Authorization: Bearer {token}
Content-Type: application/json

{
  "certifications": [
    { "certificationId": "cert_abc123" },
    { "certificationId": "cert_def456" },
    { "agentId": "agent_xyz789" }  // Lookup by agent
  ],
  "verificationContext": {
    "requiredTier": "certified",
    "checkRevocation": true
  }
}
```

**Response:**

```json
{
  "data": {
    "results": [
      { "certificationId": "cert_abc123", "valid": true, "tier": "gold" },
      { "certificationId": "cert_def456", "valid": false, "reason": "revoked" },
      { "certificationId": "cert_ghi789", "valid": true, "tier": "silver" }
    ],
    "summary": {
      "total": 3,
      "valid": 2,
      "invalid": 1
    }
  }
}
```

### Badges

#### Get Badge

```http
GET /v1/certifications/{certificationId}/badge
Authorization: Bearer {token} (optional for public badges)
Accept: image/svg+xml | image/png | application/json
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant` | string | Badge variant: full, compact, icon |
| `theme` | string | Color theme: light, dark, auto |
| `size` | string | Size: 1x, 2x, 3x |

**Response (SVG):**

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 80">
  <!-- Badge SVG content -->
  <rect fill="#F59E0B" rx="8" ... />
  <text>OpenClaw Certified - GOLD</text>
  ...
</svg>
```

**Response (JSON):**

```json
{
  "data": {
    "certificationId": "cert_abc123",
    "embedCode": {
      "html": "<a href=\"https://cert.openclaw.dev/verify/cert_abc123\"><img src=\"...\" /></a>",
      "markdown": "[![OpenClaw Certified](https://...)](https://cert.openclaw.dev/verify/cert_abc123)",
      "react": "<OpenClawBadge certificationId=\"cert_abc123\" />"
    },
    "directUrls": {
      "svg": "https://api.openclaw.dev/v1/certifications/cert_abc123/badge.svg",
      "png": "https://api.openclaw.dev/v1/certifications/cert_abc123/badge.png",
      "png2x": "https://api.openclaw.dev/v1/certifications/cert_abc123/badge@2x.png"
    },
    "verificationUrl": "https://cert.openclaw.dev/verify/cert_abc123"
  }
}
```

### Evidence

#### List Evidence

```http
GET /v1/certifications/{certificationId}/evidence
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Evidence type: audit_log, receipt, policy, guard_config |
| `start_date` | string | Start of date range (ISO 8601) |
| `end_date` | string | End of date range (ISO 8601) |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response:**

```json
{
  "data": {
    "evidenceSummary": {
      "auditEvents": 15234,
      "signedReceipts": 892,
      "policySnapshots": 3,
      "guardConfigurations": 6
    },
    "items": [
      {
        "evidenceId": "evd_abc123",
        "type": "audit_log",
        "period": {
          "start": "2025-01-01T00:00:00Z",
          "end": "2025-01-15T23:59:59Z"
        },
        "eventCount": 5234,
        "hash": "sha256:abc123...",
        "size": 15234567,
        "downloadUrl": "https://evidence.openclaw.dev/..."
      }
    ]
  },
  "links": {
    "export": "https://api.openclaw.dev/v1/certifications/cert_abc123/evidence/export"
  }
}
```

#### Export Evidence Bundle

```http
POST /v1/certifications/{certificationId}/evidence/export
Authorization: Bearer {token}
Content-Type: application/json

{
  "format": "zip",
  "dateRange": {
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-01-15T23:59:59Z"
  },
  "includeTypes": ["audit_log", "policy", "guard_config"],
  "complianceTemplate": "hipaa",
  "notifyEmail": "auditor@example.com"
}
```

**Response:**

```json
{
  "data": {
    "exportId": "exp_xyz789",
    "status": "processing",
    "estimatedSize": 150000000,
    "estimatedCompletion": "2025-01-15T11:00:00Z"
  },
  "links": {
    "status": "https://api.openclaw.dev/v1/evidence-exports/exp_xyz789"
  }
}
```

#### Get Export Status

```http
GET /v1/evidence-exports/{exportId}
Authorization: Bearer {token}
```

**Response:**

```json
{
  "data": {
    "exportId": "exp_xyz789",
    "status": "completed",
    "downloadUrl": "https://evidence.openclaw.dev/exports/exp_xyz789.zip",
    "expiresAt": "2025-01-22T10:30:00Z",
    "size": 145678901,
    "hash": "sha256:def456..."
  }
}
```

### Policy

#### Get Policy Snapshot

```http
GET /v1/certifications/{certificationId}/policy
Authorization: Bearer {token}
```

**Response:**

```json
{
  "data": {
    "policyHash": "sha256:a1b2c3d4...",
    "version": "1.0.0",
    "ruleset": "clawdstrike:strict",
    "effectiveFrom": "2025-01-01T00:00:00Z",
    "yaml": "version: \"1.0.0\"\nname: ...\n...",
    "guards": {
      "forbidden_path": { "enabled": true, "patterns": 15 },
      "egress_allowlist": { "enabled": true, "allowedDomains": 8 },
      "secret_leak": { "enabled": true, "patterns": 12 },
      "patch_integrity": { "enabled": true, "forbiddenPatterns": 8 },
      "mcp_tool": { "enabled": true, "allowedTools": 5 },
      "prompt_injection": { "enabled": true, "blockLevel": "medium" }
    }
  }
}
```

#### List Policy History

```http
GET /v1/certifications/{certificationId}/policy/history
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Page size (default: 20, max: 100) |
| `cursor` | string | Pagination cursor |

**Response:**

```json
{
  "data": {
    "items": [
      {
        "policyHash": "sha256:a1b2c3d4...",
        "version": "1.0.0",
        "effectiveFrom": "2025-01-01T00:00:00Z",
        "effectiveTo": null,
        "changeSummary": "Initial policy deployment"
      },
      {
        "policyHash": "sha256:xyz789...",
        "version": "1.0.0",
        "effectiveFrom": "2024-10-01T00:00:00Z",
        "effectiveTo": "2024-12-31T23:59:59Z",
        "changeSummary": "Previous policy version"
      }
    ]
  },
  "links": {
    "self": "https://api.openclaw.dev/v1/certifications/cert_abc123/policy/history"
  }
}
```

### Revocation

#### Revoke Certification

```http
POST /v1/certifications/{certificationId}/revoke
Authorization: Bearer {token}
Content-Type: application/json

{
  "reason": "security_incident",
  "details": "Policy violation detected during security audit",
  "notifyOrganization": true
}
```

**Response:**

```json
{
  "data": {
    "certificationId": "cert_abc123",
    "status": "revoked",
    "revokedAt": "2025-01-15T10:30:00Z",
    "reason": "security_incident",
    "revokedBy": "admin_xyz789"
  }
}
```

#### Get Revocation Status

```http
GET /v1/certifications/{certificationId}/revocation
Authorization: Bearer {token}
```

**Response:**

```json
{
  "data": {
    "revoked": true,
    "revokedAt": "2025-01-15T10:30:00Z",
    "reason": "security_incident",
    "details": "Policy violation detected during security audit",
    "revokedBy": "admin_xyz789",
    "supersededBy": null
  }
}
```

### Webhooks

#### Create Webhook

```http
POST /v1/webhooks
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "https://your-server.com/clawdstrike-webhook",
  "events": [
    "certification.issued",
    "certification.expiring",
    "certification.revoked",
    "violation.detected"
  ],
  "secret": "your-hmac-secret",
  "enabled": true,
  "metadata": {
    "environment": "production"
  }
}
```

**Response:**

```json
{
  "data": {
    "webhookId": "whk_abc123",
    "url": "https://your-server.com/clawdstrike-webhook",
    "events": ["certification.issued", "certification.expiring", "certification.revoked", "violation.detected"],
    "enabled": true,
    "createdAt": "2025-01-15T10:30:00Z"
  }
}
```

#### Webhook Events

```json
// certification.issued
{
  "event": "certification.issued",
  "timestamp": "2025-01-15T10:30:00Z",
  "data": {
    "certificationId": "cert_abc123",
    "subject": { "type": "agent", "id": "agent_xyz789" },
    "tier": "gold",
    "frameworks": ["hipaa"]
  }
}

// certification.expiring
{
  "event": "certification.expiring",
  "timestamp": "2025-12-15T00:00:00Z",
  "data": {
    "certificationId": "cert_abc123",
    "daysRemaining": 30,
    "expiryDate": "2026-01-14T23:59:59Z",
    "renewalUrl": "https://cert.openclaw.dev/renew/cert_abc123"
  }
}

// violation.detected
{
  "event": "violation.detected",
  "timestamp": "2025-01-15T10:35:00Z",
  "data": {
    "violationId": "vio_xyz789",
    "certificationId": "cert_abc123",
    "guard": "forbidden_path",
    "severity": "high",
    "resource": "/home/user/.ssh/id_rsa",
    "sessionId": "sess_abc123"
  }
}
```

#### Webhook Signature Verification

```typescript
import crypto from 'crypto';

function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(`sha256=${expectedSignature}`)
  );
}

// Usage
app.post('/clawdstrike-webhook', (req, res) => {
  const signature = req.headers['x-clawdstrike-signature'];
  const isValid = verifyWebhookSignature(
    JSON.stringify(req.body),
    signature,
    process.env.WEBHOOK_SECRET
  );

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  // Process webhook
  const event = req.body;
  console.log(`Received ${event.event}:`, event.data);

  res.status(200).send('OK');
});
```

---

## SDK Integration

### JavaScript/TypeScript SDK

```typescript
import { ClawdstrikeClient } from '@clawdstrike/sdk';

const client = new ClawdstrikeClient({
  apiKey: process.env.CLAWDSTRIKE_API_KEY,
  environment: 'production', // or 'sandbox'
});

// Verify certification
const verification = await client.certifications.verify('cert_abc123', {
  requiredTier: 'silver',
  requiredFrameworks: ['hipaa'],
});

if (verification.valid) {
  console.log(`Agent ${verification.subject.name} is certified`);
} else {
  console.log(`Verification failed: ${verification.failureReasons.join(', ')}`);
}

// Get badge
const badge = await client.certifications.getBadge('cert_abc123', {
  variant: 'full',
  theme: 'light',
});

// Subscribe to events
client.webhooks.subscribe('certification.revoked', async (event) => {
  console.log(`Certification ${event.data.certificationId} was revoked`);
  // Trigger incident response
});
```

### Python SDK

```python
from clawdstrike import ClawdstrikeClient

client = ClawdstrikeClient(api_key=os.environ["CLAWDSTRIKE_API_KEY"])

# Verify certification
verification = client.certifications.verify(
    certification_id="cert_abc123",
    required_tier="silver",
    required_frameworks=["hipaa"]
)

if verification.valid:
    print(f"Agent {verification.subject.name} is certified")
else:
    print(f"Verification failed: {', '.join(verification.failure_reasons)}")

# Export evidence for auditor
export = client.evidence.export(
    certification_id="cert_abc123",
    format="zip",
    compliance_template="hipaa",
    date_range={"start": "2025-01-01", "end": "2025-01-31"}
)

# Poll for completion
while export.status != "completed":
    time.sleep(30)
    export = client.evidence.get_export(export.export_id)

print(f"Download evidence: {export.download_url}")
```

### CLI Integration

```bash
# Install CLI
npm install -g @clawdstrike/cli

# Configure
clawdstrike config set api_key cs_live_abc123...

# Verify certification
clawdstrike verify cert_abc123 --tier silver --framework hipaa

# Get badge embed code
clawdstrike badge cert_abc123 --format markdown

# Export evidence
clawdstrike evidence export cert_abc123 \
  --start 2025-01-01 \
  --end 2025-01-31 \
  --template hipaa \
  --output evidence.zip
```

### CI/CD Integration

```yaml
# GitHub Actions
name: Security Gate
on: [push, pull_request]

jobs:
  verify-certification:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify Agent Certification
        uses: clawdstrike/verify-action@v1
        with:
          api_key: ${{ secrets.CLAWDSTRIKE_API_KEY }}
          agent_id: ${{ vars.AGENT_ID }}
          required_tier: silver
          required_frameworks: hipaa,soc2
          fail_on_invalid: true

      - name: Deploy
        if: success()
        run: ./deploy.sh
```

```groovy
// Jenkins Pipeline
pipeline {
    agent any
    stages {
        stage('Verify Certification') {
            steps {
                script {
                    def result = sh(
                        script: """
                            clawdstrike verify ${AGENT_ID} \
                                --tier silver \
                                --framework hipaa \
                                --json
                        """,
                        returnStdout: true
                    )
                    def verification = readJSON text: result
                    if (!verification.valid) {
                        error("Certification verification failed: ${verification.failureReasons}")
                    }
                }
            }
        }
    }
}
```

---

## Rate Limiting

### Limits by Tier

| Tier | Requests/Minute | Burst | Concurrent |
|------|-----------------|-------|------------|
| Free | 10 | 20 | 2 |
| Silver | 100 | 200 | 10 |
| Gold | 500 | 1000 | 50 |
| Platinum | 2000 | 5000 | 200 |

### Rate Limit Headers

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705318800
X-RateLimit-RetryAfter: 60
```

### Rate Limit Response

```json
HTTP/1.1 429 Too Many Requests
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please retry after 45 seconds.",
    "retryAfter": 45
  }
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid API key |
| `INSUFFICIENT_SCOPE` | 403 | Token lacks required scope |
| `CERTIFICATION_NOT_FOUND` | 404 | Certification ID not found |
| `AGENT_NOT_FOUND` | 404 | Agent ID not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

---

## Implementation Phases

### Phase 1: Core API (Q1 2025)
- [ ] Authentication (API key)
- [ ] GET /certifications
- [ ] GET /certifications/{id}
- [ ] POST /certifications/{id}/verify
- [ ] GET /certifications/{id}/badge
- [ ] Rate limiting
- [ ] SDK (JS/Python)

### Phase 2: Evidence API (Q2 2025)
- [ ] GET /certifications/{id}/evidence
- [ ] POST /evidence/export
- [ ] GET /evidence-exports/{id}
- [ ] Auditor portal
- [ ] CLI tool

### Phase 3: Webhooks (Q3 2025)
- [ ] Webhook management API
- [ ] Event delivery
- [ ] Retry logic
- [ ] Signature verification
- [ ] Event filtering

### Phase 4: Enterprise (Q4 2025)
- [ ] OAuth2 support
- [ ] Batch operations
- [ ] GraphQL API (optional)
- [ ] SLA guarantees
- [ ] Custom domains

---

## Security Considerations

### API Security

| Threat | Mitigation |
|--------|------------|
| API key theft | Key rotation, IP allowlisting, short TTL |
| Replay attacks | Request timestamps, nonces |
| Data exposure | Field-level permissions, audit logging |
| DDoS | Rate limiting, CDN, geo-blocking |
| Injection | Input validation, parameterized queries |

### Audit Logging

```json
{
  "apiLogEntry": {
    "timestamp": "2025-01-15T10:30:00Z",
    "requestId": "req_abc123",
    "method": "POST",
    "path": "/v1/certifications/cert_abc123/verify",
    "clientId": "client_xyz",
    "ipAddress": "1.2.3.4",
    "userAgent": "ClawdstrikeSDK/1.0.0",
    "responseStatus": 200,
    "latencyMs": 45,
    "scope": ["certifications:verify"]
  }
}
```

---

## Appendix: OpenAPI Specification

The full OpenAPI 3.0 specification is available at:
- **Production**: https://api.openclaw.dev/v1/openapi.json
- **Sandbox**: https://api.sandbox.openclaw.dev/v1/openapi.json

Key endpoints summary:

```yaml
openapi: 3.0.3
info:
  title: Clawdstrike Certification API
  version: 1.0.0
paths:
  /v1/certifications:
    get: { summary: "List certifications" }
    post: { summary: "Create certification" }
  /v1/certifications/verify-batch:
    post: { summary: "Batch verify certifications" }
  /v1/certifications/{id}:
    get: { summary: "Get certification" }
  /v1/certifications/{id}/verify:
    post: { summary: "Verify certification" }
  /v1/certifications/{id}/badge:
    get: { summary: "Get badge" }
  /v1/certifications/{id}/evidence:
    get: { summary: "List evidence" }
  /v1/certifications/{id}/evidence/export:
    post: { summary: "Export evidence" }
  /v1/certifications/{id}/policy:
    get: { summary: "Get policy snapshot" }
  /v1/certifications/{id}/policy/history:
    get: { summary: "List policy history" }
  /v1/certifications/{id}/revoke:
    post: { summary: "Revoke certification" }
  /v1/certifications/{id}/revocation:
    get: { summary: "Get revocation status" }
  /v1/evidence-exports/{id}:
    get: { summary: "Get export status" }
  /v1/webhooks:
    get: { summary: "List webhooks" }
    post: { summary: "Create webhook" }
  /v1/webhooks/{id}:
    get: { summary: "Get webhook" }
    patch: { summary: "Update webhook" }
    delete: { summary: "Delete webhook" }
```
