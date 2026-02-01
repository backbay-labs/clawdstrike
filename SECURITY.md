# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: [security@hushclaw.dev](mailto:security@hushclaw.dev)
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Any suggested fixes (optional)

### Response Timeline

- **48 hours**: Initial acknowledgment of your report
- **7 days**: Assessment and severity determination
- **30 days**: Target for fix release (may vary based on complexity)

We will keep you informed throughout the process and credit you in the release notes (unless you prefer to remain anonymous).

## Security Model

Hushclaw implements defense-in-depth for AI agent execution:

### Guards

Five composable security guards provide runtime protection:

1. **ForbiddenPathGuard** - Blocks access to sensitive filesystem paths (SSH keys, credentials, etc.)
2. **EgressAllowlistGuard** - Controls network egress via domain allowlist/blocklist
3. **SecretLeakGuard** - Detects potential secrets in file writes and patches
4. **PatchIntegrityGuard** - Validates patch safety (size limits, forbidden patterns)
5. **McpToolGuard** - Restricts MCP tool invocations

### Attestation

Cryptographic verification for agent execution:

- **Ed25519 signatures** for receipt signing
- **SHA-256 and Keccak-256** content hashing
- **Merkle trees** for efficient proof generation
- **Canonical JSON** for deterministic serialization

### Daemon (hushd)

Centralized policy enforcement:

- HTTP API with key-based authentication
- SQLite-backed audit ledger
- Server-Sent Events (SSE) for real-time monitoring
- Policy hot-reload without restart

## Known Limitations (v0.1.0)

The following security features are **not yet implemented** in v0.1.0:

| Feature | Status | Notes |
|---------|--------|-------|
| Rate limiting | Planned | No request throttling on daemon API |
| TPM integration | Planned | Hardware key storage not supported |
| Audit log encryption | Planned | Logs stored in plaintext SQLite |
| Network isolation | Partial | Relies on policy, no kernel enforcement |

## Security Best Practices

When using Hushclaw in production:

1. **Use strict rulesets** - Start with `strict` ruleset and allow only required paths/domains
2. **Rotate signing keys** - Generate new keypairs periodically
3. **Monitor audit logs** - Review daemon audit ledger for anomalies
4. **Keep updated** - Apply security patches promptly
5. **Validate receipts** - Always verify signatures before trusting attestations

## Acknowledgments

We gratefully thank security researchers who help improve Hushclaw's security posture.
