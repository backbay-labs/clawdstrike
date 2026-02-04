# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: [connor@backbay.io](mailto:connor@backbay.io)
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

Clawdstrike implements defense-in-depth for AI agent execution:

### Enforcement boundary (explicit)

Clawdstrike enforces policy at the **agent/tool boundary**. It is **not** an OS sandbox and does not intercept syscalls. Anything that bypasses your tool/runtime integration is out of scope for enforcement.

### Guards

Seven composable security guards provide runtime protection:

1. **ForbiddenPathGuard** - Blocks access to sensitive filesystem paths (SSH keys, credentials, etc.)
2. **EgressAllowlistGuard** - Controls network egress via domain allowlist/blocklist
3. **SecretLeakGuard** - Detects potential secrets in file writes and patches
4. **PatchIntegrityGuard** - Validates patch safety (size limits, forbidden patterns)
5. **McpToolGuard** - Restricts MCP tool invocations
6. **PromptInjectionGuard** - Detects and deduplicates prompt-injection attempts in untrusted text
7. **JailbreakGuard** - Detects jailbreak attempts in user input (multi-layer analysis)

### Attestation

Cryptographic verification for agent execution:

- **Ed25519 signatures** for receipt signing
- **SHA-256 and Keccak-256** content hashing
- **Merkle trees** for efficient proof generation
- **Canonical JSON** for deterministic serialization

### Daemon (hushd)

Centralized policy enforcement (experimental):

- HTTP API with key-based authentication
- SQLite-backed audit ledger
- Server-Sent Events (SSE) for real-time monitoring
- Policy hot-reload without restart

`hushd` is currently **experimental/WIP** and should not be relied on as a hardened production enforcement boundary without additional review.

### Security testing (ongoing)

- CI enforces `fmt`/`clippy`/`test`, and validates docs shell code blocks.
- Fuzzing for parser-critical surfaces (DNS/SNI parsing in `hush-proxy`) runs on a schedule via `.github/workflows/fuzz.yml`.

## Known Limitations (v0.1.0)

The following security features have limited or no support in v0.1.0:

| Feature              | Status      | Notes                                          |
| -------------------- | ----------- | ---------------------------------------------- |
| Rate limiting        | Implemented | Per-IP token bucket with trusted proxy support |
| TPM integration      | Planned     | Hardware key storage not supported             |
| Audit log encryption | Planned     | Logs stored in plaintext SQLite                |
| Network isolation    | Partial     | Relies on policy, no kernel enforcement        |

### Rate Limiting Security Note

Rate limiting trusts `X-Forwarded-For` headers only from configured `trusted_proxies`.
If deploying behind a reverse proxy, configure `trusted_proxies` with your proxy IPs.
The `trust_xff_from_any` option is available but **not recommended for production**
as it allows rate limit bypass via header spoofing.

## Security Best Practices

When using Clawdstrike in production:

1. **Use strict rulesets** - Start with `strict` ruleset and allow only required paths/domains
2. **Rotate signing keys** - Generate new keypairs periodically
3. **Monitor audit logs** - Review daemon audit ledger for anomalies
4. **Keep updated** - Apply security patches promptly
5. **Validate receipts** - Always verify signatures before trusting attestations

## Acknowledgments

We gratefully thank security researchers who help improve Clawdstrike's security posture.
