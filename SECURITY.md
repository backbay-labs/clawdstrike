# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. **DO NOT** open a public GitHub issue for vulnerabilities.

### GitHub Private Reporting (Preferred)

1. Go to <https://github.com/backbay-labs/clawdstrike/security/advisories/new>
2. Fill out the vulnerability report form
3. We will respond within 48 hours

### Email

Email [security@clawdstrike.io](mailto:security@clawdstrike.io) with:
- Description of the vulnerability
- Steps to reproduce
- Affected versions and components
- Potential impact assessment
- Any suggested fixes (optional)

### Response Timeline

- **48 hours**: Initial acknowledgment
- **7 days**: Assessment and severity determination
- **30 days**: Target for fix release (may vary based on complexity)

We will keep you informed throughout the process and credit you in the release notes (unless you prefer to remain anonymous).

## CVE Publication

For confirmed vulnerabilities:

1. We request a CVE ID via GitHub Security Advisory
2. We develop and test a fix on a private branch
3. We publish the fix, CVE, and advisory simultaneously
4. Critical patches are released within 48 hours of confirmation

## Security Scope

| Component | Directory | Critical Assets |
|-----------|-----------|-----------------|
| Crypto primitives | `crates/hush-core/` | Key material, Ed25519 signatures, SHA-256/Keccak, Merkle proofs |
| Guard engine | `crates/clawdstrike/` | Policy evaluation, fail-closed invariant, guard bypass resistance |
| Spine protocol | `crates/spine/` | Envelope signing, append-only log integrity, checkpoint verification |
| Bridges | `crates/tetragon-bridge/`, `crates/hubble-bridge/` | Signing key management, event deduplication, NATS transport |
| Marketplace | `crates/clawdstrike/src/marketplace_feed.rs` | Curator key trust, feed signing, bundle verification, IPFS integrity |
| hushd daemon | `crates/hushd/` | API authentication, audit log integrity, SSE broadcast |
| Desktop app | `apps/desktop/` | Tauri IPC, localStorage trust config, P2P discovery |
| Multi-agent | `crates/hush-multi-agent/` | Delegation tokens, agent identity, revocation |

## Security Design Principles

- **Fail-closed**: Invalid policies reject at load time; errors during evaluation deny access
- **No panics in production**: `unwrap_used = "deny"`, `expect_used = "deny"` via Clippy
- **Strict deserialization**: `#[serde(deny_unknown_fields)]` on all serde types
- **Canonical JSON**: RFC 8785 (JCS) for cross-language deterministic signing
- **Domain separation**: All signatures use domain-separated hashing

## Security Model

### Enforcement Boundary

ClawdStrike enforces policy at the **agent/tool boundary**. It is **not** an OS sandbox and does not intercept syscalls. The SDR stack adds kernel-level enforcement via Tetragon eBPF policies (see `deploy/tetragon-policies/`).

### Built-in Guards

Seven composable security guards provide runtime protection:

1. **ForbiddenPathGuard** -- Blocks access to sensitive filesystem paths
2. **EgressAllowlistGuard** -- Controls network egress via domain allowlist/blocklist
3. **SecretLeakGuard** -- Detects potential secrets in file writes and patches
4. **PatchIntegrityGuard** -- Validates patch safety (size limits, forbidden patterns)
5. **McpToolGuard** -- Restricts MCP tool invocations
6. **PromptInjectionGuard** -- Detects prompt injection in untrusted text
7. **JailbreakGuard** -- Multi-layer jailbreak detection (heuristic + statistical + ML + LLM-judge)

### Attestation

- **Ed25519 signatures** for receipt and envelope signing
- **SHA-256 and Keccak-256** content hashing
- **Merkle trees** for efficient inclusion proofs (RFC 6962)
- **Canonical JSON** (RFC 8785) for deterministic serialization
- **Witness co-signatures** for checkpoint integrity

### Spine Transparency Log

The Spine protocol provides an append-only transparency log with:
- Signed envelopes with monotonic sequence numbers and hash chaining
- Periodic checkpoints with Merkle root and witness co-signatures
- Inclusion proofs verifiable by any client
- NATS JetStream transport with KV bucket persistence

### Rate Limiting

Rate limiting trusts `X-Forwarded-For` headers only from configured `trusted_proxies`.
The `trust_xff_from_any` option is available but **not recommended for production**.

## Security Audits

| Scope | Status | Firm | Date |
|-------|--------|------|------|
| hush-core cryptography | Planned | TBD | Pre-1.0 |
| Spine protocol | Planned | TBD | Pre-1.0 |
| Guard bypass resistance | Planned | TBD | Pre-1.0 |
| Tetragon bridge | Planned | TBD | Pre-1.0 |

## Security Testing

- CI enforces `fmt`/`clippy`/`test` and validates docs shell code blocks
- Fuzzing for parser surfaces (DNS/SNI parsing) runs via `.github/workflows/fuzz.yml`
- Property-based testing with `proptest` for cryptographic and serialization code

## Security Best Practices

When deploying ClawdStrike in production:

1. **Use strict rulesets** -- Start with `strict` and allow only required paths/domains
2. **Rotate signing keys** -- Generate new keypairs periodically
3. **Monitor audit logs** -- Review daemon audit ledger for anomalies
4. **Keep updated** -- Apply security patches promptly
5. **Validate receipts** -- Always verify Ed25519 signatures before trusting attestations
6. **Deploy Tetragon policies** -- Use kernel-level enforcement as defense-in-depth
7. **Enable Cilium network policies** -- Microsegment SDR services

## Known Limitations (v0.1.0)

| Feature              | Status      | Notes                                          |
| -------------------- | ----------- | ---------------------------------------------- |
| Rate limiting        | Implemented | Per-IP token bucket with trusted proxy support |
| TPM integration      | Implemented | Best-effort via TPM2-sealed Ed25519 seed       |
| Audit log encryption | Implemented | Optional at-rest encryption for audit metadata |
| Network isolation    | Partial     | Policy-based + Cilium NetworkPolicy (no kernel enforcement without Tetragon) |
| Key revocation       | In-memory   | No persistent revocation store yet             |

## Acknowledgments

We gratefully thank security researchers who help improve ClawdStrike's security posture.

## Related Documents

- [CONTRIBUTING.md](CONTRIBUTING.md) -- For non-security contributions
- [GOVERNANCE.md](GOVERNANCE.md) -- Decision process and maintainer roles
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) -- Community standards
