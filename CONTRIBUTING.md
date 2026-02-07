# Contributing to ClawdStrike

Thank you for your interest in contributing to ClawdStrike! This document provides guidelines for contributing to the project.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing. For security vulnerabilities, see [SECURITY.md](SECURITY.md). For project governance and decision-making, see [GOVERNANCE.md](GOVERNANCE.md).

## Developer Certificate of Origin (DCO)

All contributions require a DCO sign-off. Add `-s` to your commits:

```bash
git commit -s -m "feat(guards): add rate limiting"
```

Every commit must include a `Signed-off-by: Name <email>` trailer, certifying you have the right to submit the work under the project's license ([DCO 1.1](https://developercertificate.org/)).

## Getting Started

### Prerequisites

- **Rust 1.93+** (`rustc --version`)
- **Cargo** (comes with Rust)
- **Git**

Optional for specific packages:
- **Node.js 24+** for TypeScript SDK and adapters
- **Python 3.11+** for `hush-py`
- **wasm-pack** for WebAssembly bindings
- **Helm 3.14+** for Kubernetes chart development
- **Docker** for building container images

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/clawdstrike.git
   cd clawdstrike
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/backbay-labs/clawdstrike.git
   ```

### Development Setup

#### Rust (core crates)

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

#### TypeScript (SDK + adapters)

```bash
npm install --workspace=packages/hush-ts
npm run build --workspace=packages/hush-ts
npm test --workspace=packages/hush-ts
```

#### Python

```bash
pip install -e packages/hush-py[dev]
pytest packages/hush-py/tests
```

#### Desktop (Tauri)

```bash
cd apps/desktop
npm install
npm run tauri dev
```

#### Helm Chart

```bash
helm lint deploy/helm/clawdstrike/
helm template test deploy/helm/clawdstrike/
```

### Branch Naming

```bash
git checkout -b feat/your-feature-name
git checkout -b fix/issue-description
```

## Architecture Overview

```
clawdstrike/
├── crates/
│   ├── hush-core/          # Ed25519, SHA-256, Keccak-256, Merkle trees, RFC 8785
│   ├── clawdstrike/        # Policy engine, 7 built-in guards, receipts, marketplace
│   ├── spine/              # Signed envelopes, checkpoints, NATS transport, proofs API
│   ├── tetragon-bridge/    # Tetragon gRPC -> Spine envelopes
│   ├── hubble-bridge/      # Hubble gRPC -> Spine envelopes
│   ├── hushd/              # HTTP enforcement daemon (experimental)
│   ├── hush-cli/           # CLI binary
│   ├── hush-proxy/         # Network proxy utilities
│   ├── hush-wasm/          # WebAssembly bindings
│   ├── hush-multi-agent/   # Delegation tokens, agent identity
│   └── hush-certification/ # Compliance templates
├── packages/
│   ├── hush-ts/            # TypeScript SDK (@clawdstrike/sdk)
│   ├── hush-py/            # Python SDK
│   ├── clawdstrike-policy/ # Canonical policy engine (TS)
│   └── clawdstrike-*/      # Framework adapters (Claude Code, Vercel AI, etc.)
├── apps/
│   └── desktop/            # Tauri desktop SOC app
├── deploy/
│   ├── helm/               # Production Helm chart
│   ├── tetragon-policies/  # Tetragon TracingPolicy CRDs
│   ├── cilium-policies/    # CiliumNetworkPolicy manifests
│   └── kubernetes/         # Kustomize manifests
├── rulesets/               # Built-in security policies (YAML)
└── docs/                   # mdBook documentation + specs
```

### Key Abstractions

- **Guard** -- Security check implementing the `Guard` (sync) or `AsyncGuard` (async) trait
- **Policy** -- YAML configuration (schema v1.1.0) with `extends` for inheritance
- **Receipt** -- Ed25519-signed attestation of decision, policy, and evidence
- **HushEngine** -- Facade orchestrating guards and signing
- **Spine Envelope** -- Signed fact in the append-only transparency log
- **Checkpoint** -- Merkle root with witness co-signatures

## Contribution On-Ramps

### Level 1: Rulesets (YAML) -- lowest barrier

Create a new security ruleset in `rulesets/community/`:

```yaml
# rulesets/community/my-policy.yaml
schema_version: "1.1.0"
name: "my-org-baseline"
extends: "default"
guards:
  forbidden_paths:
    deny:
      - "/etc/shadow"
```

### Level 2: Documentation

Improve docs in `docs/`, fix typos, add examples.

### Level 3: Framework Adapters (TypeScript/Python)

Add integrations for new AI frameworks in `packages/`.

### Level 4: Compliance Templates

Add industry-specific compliance templates in `crates/hush-certification/`.

### Level 5: Custom Guards (Rust)

Implement the `Guard` trait for new security checks:

```rust
impl Guard for MyGuard {
    fn check(&self, action: &Action, policy: &Policy) -> Result<Decision> {
        // Your detection logic here
    }
}
```

### Level 6: Transport Adapters

Add new transport planes for Spine envelopes.

### Level 7: Bridge Plugins (Rust + eBPF)

Create new bridges for kernel-level event sources.

## Code Style and Conventions

- Follow Rust idioms and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- `cargo fmt` before committing
- All `cargo clippy` warnings are errors (`-D warnings`)
- `#[serde(deny_unknown_fields)]` on all deserialized types
- No `.unwrap()` or `.expect()` in library code -- use `map_err`, `ok_or_else`
- RFC 8785 canonical JSON for all signing operations
- Write doc comments for public APIs

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(guards): add rate limiting to egress guard
fix(spine): handle empty checkpoint witness list
docs(readme): add Helm chart installation instructions
test(core): add property tests for Merkle proofs
```

## Security Review Requirements

Changes to the following areas require review from **two maintainers**:

- `crates/hush-core/` -- cryptographic primitives
- Guard implementations in `crates/clawdstrike/src/guards/`
- Spine protocol in `crates/spine/`
- Authentication and authorization logic in `crates/hushd/`
- Signing and verification paths

See [GOVERNANCE.md](GOVERNANCE.md) for the full decision process.

## Pull Request Process

### Before Submitting

1. Sync with upstream: `git fetch upstream && git rebase upstream/main`
2. Run the full CI locally:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
3. Update documentation for any public API changes
4. Sign off all commits with `-s`

### Review Process

1. Open a PR using the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
2. CI must pass before review
3. A maintainer from the relevant [component area](GOVERNANCE.md) will review
4. Security-sensitive changes require two maintainer approvals
5. Once approved, a maintainer will merge

## Reporting Issues

Use our [issue templates](.github/ISSUE_TEMPLATE/) for:
- **Bug reports** -- with component dropdown and reproduction steps
- **Feature requests** -- with problem statement and proposed solution
- **Guard proposals** -- with threat model and detection logic
- **Ruleset proposals** -- with draft YAML policy

For security issues, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
