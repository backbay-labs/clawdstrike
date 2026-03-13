# Contributing to ClawdStrike

Thank you for your interest in contributing to ClawdStrike! This document provides guidelines for contributing to the project.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing. For security vulnerabilities, see [SECURITY.md](SECURITY.md). For project governance and decision-making, see [GOVERNANCE.md](GOVERNANCE.md).
If you’d like to discuss ideas, ask questions`, or coordinate work, you are very welcome to join our Discord server: [clawdstrike Discord](https://discord.gg/tWKSGCvq).


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
npm install --workspace=packages/sdk/hush-ts
npm run build --workspace=packages/sdk/hush-ts
npm test --workspace=packages/sdk/hush-ts
```

Package manager standards are documented in `docs/src/getting-started/package-manager-policy.md`.

#### Python

```bash
pip install -e packages/sdk/hush-py[dev]
pytest packages/sdk/hush-py/tests
```

#### Desktop (Tauri)

```bash
cd apps/desktop
npm install
npm run tauri dev
```

#### Helm Chart

```bash
helm lint infra/deploy/helm/clawdstrike/
helm template test infra/deploy/helm/clawdstrike/
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
│   ├── libs/               # Reusable Rust libraries
│   ├── services/           # Deployable Rust services/CLIs
│   ├── bridges/            # Event-source bridge binaries
│   └── tests/              # Cross-crate integration test crates
├── packages/
│   ├── sdk/                # TypeScript + Python SDKs
│   ├── policy/             # Canonical TypeScript policy engine
│   └── adapters/           # Framework adapters (Claude, Vercel AI, OpenAI, etc.)
├── apps/
│   ├── desktop/            # Tauri desktop SOC app
│   ├── agent/              # Tauri agent app
│   └── control-console/    # Web dashboard app
├── infra/
│   ├── deploy/             # Helm/Kustomize/systemd/launchd assets
│   ├── docker/             # Dockerfiles and compose
│   ├── packaging/          # Homebrew formula
│   └── vendor/             # Vendored Rust crates for offline builds
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

## Architecture Guardrails

Use these guardrails for monorepo changes:

1. Keep directory moves and behavior changes in separate PRs.
2. Keep each top-level domain (`apps/`, `crates/`, `packages/`, and peers) self-describing with a `README.md`.
3. When moving paths, update docs and workflow references in the same PR.
4. Run guardrail scripts before requesting review:
   - `bash scripts/path-lint.sh`
   - `bash scripts/move-validation.sh`
   - `bash scripts/architecture-guardrails.sh`
5. For path-aware local verification, use `mise run ci:changed`.

## Contribution On-Ramps

### Level 1: Rulesets (YAML) -- lowest barrier

Create a new security ruleset in `rulesets/`:

```yaml
# rulesets/my-policy.yaml
version: "1.2.0"
name: "my-org-baseline"
extends: "default"
guards:
  forbidden_path:
    patterns:
      - "/etc/shadow"
```

### Level 2: Documentation

Improve docs in `docs/`, fix typos, add examples.

### Level 3: Framework Adapters (TypeScript/Python)

Add integrations for new AI frameworks in `packages/`.

### Level 4: Compliance Templates

Add industry-specific compliance templates in `crates/libs/hush-certification/`.

### Level 5: Custom Guards (Rust)

Implement the `Guard` trait for new security checks:

```rust
#[async_trait]
impl Guard for MyGuard {
    fn name(&self) -> &str { "my_guard" }
    fn handles(&self, action: &GuardAction<'_>) -> bool { true }
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
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

- `crates/libs/hush-core/` -- cryptographic primitives
- Guard implementations in `crates/libs/clawdstrike/src/guards/`
- Spine protocol in `crates/libs/spine/`
- Authentication and authorization logic in `crates/services/hushd/`
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
   mise run guardrails
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
