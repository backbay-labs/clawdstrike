# Contributing to Clawdstrike

Thank you for your interest in contributing to Clawdstrike! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Rust 1.92+** (check with `rustc --version`)
- **Cargo** (comes with Rust)
- **Git**

Optional for specific packages:
- **Node.js 20+** for `@clawdstrike/openclaw`
- **Python 3.11+** for `hush-py`
- **wasm-pack** for `@clawdstrike/wasm`

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/hushclaw.git
   cd hushclaw
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/backbay-labs/hushclaw.git
   ```

### Development Setup

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Run clippy (must pass before PR)
cargo clippy --all-targets --all-features

# Format code
cargo fmt
```

### Branch Naming

Create a feature branch from `main`:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

## Making Changes

### Code Style

- Follow Rust idioms and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` before committing
- Address all `cargo clippy` warnings
- Write doc comments for public APIs

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `chore`: Maintenance tasks

Examples:
```
feat(guards): add rate limiting to egress guard
fix(cli): handle missing config file gracefully
docs(readme): add installation instructions for Windows
test(core): add property tests for merkle proofs
```

### Testing

All changes should include appropriate tests:

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p hush-core
cargo test -p clawdstrike

# Run with verbose output
cargo test -- --nocapture

# Run a specific test
cargo test test_forbidden_path_blocks_ssh
```

For property-based tests, we use `proptest`:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn merkle_proof_roundtrip(leaves in prop::collection::vec(any::<[u8; 32]>(), 1..100)) {
        // test implementation
    }
}
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full test suite:**
   ```bash
   cargo test --all-features
   cargo clippy --all-targets --all-features
   cargo fmt --check
   ```

3. **Update documentation** if you changed public APIs

### PR Guidelines

- Keep PRs focused on a single concern
- Fill out the PR template completely
- Link related issues (e.g., "Closes #123")
- Ensure CI passes before requesting review
- Be responsive to review feedback

### Review Process

1. A maintainer will review your PR within a few days
2. Address any requested changes
3. Once approved, a maintainer will merge your PR

## Architecture Overview

```
clawdstrike/
├── crates/
│   ├── hush-core/     # Cryptographic primitives
│   ├── hush-proxy/    # Network proxy utilities
│   ├── clawdstrike/      # Guard implementations and policy engine
│   ├── hush-cli/      # CLI binary
│   ├── hushd/         # Security daemon
│   └── hush-wasm/     # WebAssembly bindings
├── packages/
│   ├── hush-py/       # Python SDK
│   └── clawdstrike-openclaw/  # OpenClaw integration
├── rulesets/          # Pre-configured security policies
├── docs/              # mdBook documentation
└── examples/          # Usage examples
```

### Key Abstractions

- **Guard**: A security check (trait `Guard` in `clawdstrike`)
- **Policy**: Configuration for guards (YAML-based)
- **Receipt**: Cryptographically signed execution attestation
- **HushEngine**: Facade orchestrating guards and signing

## Reporting Issues

### Bug Reports

Include:
- Rust version (`rustc --version`)
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

### Feature Requests

Include:
- Use case description
- Proposed solution (if any)
- Alternatives considered

## Security Issues

**DO NOT** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a [GitHub Discussion](https://github.com/backbay-labs/hushclaw/discussions) for questions
- Join our community chat (coming soon)

Thank you for contributing!
