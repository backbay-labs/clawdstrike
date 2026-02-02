# DevOps Polish Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Dependabot configuration, fix Homebrew SHA automation, enhance Docker Compose example, and complete SNI extraction with tests.

**Architecture:** Four independent deliverables: (1) Dependabot config for automated dependency updates across Cargo, npm, pip, and GitHub Actions; (2) Release workflow enhancement to auto-update Homebrew SHA256; (3) Docker Compose improvements with simpler standalone example; (4) SNI extraction test data and comprehensive tests.

**Tech Stack:** GitHub Actions, YAML, Docker Compose, Rust, TLS/SNI protocol

---

## Task 1: Add Dependabot Configuration

**Files:**
- Create: `.github/dependabot.yml`

**Step 1: Create Dependabot configuration file**

```yaml
# Dependabot configuration for automated dependency updates
# Docs: https://docs.github.com/en/code-security/dependabot/dependabot-version-updates

version: 2
updates:
  # Rust dependencies (Cargo)
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    groups:
      rust-minor:
        patterns:
          - "*"
        update-types:
          - "minor"
          - "patch"
    ignore:
      # Major version updates require manual review
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
    labels:
      - "dependencies"
      - "rust"

  # npm dependencies (@clawdstrike/openclaw plugin)
  - package-ecosystem: "npm"
    directory: "/packages/clawdstrike-openclaw"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    groups:
      npm-minor:
        patterns:
          - "*"
        update-types:
          - "minor"
          - "patch"
    labels:
      - "dependencies"
      - "javascript"

  # Python dependencies (hush-py SDK)
  - package-ecosystem: "pip"
    directory: "/packages/hush-py"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "python"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "ci"
```

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))"`
Expected: No output (valid YAML)

**Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: add Dependabot configuration for automated updates"
```

---

## Task 2: Fix Homebrew Formula SHA Automation

**Files:**
- Modify: `HomebrewFormula/hush.rb`
- Modify: `.github/workflows/release.yml`

**Step 1: Update Homebrew formula with documentation comment**

Update `HomebrewFormula/hush.rb` to have clear documentation:

```ruby
# Homebrew formula for hush CLI
# Install: brew install clawdstrike/tap/hush
# Or from local: brew install --build-from-source ./HomebrewFormula/hush.rb
#
# SHA256 is automatically updated by the release workflow.
# To calculate SHA256 manually:
#   curl -sL https://github.com/backbay-labs/clawdstrike/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

class Hush < Formula
  desc "CLI for clawdstrike security verification and policy enforcement"
  homepage "https://github.com/backbay-labs/clawdstrike"
  url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "MIT"
  head "https://github.com/backbay-labs/clawdstrike.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/hush-cli")

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")
  end
end
```

**Step 2: Add Homebrew update job to release workflow**

Append new job to `.github/workflows/release.yml` after the `create-release` job:

```yaml

  # Update Homebrew formula with correct SHA256
  update-homebrew:
    name: Update Homebrew Formula
    runs-on: ubuntu-latest
    needs: [create-release]
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main  # Checkout main branch for the update

      - name: Calculate SHA256
        id: sha
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          URL="https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v${VERSION}.tar.gz"
          echo "Downloading from: $URL"
          SHA=$(curl -sL "$URL" | shasum -a 256 | cut -d' ' -f1)
          echo "sha256=$SHA" >> $GITHUB_OUTPUT
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "Calculated SHA256: $SHA"

      - name: Update formula
        run: |
          # Update URL with new version
          sed -i 's|url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v[^"]*"|url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v${{ steps.sha.outputs.version }}.tar.gz"|' HomebrewFormula/hush.rb
          # Update SHA256
          sed -i 's|sha256 "[^"]*"|sha256 "${{ steps.sha.outputs.sha256 }}"|' HomebrewFormula/hush.rb

          echo "Updated formula:"
          cat HomebrewFormula/hush.rb

      - name: Commit and push
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add HomebrewFormula/hush.rb
          git diff --cached --quiet || git commit -m "chore: update Homebrew formula for v${{ steps.sha.outputs.version }}"
          git push origin main
```

**Step 3: Validate release workflow YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: No output (valid YAML)

**Step 4: Commit**

```bash
git add HomebrewFormula/hush.rb .github/workflows/release.yml
git commit -m "ci: add Homebrew SHA256 auto-update to release workflow"
```

---

## Task 3: Create Simpler Docker Compose Example

**Files:**
- Create: `examples/docker-compose/docker-compose.yml`
- Create: `examples/docker-compose/config.yaml`
- Create: `examples/docker-compose/policy.yaml`
- Create: `examples/docker-compose/README.md`

The existing `examples/docker/` is more complex. Create a simpler standalone example.

**Step 1: Create docker-compose directory**

```bash
mkdir -p examples/docker-compose
```

**Step 2: Create simple docker-compose.yml**

```yaml
# Simple hushd Docker Compose example
# Usage: docker compose up -d

services:
  hushd:
    build:
      context: ../..
      dockerfile: Dockerfile.hushd
    ports:
      - "8080:8080"
    volumes:
      - ./policy.yaml:/etc/hushd/policy.yaml:ro
      - ./config.yaml:/etc/hushd/config.yaml:ro
      - hushd-data:/var/lib/hushd
    environment:
      - HUSH_LOG_LEVEL=info
      - HUSH_API_KEY=${HUSH_API_KEY:-changeme}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

volumes:
  hushd-data:
```

**Step 3: Create config.yaml**

```yaml
# Hushd daemon configuration
listen: "0.0.0.0:8080"
policy_path: "/etc/hushd/policy.yaml"
audit_db: "/var/lib/hushd/audit.db"
log_level: "info"

auth:
  enabled: true
  api_keys:
    - name: "default"
      # Set via HUSH_API_KEY environment variable
      key_env: "HUSH_API_KEY"
      scopes: ["check", "read"]
```

**Step 4: Create policy.yaml**

```yaml
# Example security policy for hushd
version: "1.0"
name: "docker-example"

guards:
  # Block access to sensitive files
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
      - "/etc/passwd"
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"

  # Only allow egress to specific domains
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.github.com"
      - "api.anthropic.com"
      - "api.openai.com"
      - "registry.npmjs.org"
      - "pypi.org"

  # Detect secrets in output
  secret_leak:
    enabled: true

settings:
  fail_fast: true
  audit_all: true
```

**Step 5: Create README.md**

```markdown
# Docker Compose Example

Run hushd locally with Docker Compose for development and testing.

## Quick Start

```bash
# Generate a secure API key
export HUSH_API_KEY=$(openssl rand -hex 32)

# Start hushd
docker compose up -d

# Check health
curl http://localhost:8080/health

# View logs
docker compose logs -f hushd
```

## Test Policy Check

```bash
# Check file access (should pass)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer $HUSH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "file_access", "path": "/tmp/test.txt"}'

# Check forbidden path (should fail)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer $HUSH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "file_access", "path": "/etc/shadow"}'
```

## Configuration

| File | Purpose |
|------|---------|
| `config.yaml` | Daemon configuration (ports, auth) |
| `policy.yaml` | Security policy (guards, allowlists) |

## Volumes

- `hushd-data` - Persists audit database between restarts

## Stop

```bash
docker compose down
```

## Clean Up

```bash
docker compose down -v  # Also removes volumes
```
```

**Step 6: Validate YAML files**

Run: `python3 -c "import yaml; yaml.safe_load(open('examples/docker-compose/docker-compose.yml')); yaml.safe_load(open('examples/docker-compose/config.yaml')); yaml.safe_load(open('examples/docker-compose/policy.yaml')); print('All YAML valid')"`
Expected: "All YAML valid"

**Step 7: Commit**

```bash
git add examples/docker-compose/
git commit -m "docs: add simple Docker Compose example for hushd"
```

---

## Task 4: Complete SNI Extraction with Test Data

**Files:**
- Create: `crates/hush-proxy/testdata/client_hello_example.bin`
- Create: `crates/hush-proxy/testdata/client_hello_no_sni.bin`
- Modify: `crates/hush-proxy/src/sni.rs`

The existing SNI implementation is mostly complete but needs test data files.

**Step 1: Create testdata directory**

```bash
mkdir -p crates/hush-proxy/testdata
```

**Step 2: Create test data generator script**

Create `crates/hush-proxy/testdata/generate_test_data.py`:

```python
#!/usr/bin/env python3
"""Generate TLS ClientHello test data for SNI extraction tests."""

import struct

def build_client_hello(hostname: str | None = None) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with optional SNI extension."""

    # Build extensions
    extensions = b''

    if hostname:
        # SNI extension (type 0x0000)
        hostname_bytes = hostname.encode('ascii')
        # SNI list: name_type (1) + name_length (2) + name
        sni_list = struct.pack('!BH', 0, len(hostname_bytes)) + hostname_bytes
        # SNI extension data: list_length (2) + list
        sni_data = struct.pack('!H', len(sni_list)) + sni_list
        # Extension: type (2) + length (2) + data
        extensions += struct.pack('!HH', 0, len(sni_data)) + sni_data

    # Add a dummy extension to make it more realistic (supported_versions)
    supported_versions = struct.pack('!HH', 0x002b, 3) + b'\x02\x03\x03'
    extensions += supported_versions

    # Build ClientHello body
    hello_body = b''
    hello_body += struct.pack('!H', 0x0303)  # Version: TLS 1.2
    hello_body += b'\x00' * 32               # Random (32 bytes)
    hello_body += b'\x00'                    # Session ID length (0)
    hello_body += struct.pack('!H', 2)       # Cipher suites length
    hello_body += struct.pack('!H', 0x1301)  # TLS_AES_128_GCM_SHA256
    hello_body += b'\x01\x00'                # Compression methods: null
    hello_body += struct.pack('!H', len(extensions))  # Extensions length
    hello_body += extensions

    # Build Handshake message
    handshake = b''
    handshake += b'\x01'                               # Type: ClientHello
    handshake += struct.pack('!I', len(hello_body))[1:]  # Length (3 bytes)
    handshake += hello_body

    # Build TLS record
    record = b''
    record += b'\x16'                           # Content type: Handshake
    record += struct.pack('!H', 0x0301)         # Version: TLS 1.0 (in record layer)
    record += struct.pack('!H', len(handshake)) # Record length
    record += handshake

    return record


def main():
    # Generate ClientHello with SNI
    with_sni = build_client_hello("example.com")
    with open("client_hello_example.bin", "wb") as f:
        f.write(with_sni)
    print(f"Generated client_hello_example.bin ({len(with_sni)} bytes)")

    # Generate ClientHello without SNI
    without_sni = build_client_hello(None)
    with open("client_hello_no_sni.bin", "wb") as f:
        f.write(without_sni)
    print(f"Generated client_hello_no_sni.bin ({len(without_sni)} bytes)")


if __name__ == "__main__":
    main()
```

**Step 3: Generate test data files**

Run:
```bash
cd crates/hush-proxy/testdata
python3 generate_test_data.py
```

Expected:
```
Generated client_hello_example.bin (XX bytes)
Generated client_hello_no_sni.bin (XX bytes)
```

**Step 4: Update SNI tests to use test data files**

Add comprehensive tests to `crates/hush-proxy/src/sni.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_short_packet() {
        assert_eq!(extract_sni(&[0; 5]).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_non_tls() {
        let data = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00]; // Not handshake type
        assert_eq!(extract_sni(&data).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_with_hostname() {
        // Real TLS ClientHello with SNI = "example.com"
        let client_hello = include_bytes!("../testdata/client_hello_example.bin");
        let result = extract_sni(client_hello).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_no_sni_extension() {
        // ClientHello without SNI extension
        let client_hello = include_bytes!("../testdata/client_hello_no_sni.bin");
        let result = extract_sni(client_hello).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_sni_http_request() {
        // HTTP request (not TLS)
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_sni(http).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_invalid_version() {
        // Invalid TLS version
        let data = [0x16, 0x02, 0x00, 0x00, 0x01, 0x00]; // SSL 2.0
        assert_eq!(extract_sni(&data).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_empty() {
        assert_eq!(extract_sni(&[]).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_truncated_record() {
        // Handshake header says 100 bytes but data is shorter
        let data = [0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x00, 0x00, 0x05];
        let result = extract_sni(&data);
        assert!(result.is_err()); // Should error on incomplete record
    }
}
```

**Step 5: Run the tests**

Run: `cd /Users/connor/Medica/clawdstrike-ws16-devops-polish && cargo test -p hush-proxy -- --test-threads=1`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/hush-proxy/testdata/ crates/hush-proxy/src/sni.rs
git commit -m "test: add SNI extraction test data and comprehensive tests"
```

---

## Task 5: Final Verification

**Step 1: Run all Rust tests**

Run: `cargo test --workspace`
Expected: All tests pass

**Step 2: Validate all YAML files**

Run:
```bash
python3 -c "
import yaml
import glob

files = [
    '.github/dependabot.yml',
    '.github/workflows/release.yml',
    '.github/workflows/ci.yml',
    'examples/docker-compose/docker-compose.yml',
    'examples/docker-compose/config.yaml',
    'examples/docker-compose/policy.yaml',
]

for f in files:
    try:
        yaml.safe_load(open(f))
        print(f'OK: {f}')
    except Exception as e:
        print(f'FAIL: {f} - {e}')
"
```
Expected: All files report "OK"

**Step 3: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

**Step 4: Final commit if needed**

```bash
git status
# If clean: done
# If changes: git add -A && git commit -m "chore: final polish"
```

---

## Summary Checklist

- [ ] `.github/dependabot.yml` created with Cargo, npm, pip, GitHub Actions
- [ ] `HomebrewFormula/hush.rb` updated with documentation
- [ ] `.github/workflows/release.yml` has Homebrew SHA update job
- [ ] `examples/docker-compose/` created with simple standalone example
- [ ] `crates/hush-proxy/testdata/` has ClientHello test binaries
- [ ] SNI extraction tests pass with real test data
- [ ] All workspace tests pass
- [ ] All YAML files validate
