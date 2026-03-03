# RFC 0001: Clawdstrike Package Manager

| Field      | Value                                    |
|------------|------------------------------------------|
| RFC        | 0001                                     |
| Title      | Clawdstrike Package Manager              |
| Status     | Draft                                    |
| Authors    | Clawdstrike Contributors                 |
| Date       | 2026-02-27                               |
| Requires   | Policy Schema v1.2.0, Spine Envelope v1  |

## Summary

This RFC proposes a package manager for the Clawdstrike ecosystem that enables distributing, discovering, and installing reusable security components: guards, policy packs, framework adapters, engine backends, project templates, and pre-compiled bundles. The system leverages Clawdstrike's existing cryptographic infrastructure (Ed25519 signing, Merkle trees, signed receipts) to provide end-to-end supply chain integrity from publisher to consumer.

## Motivation

Today, extending Clawdstrike requires manual integration. Custom guards must be compiled into the host binary via `CustomGuardFactory` and registered in a `CustomGuardRegistry`. Policy inheritance works via `extends` references to local files, built-in rulesets, or remote URLs with SHA-256 pins. Framework adapters (OpenClaw, Vercel AI, LangChain) are separate npm packages with no unified discovery.

This creates several problems:

1. **No reuse mechanism.** Organizations writing custom guards cannot share them without forking or vendoring source code. The `CustomGuardFactory` trait requires compile-time integration.

2. **No discovery.** There is no central or federated place to find community-contributed guards, policies, or adapters.

3. **No trust chain.** Remote policy `extends` requires manual SHA-256 pin management. There is no publisher identity, no transparency log, and no way to audit the provenance of third-party components.

4. **No sandboxing for third-party code.** The existing `PluginManifest` (in `crates/libs/clawdstrike/src/plugins/manifest.rs`) defines capability-based permissions and WASM sandboxing, but there is no runtime to execute WASM guards.

5. **Fragmented tooling.** Guards are Rust crates, adapters are npm/pip packages, and policies are raw YAML files. Each follows a different distribution path.

A package manager unifies these concerns under a single CLI surface (`clawdstrike pkg`), a shared manifest format (`clawdstrike-pkg.toml`), and a registry with cryptographic attestation.

## Package Types

The package manager supports six distinct package types, each with different artifact formats and installation semantics.

### Guard (WASM)

Compiled WebAssembly modules implementing the `Guard` trait. Guards are sandboxed via wasmtime with capability-based permissions declared in the manifest.

```text
clawdstrike-pkg.toml (type = "guard")
          |
          v
    +-----------+
    | .wasm     |  Compiled module (wasm32-wasip2)
    | config.rs |  Optional default configuration
    +-----------+
```

The WASM guest ABI exports three functions corresponding to the `Guard` trait:

```rust,ignore
// Guest ABI exports (wit-bindgen)
fn name() -> String;
fn handles(action: &GuardAction) -> bool;
fn check(action: &GuardAction, context: &GuardContext) -> GuardResult;
```

These map directly to the existing trait defined in `crates/libs/clawdstrike/src/guards/mod.rs`:

```rust,ignore
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction<'_>) -> bool;
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}
```

### Policy Pack (YAML)

Bundles of YAML rulesets with optional data files (threat intel lists, regex pattern sets). Policy packs are loaded by the `PolicyResolver` and can be referenced in `extends` chains.

```yaml
# Example: a HIPAA compliance policy pack
schema_version: "1.2.0"
extends:
  - "pkg:acme/hipaa-base@1.0.0"
guards:
  forbidden_path:
    enabled: true
    paths:
      - "/etc/shadow"
      - "${PHI_DATA_DIR}/**"
```

### Adapter (TypeScript / Python)

Framework bridges distributed as npm or pip packages. The registry serves as a discovery layer; actual artifacts are language-native packages published to npm/PyPI with registry metadata cross-referencing the canonical package name.

### Engine

Backend implementations (alternative to the built-in CLI engine or hushd). Engines are Rust crates or WASM modules that implement the `HushEngine` interface.

### Template

Scaffolding packages for new projects, policies, or guard implementations. Installed via `clawdstrike pkg init --template <name>`.

### Bundle

Signed, pre-compiled sets combining a policy with its guard dependencies. Bundles extend the existing `SignedPolicyBundle` concept (see `crates/libs/clawdstrike/src/policy_bundle.rs`) with embedded WASM artifacts and a lockfile snapshot.

## Package Format

### Manifest: `clawdstrike-pkg.toml`

The manifest is TOML, consistent with Cargo and the existing `PluginManifest` struct. A single manifest covers all package types.

```toml
[package]
name = "acme-phi-guard"
version = "1.2.0"
type = "guard"                    # guard | policy-pack | adapter | engine | template | bundle
description = "PHI detection guard for HIPAA environments"
license = "Apache-2.0"
authors = ["ACME Security <security@acme.corp>"]
repository = "https://github.com/acme/phi-guard"
keywords = ["hipaa", "phi", "healthcare"]
readme = "README.md"

[clawdstrike]
min_version = "0.12.0"            # Minimum compatible clawdstrike version
policy_schema = "1.2.0"           # Required policy schema version

[guards.phi_detector]
name = "acme.phi_detector"
display_name = "PHI Detector"
entrypoint = "phi_detector.wasm"  # Relative path within archive
handles = ["file_write", "custom"]

[capabilities]
network = false
subprocess = false
filesystem.read = ["/etc/acme/*.conf"]
filesystem.write = false
secrets.access = false

[resources]
max_memory_mb = 64
max_cpu_ms = 100
max_timeout_ms = 5000

[trust]
level = "untrusted"               # untrusted | trusted
sandbox = "wasm"                  # wasm | native

[dependencies]
"acme-common" = "^1.0.0"
"clawdstrike-threat-intel" = "~2.1.0"

[build]
target = "wasm32-wasip2"
profile = "release"
```

This structure directly extends the existing `PluginManifest` type:

```rust,ignore
// Existing: crates/libs/clawdstrike/src/plugins/manifest.rs
pub struct PluginManifest {
    pub plugin: PluginMetadata,                         // -> [package]
    pub clawdstrike: Option<PluginClawdstrikeCompatibility>, // -> [clawdstrike]
    pub guards: Vec<PluginGuardManifestEntry>,           // -> [guards.*]
    pub capabilities: PluginCapabilities, // -> [capabilities]
    pub resources: PluginResourceLimits,  // -> [resources]
    pub trust: PluginTrust,              // -> [trust]
}
```

The `[package]` section supersedes the existing `[plugin]` section with additional fields for registry metadata. The `[dependencies]` section is new.

### Archive: `.cpkg`

A `.cpkg` file is a zstd-compressed tarball with a fixed layout:

```text
acme-phi-guard-1.2.0.cpkg
  |-- clawdstrike-pkg.toml          # Package manifest
  |-- artifacts/
  |   |-- phi_detector.wasm          # Compiled guard module
  |   `-- default_config.yaml        # Optional default configuration
  |-- README.md                      # Package documentation (optional)
  `-- LICENSE                        # License file (optional)
```

### Publication Attestation (Target Hosted Model)

Target hosted model: packages may optionally include a publication receipt artifact.

**Implementation status (2026-02-28):** current registry flow uses detached publish metadata:
- publisher signs archive hash (`publisher_sig`)
- registry counter-signs archive hash (`registry_sig`)
- registry stores attestation + transparency metadata server-side

```json
{
  "schema_version": "1.0.0",
  "receipt_id": "pkg-pub-acme-phi-guard-1.2.0-20260227",
  "timestamp": "2026-02-27T12:00:00Z",
  "action": "package.publish",
  "package": {
    "name": "acme-phi-guard",
    "version": "1.2.0",
    "type": "guard",
    "archive_sha256": "0xabcdef1234567890..."
  },
  "publisher": {
    "identity": "oidc:github:acme-security",
    "public_key": "0x..."
  },
  "signature": "0x..."
}
```

## CLI Commands

All package management commands live under `clawdstrike pkg`, following the existing CLI structure in `crates/services/hush-cli/src/main.rs`.

### Command Reference

| Command | Description |
|---------|-------------|
| `clawdstrike pkg init` | Initialize a new package in the current directory |
| `clawdstrike pkg install <source>` | Install from a `.cpkg` file or registry package name |
| `clawdstrike pkg list` | List installed packages |
| `clawdstrike pkg search <query>` | Search the registry |
| `clawdstrike pkg info <name> --version <version>` | Show installed package details |
| `clawdstrike pkg publish` | Publish the current package to the registry |
| `clawdstrike pkg verify <name> --version <version>` | Verify package signatures and transparency proof |
| `clawdstrike pkg audit` | Audit installed packages for advisories |
| `clawdstrike pkg login` | Prepare publisher key + registry config (token setup is manual) |
| `clawdstrike pkg pack` | Build a `.cpkg` archive without publishing |

### Example Workflows

**Installing a guard:**

```bash
$ clawdstrike pkg install acme-phi-guard@1.2.0
Resolving dependencies...
  acme-phi-guard 1.2.0
  acme-common 1.4.2
Downloading 2 packages...
Verifying signatures...
  acme-phi-guard: signed (verified publisher: oidc:github:acme-security)
  acme-common: signed (verified publisher: oidc:github:acme-security)
Installed 2 packages in 1.2s
```

**Publishing a package:**

```bash
$ clawdstrike pkg login
Publisher keypair ready.
Publisher key: 3f21...9ab1
Registry: https://registry.clawdstrike.com
To complete login, set CLAWDSTRIKE_AUTH_TOKEN or credentials.toml

$ clawdstrike pkg publish
Building acme-phi-guard 1.2.0...
  Compiling phi_detector.wasm (wasm32-wasip2, release)
  Packing acme-phi-guard-1.2.0.cpkg (148 KB)
  Signing with publisher key...
  Receipt: 0xabc123...
Publishing to registry.clawdstrike.dev...
  Registry counter-signature: 0xdef456...
  Transparency log entry: #4821
Published acme-phi-guard@1.2.0
```

**Verifying a package:**

```bash
$ clawdstrike pkg verify acme-phi-guard --version 1.2.0
Package: acme-phi-guard 1.2.0
Publisher: oidc:github:acme-security
Publisher signature: VALID (Ed25519)
Registry counter-signature: VALID (Spine envelope)
Transparency log: INCLUDED (entry #4821, Merkle proof verified)
Trust level: verified
Archive integrity: SHA-256 match
```

## Registry Architecture

The registry uses a three-tier architecture optimized for different access patterns.

```text
                  +-----------------------+
                  |    CDN / Edge Cache   |
                  |  (sparse index, .cpkg)|
                  +----------+------------+
                             |
              +--------------+--------------+
              |                             |
    +---------v----------+     +------------v-----------+
    |   Sparse Index     |     |    REST API            |
    |  (read-heavy)      |     |  (writes, search)      |
    +--------------------+     +------------------------+
              |                       |            |
    +---------v----------+   +--------v---+  +-----v--------+
    | OCI Registry       |   | PostgreSQL |  | Spine        |
    | (artifact storage) |   | (metadata) |  | (audit log)  |
    +--------------------+   +------------+  +--------------+
```

### Sparse Index (Read Path)

The sparse index follows the Cargo registry index protocol. Each package has a file in the index keyed by name, containing one JSON line per published version.

```text
index/
  ac/me/acme-phi-guard
  cl/aw/clawdstrike-threat-intel
  config.json
```

Each index entry:

```json
{
  "name": "acme-phi-guard",
  "vers": "1.2.0",
  "type": "guard",
  "deps": [
    { "name": "acme-common", "req": "^1.0.0" }
  ],
  "cksum": "sha256:abcdef1234567890...",
  "receipt_hash": "sha256:fedcba0987654321...",
  "yanked": false,
  "clawdstrike_min": "0.12.0",
  "policy_schema": "1.2.0",
  "features": {}
}
```

Index files are served with `ETag` headers for HTTP conditional requests, enabling efficient incremental updates without downloading the full index.

### OCI Registry Backend (Artifact Storage)

Package artifacts (`.cpkg` files) are stored in an OCI-compliant registry using custom media types:

| Package Type | Media Type |
|-------------|------------|
| Guard | `application/vnd.clawdstrike.guard.v1+wasm` |
| Policy Pack | `application/vnd.clawdstrike.policy-pack.v1+tar+gzip` |
| Adapter | `application/vnd.clawdstrike.adapter.v1+tar+gzip` |
| Engine | `application/vnd.clawdstrike.engine.v1+tar+gzip` |
| Template | `application/vnd.clawdstrike.template.v1+tar+gzip` |
| Bundle | `application/vnd.clawdstrike.bundle.v1+tar+gzip` |

OCI distribution provides content-addressable storage, deduplication, and compatibility with existing container infrastructure (Harbor, ECR, GCR, ACR).

### REST API (Write Path)

The REST API handles mutations and rich queries that the sparse index cannot serve.

**Implementation status (2026-02-28):** this branch implements direct publish via
`POST /api/v1/packages` and does OIDC validation inline in publish requests.
`/api/v1/auth/oidc` below is retained as a future hosted-token-exchange design target.

```text
POST   /api/v1/packages                 # Publish
DELETE /api/v1/packages/{name}/{version} # Yank
GET    /api/v1/packages/{name}           # Package metadata
GET    /api/v1/search?q={query}          # Full-text search
POST   /api/v1/auth/oidc                 # OIDC token exchange
GET    /api/v1/advisories                # Security advisories
```

### Metadata Storage (PostgreSQL)

PostgreSQL stores package metadata, publisher identities, download counts, advisory data, and organization ownership in the **target hosted architecture**.  
**Implementation status (2026-02-28):** current branch uses SQLite + filesystem blob storage.

Target schema highlights:

```sql
CREATE TABLE packages (
    name         TEXT PRIMARY KEY,
    owner_id     UUID REFERENCES publishers(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE versions (
    package_name TEXT REFERENCES packages(name),
    version      TEXT NOT NULL,
    type         TEXT NOT NULL,
    cksum        TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    yanked       BOOLEAN NOT NULL DEFAULT false,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (package_name, version)
);

CREATE TABLE publishers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity     TEXT UNIQUE NOT NULL,  -- oidc:github:acme-security
    public_key   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Audit Trail (Spine)

All registry mutations (publish, yank, ownership transfer) are recorded as Spine signed envelopes on a NATS-backed audit log. The envelope format follows `crates/libs/spine/src/envelope.rs`:

```json
{
  "schema": "aegis.spine.envelope.v1",
  "seq": 4821,
  "issued_at": "2026-02-27T12:00:00Z",
  "issuer": "aegis:ed25519:<registry-pubkey>",
  "capability_token": null,
  "fact": {
    "type": "clawdstrike.registry.publish",
    "package": "acme-phi-guard",
    "version": "1.2.0",
    "publisher": "oidc:github:acme-security",
    "archive_sha256": "0xabcdef...",
    "receipt_hash": "0xfedcba..."
  },
  "prev_envelope_hash": "0x...",
  "envelope_hash": "0x...",
  "signature": "0x..."
}
```

## Trust and Verification

Trust is established through three independent layers that can be verified independently.

### Layer 1: Publisher Ed25519 Signature

Current implementation verifies publisher signatures over the archive SHA-256 digest (`publisher_sig` over hash bytes). This is detached metadata, not a required embedded `RECEIPT.json` file.

### Layer 2: Registry Counter-Signature

When the registry accepts a publication, it counter-signs the archive hash (`registry_sig`) and records signed attestation metadata. This attests that the registry validated the package at acceptance time: manifest schema, capability constraints, and publisher identity.

### Layer 3: Transparency Log

All publications are appended to an RFC 6962-compatible Merkle tree using `crates/libs/clawdstrike/src/pkg/merkle.rs`:

```text
leaf_data = { package_name, version, content_hash, publisher_key, timestamp }
LeafHash(canonical_json(leaf_data)) = SHA256(0x00 || canonical_json(leaf_data))
NodeHash(left, right)               = SHA256(0x01 || left || right)
```

Clients request inclusion proofs and verify them locally.  
**Implementation status (2026-02-28):** `certified` verification checks checkpoint signature and Merkle inclusion proof cryptographically.

### Trust Levels

Packages are assigned a trust level based on the verification layers present:

| Level | Criteria | Display |
|-------|----------|---------|
| `unverified` | No valid signature | Red warning |
| `signed` | Valid publisher Ed25519 signature | Yellow |
| `verified` | Publisher signature + registry counter-signature, anchored to configured registry public key | Green |
| `certified` | All above + checkpoint signature + transparency inclusion proof (same anchored registry key) | Green + badge |

### OIDC Trusted Publishing

Publisher authentication uses OIDC federated identity (GitHub Actions, GitLab CI, Google Cloud) rather than long-lived API tokens. This follows the model established by PyPI Trusted Publishing and npm provenance.

```text
CI workflow
    |
    v
OIDC Identity Provider (GitHub)
    |  id_token (short-lived JWT)
    v
Registry Token Exchange (/api/v1/auth/oidc) [target hosted model]
    |  registry_token (scoped, short-lived)
    v
Publish with registry_token + Ed25519 signature

Current implementation (2026-02-28): publish uses bearer identity token directly
with `X-Clawdstrike-Auth-Type: oidc` and provider hint headers.
```

The OIDC subject claim binds the publication to a specific repository and workflow, creating an auditable link from package to source.

## Plugin Runtime

### WASM Guard Runtime

Guard packages are executed in a wasmtime sandbox with capability-based security. The runtime bridges between the host `Guard` trait and the WASM guest ABI.

```text
+--------------------------------------------+
|              Host (clawdstrike)             |
|                                            |
|  +-----------+     +-------------------+   |
|  | HushEngine| --> | WasmGuardRuntime  |   |
|  +-----------+     | (wasmtime)        |   |
|                    |                   |   |
|                    | Capabilities:     |   |
|                    |  - fs_read        |   |
|                    |  - network        |   |
|                    |  - clock          |   |
|                    +--------+----------+   |
|                             |              |
+-----------------------------|--------------+
                              |
                    +---------v----------+
                    |   WASM Guest       |
                    |                    |
                    |  name() -> String  |
                    |  handles() -> bool |
                    |  check() -> Result |
                    +--------------------+
```

Resource limits from the manifest (`[resources]`) are enforced by wasmtime:

- **max_memory_mb**: WASM linear memory limit (default: 64 MB)
- **max_cpu_ms**: Fuel-based CPU time limit per invocation (default: 100 ms)
- **max_timeout_ms**: Wall-clock timeout (default: 5000 ms)

Capability enforcement matches the existing `PluginManifest` validation rules. Per `crates/libs/clawdstrike/src/plugins/manifest.rs`, untrusted plugins cannot request `subprocess`, `filesystem.write`, or `secrets.access` capabilities.

### Guard SDK Crate

A new `clawdstrike-guard-sdk` crate provides the guest-side interface:

```rust,ignore
// clawdstrike-guard-sdk (guest side)
use clawdstrike_guard_sdk::{export_guard, GuardAction, GuardContext, GuardResult};

struct PhiDetectorGuard;

impl clawdstrike_guard_sdk::Guard for PhiDetectorGuard {
    fn name(&self) -> &str { "acme.phi_detector" }

    fn handles(&self, action: &GuardAction) -> bool {
        matches!(action, GuardAction::FileWrite(_, _) | GuardAction::Custom(_, _))
    }

    fn check(&self, action: &GuardAction, context: &GuardContext) -> GuardResult {
        match action {
            GuardAction::FileWrite(path, content) => {
                if contains_phi(content) {
                    GuardResult::block("acme.phi_detector", Severity::Error,
                        format!("PHI detected in write to {}", path))
                } else {
                    GuardResult::allow("acme.phi_detector")
                }
            }
            _ => GuardResult::allow("acme.phi_detector"),
        }
    }
}

export_guard!(PhiDetectorGuard);
```

### Policy Pack Loading

Policy packs are static YAML bundles loaded by the `PolicyResolver`. When a policy references a package via the `pkg:` scheme, the resolver looks up the installed package and resolves its YAML files:

```yaml
# User policy referencing a package
schema_version: "1.2.0"
extends:
  - "pkg:acme/hipaa-base@1.0.0"    # Resolved from installed packages
  - "strict"                         # Built-in ruleset (unchanged)
  - "./local-overrides.yaml"         # Local file (unchanged)
```

The `pkg:` scheme is a new `PolicyLocation` variant, extending the existing enum that handles `Ruleset`, `File`, `Url`, and `Git` locations.

### Adapter Discovery

Adapters (TypeScript, Python) are language-native packages. The registry provides a discovery layer mapping canonical package names to their npm/pip equivalents:

```json
{
  "name": "clawdstrike-langchain",
  "type": "adapter",
  "npm": "@clawdstrike/langchain",
  "pip": "clawdstrike-langchain",
  "clawdstrike_min": "0.10.0"
}
```

Installation delegates to the appropriate language package manager:

```bash
$ clawdstrike pkg install clawdstrike-langchain
Detected: Node.js project (package.json present)
Running: npm install @clawdstrike/langchain@2.1.0
```

## Dependency Resolution

### Version Specification

Dependencies use SemVer 2.0.0 with standard range operators:

| Operator | Example | Meaning |
|----------|---------|---------|
| `^` | `^1.2.3` | `>=1.2.3, <2.0.0` |
| `~` | `~1.2.3` | `>=1.2.3, <1.3.0` |
| `=` | `=1.2.3` | Exactly `1.2.3` |
| `>=` | `>=1.2.0` | `1.2.0` or newer |
| Range | `>=1.0.0, <2.0.0` | Explicit range |

### Three Compatibility Dimensions

Resolution must satisfy three independent compatibility constraints:

1. **Clawdstrike version**: Each package declares `clawdstrike.min_version`. The resolver rejects packages incompatible with the running clawdstrike version.

2. **Policy schema version**: Policy packs declare `clawdstrike.policy_schema`. All policy packs in a resolved graph must target a schema version in `POLICY_SUPPORTED_SCHEMA_VERSIONS` (currently `["1.1.0", "1.2.0"]`).

3. **Inter-package dependencies**: Standard SemVer dependency resolution between packages.

### Resolution Algorithm

The resolver uses the PubGrub algorithm (same approach as Cargo and uv) for client-side dependency resolution. Resolution runs entirely on the client using the sparse index, with no server-side computation.

```text
Input: root dependencies + clawdstrike version + policy schema
  |
  v
PubGrub Solver
  |-- Fetch index entries for each dependency
  |-- Apply version constraints
  |-- Check clawdstrike compatibility
  |-- Check policy schema compatibility
  |-- Backtrack on conflicts
  |
  v
Output: resolved version set or conflict explanation
```

### Lockfile: `clawdstrike-pkg.lock`

The lockfile pins exact versions, checksums, and receipt hashes for reproducible installations.

```toml
# clawdstrike-pkg.lock
# This file is auto-generated. Do not edit manually.
version = 1

[[package]]
name = "acme-phi-guard"
version = "1.2.0"
type = "guard"
checksum = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
receipt_hash = "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
source = "registry+https://registry.clawdstrike.dev"

[[package.dependencies]]
name = "acme-common"
version = "1.4.2"

[[package]]
name = "acme-common"
version = "1.4.2"
type = "guard"
checksum = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
receipt_hash = "sha256:0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba"
source = "registry+https://registry.clawdstrike.dev"
```

## Local Storage Layout

Installed packages reside under the Clawdstrike data directory:

```text
$XDG_DATA_HOME/clawdstrike/
  packages/
    acme-phi-guard/
      1.2.0/
        clawdstrike-pkg.toml
        .pkg-meta.json
        artifacts/
          phi_detector.wasm
    acme-common/
      1.4.2/
        ...
  cache/
    registry/
      index/          # Sparse index cache
      archives/       # Downloaded .cpkg files
    builds/           # Compiled WASM artifacts cache
```

## Security Considerations

### Fail-Closed Principle

Consistent with Clawdstrike's core design philosophy:

- **Invalid manifests reject at load time.** The existing `PluginManifest::validate()` rejects duplicate guard names, invalid semver, and untrusted plugins requesting high-risk capabilities.
- **Unverifiable packages are denied.** If a publisher signature cannot be verified, the package is not installed (unless explicitly overridden with `--allow-unverified`).
- **Missing transparency proofs produce warnings.** Packages without transparency log entries are assigned `signed` trust level, not `verified`.

### Supply Chain Integrity

1. **Content-addressable storage.** Archives are identified by SHA-256 checksum. The checksum is recorded in the sparse index and verified on download.

2. **Attestation chain.** Each package version has publisher signature + registry counter-signature metadata linking publisher identity, archive checksum, and timestamp.

3. **Append-only log.** The Merkle tree transparency log provides cryptographic proof that a package was published at a specific sequence number. Clients can detect index tampering by verifying inclusion proofs.

4. **No long-lived tokens.** OIDC trusted publishing eliminates stored API keys. Publisher identity is bound to verifiable CI/CD workflows.

### WASM Sandboxing

WASM guards run in wasmtime with:

- **No ambient authority.** Capabilities must be explicitly declared and granted.
- **Resource limits.** Memory, CPU, and wall-clock time are bounded.
- **Capability escalation prevention.** Untrusted packages cannot request `subprocess`, `filesystem.write`, or `secrets.access` (enforced by `PluginManifest::validate()`).

### Network Security

Registry communication follows the same hardening applied to remote policy extends (see `crates/services/hush-cli/src/remote_extends.rs`):

- HTTPS-only by default
- No private/loopback IP resolution (SSRF protection)
- No cross-host redirects
- Size limits on fetched content
- Host allowlisting for air-gapped environments

## Backward Compatibility

### Policy Schema

The package manager requires policy schema v1.2.0 but maintains backward compatibility with v1.1.0 policies per `POLICY_SUPPORTED_SCHEMA_VERSIONS`. The `pkg:` extends scheme is a new feature within the v1.2.0 schema boundary.

### Existing Plugin Manifest

The `clawdstrike-pkg.toml` format is a superset of the existing `PluginManifest`. Existing manifests can be migrated using `clawdstrike pkg init --from-plugin`.

### CLI Namespace

All new commands live under `clawdstrike pkg`, avoiding collisions with existing commands (`check`, `verify`, `keygen`, `policy`, `guard`, `run`, `daemon`, `hash`, `sign`, `merkle`, `completions`).

### Guard Trait

The `Guard` trait interface is unchanged. WASM guards implement the same `name()`, `handles()`, `check()` contract. The `WasmGuardRuntime` adapts between the host trait and the WASM guest ABI, appearing to `HushEngine` as a regular `Box<dyn Guard>`.

## Phased Implementation

### Phase 0: Local Package Management (4-6 weeks)

Scope: manifest format, `.cpkg` archive, local install/remove, no registry.

- Define `clawdstrike-pkg.toml` schema (extend `PluginManifest`)
- Implement `.cpkg` packing and unpacking
- Add `clawdstrike pkg init`, `clawdstrike pkg pack`, `clawdstrike pkg install --path`, `clawdstrike pkg list`, `clawdstrike pkg remove`
- Add `pkg:` scheme to `PolicyResolver`
- Local storage layout and lockfile generation

Deliverables:
- `crates/libs/clawdstrike/src/pkg/manifest.rs` - Extended manifest
- `crates/libs/clawdstrike/src/pkg/archive.rs` - cpkg format
- `crates/libs/clawdstrike/src/pkg/resolver.rs` - Local resolver
- `crates/services/hush-cli/src/pkg/` - CLI commands

### Phase 1: WASM Guard Runtime (4-6 weeks)

Scope: wasmtime integration, guard SDK crate, sandboxed execution.

- `clawdstrike-guard-sdk` crate (guest-side, wit-bindgen)
- `WasmGuardRuntime` in `crates/libs/clawdstrike/src/guards/wasm.rs`
- WIT (WebAssembly Interface Types) definitions for Guard ABI
- Capability enforcement (filesystem, network, subprocess)
- Resource limit enforcement (memory, CPU fuel, timeout)
- Integration with `CustomGuardRegistry` as a built-in factory

Deliverables:
- `crates/libs/clawdstrike-guard-sdk/` - Guest SDK
- `crates/libs/clawdstrike/src/guards/wasm.rs` - Host runtime
- `wit/guard.wit` - Interface definition

### Phase 2: Registry MVP (6-8 weeks)

Scope: sparse index, OCI backend, publish/install from registry.

- Sparse index generation and serving
- OCI registry integration (custom media types)
- REST API for publishing and search
- PostgreSQL metadata storage
- Publisher Ed25519 signature generation and verification
- `clawdstrike pkg publish`, `clawdstrike pkg search`, `clawdstrike pkg info`, `clawdstrike pkg install` (from registry)

Deliverables:
- `crates/services/registry/` - Registry service
- Sparse index format specification
- OCI media type registrations
- Registry deployment (Docker Compose + Helm chart)

### Phase 3: Trust and Transparency (4-6 weeks)

Scope: signing infrastructure, transparency log, OIDC.

- Registry counter-signature (Spine envelope wrapping)
- Merkle tree transparency log (using `hush-core::merkle`)
- Inclusion proof generation and client verification
- OIDC trusted publishing (GitHub, GitLab, Google Cloud)
- `clawdstrike pkg verify`, `clawdstrike pkg audit`
- Optional Sigstore Rekor integration

Deliverables:
- `crates/libs/clawdstrike/src/pkg/transparency.rs` - Merkle log client
- OIDC token exchange endpoint
- Advisory database schema

### Phase 4: Ecosystem (Ongoing)

Scope: multi-language integration, web UI, organizations.

- TypeScript SDK integration (`@clawdstrike/sdk` package resolution)
- Python SDK integration (`hush-py` package resolution)
- Web UI for browsing and managing packages
- Organization and team ownership
- Registry mirroring for air-gapped deployments
- Package namespacing (org scopes: `@acme/phi-guard`)

## Alternatives Considered

### Use npm/pip Directly

Distributing all packages as npm or pip packages would leverage existing infrastructure but cannot handle WASM guards (which are language-agnostic), cannot enforce Clawdstrike-specific compatibility constraints (policy schema version, clawdstrike version), and cannot provide the cryptographic attestation chain (receipts, transparency log).

### OPA-Style Bundle Format

Open Policy Agent uses opaque tarballs with a `data.json` and `policy.rego` convention. This is simpler but lacks typed package metadata, dependency resolution, and the WASM guard execution model. Clawdstrike's existing policy schema system is richer than OPA's flat bundle model.

### Git Submodules

Using git repositories directly (extending the existing `git+` extends scheme) provides versioning and authentication but lacks discovery, dependency resolution, and trust attestation beyond commit signatures.

## Open Questions

1. **Namespace policy.** Should package names be globally unique (like crates.io) or scoped by organization (like npm `@scope/name`)? The current design assumes global names with optional organization ownership.

2. **WASM component model.** Should guards target wasm32-wasip2 (WASI Preview 2 / Component Model) or wasm32-wasip1? WASIP2 provides richer typed interfaces via WIT but has less toolchain maturity.

3. **Offline guard compilation.** Should the registry accept pre-compiled WASM, or should it compile from source (like docs.rs builds documentation)? Pre-compiled is simpler but requires trusting the build environment.

4. **Guard composition.** Should the package manager support guard pipelines where one guard's output feeds into another? This would require extending the `GuardResult` type.

5. **Yanking vs. deletion.** Yanked packages should remain downloadable (for lockfile reproducibility) but not appear in new resolutions. Should there be a hard-delete mechanism for security-critical removals?

## References

- [Cargo Registry Index Protocol](https://doc.rust-lang.org/cargo/reference/registry-index.html)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
- [PubGrub Algorithm](https://github.com/dart-lang/pub/blob/master/doc/solver.md)
- [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
- [Sigstore / Rekor Transparency Log](https://docs.sigstore.dev/logging/overview/)
- [RFC 6962 - Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [WASI Preview 2 / Component Model](https://github.com/WebAssembly/component-model)
- [WebAssembly Interface Types (WIT)](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md)
- Clawdstrike Guard trait: `crates/libs/clawdstrike/src/guards/mod.rs`
- Clawdstrike PluginManifest: `crates/libs/clawdstrike/src/plugins/manifest.rs`
- Clawdstrike PolicyResolver: `crates/libs/clawdstrike/src/policy.rs`
- Spine Envelope: `crates/libs/spine/src/envelope.rs`
- Merkle tree: `crates/libs/clawdstrike/src/pkg/merkle.rs`
- Remote extends: `crates/services/hush-cli/src/remote_extends.rs`
- Signed policy bundles: `crates/libs/clawdstrike/src/policy_bundle.rs`
