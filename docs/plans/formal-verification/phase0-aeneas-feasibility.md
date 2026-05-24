# Phase 0: Aeneas Feasibility Assessment

## Summary

**Recommendation: CONDITIONAL GO.** Merkle tree and verdict aggregation are strong first candidates (low refactoring). Policy merge is feasible with medium effort. Ed25519 signing and cycle detection are **infeasible** for Aeneas (external crypto crates, I/O, `impl Trait`, `HashSet`).

---

## Target Analysis

### 1. `severity_ord()` -- Easy

**Location:** `crates/libs/clawdstrike/src/engine.rs:1699-1706`

**Code pattern:**
```rust
fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}
```

**Patterns:** Pure function, exhaustive match on fieldless enum. No async/dyn/Arc/unsafe/HashMap/closures/cfg.

**Dependencies:** `Severity` enum (strip serde derives).

**Extraction difficulty: Easy.** Textbook Aeneas candidate. Zero refactoring beyond stripping serde derives.

---

### 2. `aggregate_overall()` -- Medium

**Location:** `crates/libs/clawdstrike/src/engine.rs:1785-1818`

**Code pattern:** Takes `&[GuardResult]`, iterates to find the "most severe" result using a priority scheme (blocked > allowed, then by severity ordinal, then sanitized tiebreaker). Returns `best.clone()`.

**Patterns:** No async/dyn/Arc/unsafe. Slice iteration, `severity_ord()` call, `Clone`. Key problem: `is_sanitized()` inspects `serde_json::Value`.

**Blockers:**
1. `GuardResult.details: Option<serde_json::Value>` -- replace with `sanitized: bool` in extracted version
2. Strip serde derives

**Extraction difficulty: Medium.** Core logic is pure, but `serde_json::Value` requires type abstraction (~30 lines of shim code).

---

### 3. `GuardConfigs::merge_with()` -- Medium-Hard

**Location:** `crates/libs/clawdstrike/src/policy.rs:280-368`

**Code pattern:** Constructs a new `GuardConfigs` by matching each `(Option<base>, Option<child>)` pair for 12+ guard config fields, applying field-specific merge logic.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- Extensive use of `Option::or_else()` with closures
- `Clone` on all config types
- `#[cfg(feature = "full")]` guards on spider_sense fields (2 conditional fields)
- `#[cfg(all(feature = "policy-event", not(feature = "full")))]` guard on alternative spider_sense field
- `BTreeSet<String>` used for `spider_sense_present_fields` (behind `#[cfg(feature = "full")]`)
- Calls `.merge_with()` on 7+ sub-config types (`ForbiddenPathConfig`, `EgressAllowlistConfig`, `SecretLeakConfig`, `McpToolConfig`, `SpiderSensePolicyConfig`, etc.)

**Dependencies (transitive):**
- `GuardConfigs` struct: 14+ fields, each an `Option<SomeConfig>` or `Vec<CustomGuardSpec>`
- Each `SomeConfig` type (e.g., `ForbiddenPathConfig`, `EgressAllowlistConfig`) has its own serde derives and `merge_with()` method
- `CustomGuardSpec` struct contains `serde_json::Value` in its `config` field
- `SpiderSensePolicyConfig` is behind a feature flag and lives in a different module
- All sub-config types have `#[serde(deny_unknown_fields)]` and various serde attributes

**Blockers requiring refactoring:**
1. **12+ dependent types** each need serde stripping -- large surface area
2. **`serde_json::Value`** appears in `CustomGuardSpec.config` (and behind cfg in spider_sense passthrough)
3. **`#[cfg]` feature gates** create multiple compilation variants -- Aeneas would need a single concrete version
4. **`BTreeSet<String>`** used for spider_sense tracking -- would need `Vec<String>` replacement or exclusion
5. Each sub-config's `merge_with()` is itself a non-trivial function that would also need extraction to verify the full merge chain

**Extraction difficulty: Medium-Hard.** The function itself is structurally simple (it is a large match-arm constructor), but extracting it meaningfully requires also extracting all 12+ sub-config types and their `merge_with()` implementations. The `#[cfg]` gates add additional complexity. A pragmatic approach would be to extract a simplified version that covers only the non-cfg, non-serde_json fields (roughly 8 of the 14 fields), proving the merge logic correct for the common case.

---

### 4. `Policy::merge()` -- Medium

**Location:** `crates/libs/clawdstrike/src/policy.rs:1295-1386`

**Code pattern:** Three-way dispatch on `MergeStrategy` (Replace, Merge, DeepMerge), constructing a new `Policy` by combining base and child fields.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- `Clone` on `Policy` and all sub-types
- `Option::or_else()` with closures
- String emptiness checks (`!child.name.is_empty()`)
- Equality comparison with `Default` (`child.guards != GuardConfigs::default()`)
- Calls `self.guards.merge_with(&child.guards)` (chains to #3 above)
- Calls `merge_custom_guards()` (chains to #5 below)
- Calls `base.merge_with(child_cfg)` on `PostureConfig`, `OriginsConfig`, `BrokerConfig`

**Dependencies:**
- `Policy` struct: 12 fields including `String`, `Option<String>`, `MergeStrategy` (3-variant enum), `GuardConfigs`, `Vec<PolicyCustomGuardSpec>`, `PolicySettings`, `Option<PostureConfig>`, `Option<OriginsConfig>`, `Option<BrokerConfig>`
- `MergeStrategy` enum: fieldless, 3 variants -- trivial to extract
- `PolicySettings`: 3 `Option<bool/u64>` fields -- trivial to extract (after serde stripping)
- `PolicyCustomGuardSpec`: contains `serde_json::Value` in `config` field -- needs abstraction
- `PostureConfig`, `OriginsConfig`, `BrokerConfig`: each have their own `merge_with()` methods and serde types

**Blockers requiring refactoring:**
1. `PolicyCustomGuardSpec.config: serde_json::Value` -- needs abstraction
2. `GuardConfigs::default()` comparison -- requires `PartialEq` which Aeneas can handle, but the `Default` impl must also be extracted
3. Transitive dependency on `GuardConfigs::merge_with()` and all its sub-types
4. `PostureConfig`, `OriginsConfig`, `BrokerConfig` merge methods add more surface area

**Extraction difficulty: Medium.** The function itself is clean dispatch logic. The `Replace` branch is trivially correct (just clone). The `Merge` branch uses simple field selection. The `DeepMerge` branch delegates to sub-merges. A phased approach could extract the top-level dispatch first with opaque sub-merge calls, then deepen.

---

### 5. `merge_custom_guards()` -- Medium

**Location:** `crates/libs/clawdstrike/src/policy.rs:1574-1601`

**Code pattern:** Merges two `&[PolicyCustomGuardSpec]` slices by ID: starts with base, then upserts child entries by matching on `cg.id`.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- **`HashMap<String, usize>`** used as an index -- partial Aeneas support, would need Vec-of-pairs replacement
- `Vec::push()`, `Clone` on `PolicyCustomGuardSpec`
- Closure in `index.get(&cg.id).copied()`
- `to_vec()` on slices

**Dependencies:**
- `PolicyCustomGuardSpec`: has `id: String`, `enabled: bool`, `config: serde_json::Value`
- `serde_json::Value` in `config` is not inspected by this function -- it is just cloned

**Blockers requiring refactoring:**
1. **`HashMap<String, usize>`** -- replace with linear scan over `Vec<(String, usize)>` or similar. This changes performance characteristics but preserves semantics.
2. `serde_json::Value` in `PolicyCustomGuardSpec.config` -- since this function only clones it, could be replaced with an opaque type parameter or a `Vec<u8>` in the extracted version.

**Extraction difficulty: Medium.** The algorithm is simple (upsert-by-key), but the HashMap usage is the main obstacle. Replacing with linear scan is straightforward and the resulting extracted code would be provably equivalent for small guard counts (which is always the case -- policies have <20 custom guards).

---

### 6. `from_yaml_with_extends_internal_resolver()` (cycle detection) -- Infeasible

**Location:** `crates/libs/clawdstrike/src/policy.rs:1420-1465`

**Code pattern:** Recursive function that resolves policy `extends` chains with cycle detection via `HashSet<String>` and depth limiting via `MAX_POLICY_EXTENDS_DEPTH`.

**Hard blockers:** `impl PolicyResolver` (trait dispatch to I/O), `HashSet<String>`, `serde_yaml::from_str`, filesystem/network side effects. Recursive + effectful.

**Extraction difficulty: Infeasible.** Deeply entangled with I/O, trait dispatch, and serde. The cycle detection algorithm itself (HashSet + depth counter) is simple enough to verify via an abstract model.

---

### 7. `MerkleTree::from_leaves()` -- Easy

**Location:** `crates/libs/hush-core/src/merkle.rs:69-95`

**Code pattern:** Builds a Merkle tree bottom-up from leaf data. Hashes each leaf, then iteratively pairs nodes (carrying odd nodes upward) until a single root remains.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- `Vec<Vec<Hash>>` for levels, `Vec<Hash>` for current level
- Generic parameter `T: AsRef<[u8]>` on input -- would need monomorphization to `&[&[u8]]` or similar
- `Iterator::map` + `collect` for leaf hashing
- `Vec::push`, `Vec::with_capacity`, `div_ceil` (stable since Rust 1.73)
- `Clone` on `Vec<Hash>` (for level storage)
- Calls `leaf_hash()` and `node_hash()` -- both pure

**Dependencies:**
- `Hash` type: `[u8; 32]` newtype with serde derives -- trivial to extract after stripping serde
- `leaf_hash()`: `SHA256(0x00 || bytes)` -- uses `sha2` crate
- `node_hash()`: `SHA256(0x01 || left || right)` -- uses `sha2` crate
- `Error::EmptyTree` variant

**Blockers requiring refactoring:**
1. `sha2::Sha256` calls in `leaf_hash`/`node_hash` -- external crate. Must be abstracted as an opaque hash function parameter or axiomatized.
2. `Hash` needs serde stripping (trivial)
3. Generic `T: AsRef<[u8]>` needs monomorphization

**Extraction difficulty: Easy.** The tree-building algorithm is purely structural. If SHA-256 is axiomatized as a function `hash: &[u8] -> [u8; 32]`, the entire module extracts cleanly. The `div_ceil` usage is standard integer arithmetic. This is an ideal Aeneas target for proving Merkle tree correctness properties (e.g., root determinism, inclusion proof soundness).

---

### 8. `MerkleProof::compute_root_from_hash()` / `verify()` -- Easy

**Location:** `crates/libs/hush-core/src/merkle.rs:206-250`

**Code pattern:** Walks the audit path from leaf to root, combining with siblings. Verifies by comparing computed root against expected.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- Iterator over `audit_path` with `.next()` calls
- `ok_or()` error propagation
- Simple arithmetic: `idx /= 2`, `size.div_ceil(2)`, `is_multiple_of(2)`
- `Copy` on `Hash`

**Dependencies:**
- `Hash` (32-byte newtype), `node_hash()` (pure), `leaf_hash()` (pure)
- `Error::MerkleProofFailed` variant
- `MerkleProof` struct: `tree_size: usize`, `leaf_index: usize`, `audit_path: Vec<Hash>` (plus serde derives)

**Extraction difficulty: Easy.** This is a verification algorithm with simple control flow. Together with `from_leaves()`, extracting this would allow proving the core Merkle correctness property: `tree.inclusion_proof(i).verify(leaves[i], &tree.root()) == true` for all valid indices. This is the highest-value formal verification target in the codebase.

---

### 9. `inclusion_proof()` -- Easy

**Location:** `crates/libs/hush-core/src/merkle.rs:151-185`

**Code pattern:** Generates an audit path by walking up the tree levels, collecting sibling hashes.

**Rust patterns used:**
- No async, no dyn Trait, no Arc/Mutex, no unsafe
- Vec indexing, `is_multiple_of(2)`, simple loop
- Constructs `MerkleProof` struct

**Dependencies:** Same as #8.

**Extraction difficulty: Easy.** Straightforward index-walking algorithm.

---

### 10. Signing: `Keypair`, `sign()`, `verify()` -- Infeasible

**Location:** `crates/libs/hush-core/src/signing.rs`

**Code pattern:** Thin wrappers around `ed25519-dalek` types.

**Hard blockers:** Every type wraps `ed25519-dalek` (external crypto with assembly). `OsRng` is effectful. Custom serde modules.

**Extraction difficulty: Infeasible.** Thin wrapper around `ed25519-dalek` -- no meaningful algorithm to extract. The correct approach is to axiomatize signing and verify the protocol that uses it.

---

### 11. `leaf_hash()` / `node_hash()` -- Easy (with axiomatization)

**Location:** `crates/libs/hush-core/src/merkle.rs:27-49`

**Code pattern:** `SHA256(0x00 || data)` and `SHA256(0x01 || left || right)`.

**Rust patterns used:**
- `sha2::Sha256` hasher -- external crate
- `hasher.update()`, `hasher.finalize()` -- effectful-looking but pure
- `copy_from_slice` on fixed-size arrays

**Extraction approach:** Axiomatize `SHA256` as an opaque function with the properties:
- Deterministic: `sha256(x) == sha256(x)`
- Collision-resistant (assumed, not proved): `x != y => sha256(x) != sha256(y)` (for practical purposes)
- Domain separation: `leaf_hash(x) != node_hash(a, b)` (follows from different prefix bytes, given collision resistance)

**Extraction difficulty: Easy with axiomatization.** The functions themselves are 6 lines each. Extract them as wrappers around an axiomatized hash function.

---

## Recommended Extraction Order

| Priority | Target | Difficulty | Value | Rationale |
|----------|--------|-----------|-------|-----------|
| 1 | `severity_ord()` | Easy | Low | Smoke test for Aeneas toolchain setup |
| 2 | `leaf_hash()` + `node_hash()` | Easy (axiom) | Medium | Foundation for Merkle proofs |
| 3 | `MerkleTree::from_leaves()` | Easy | High | Core data structure correctness |
| 4 | `MerkleProof::compute_root_from_hash()` + `verify()` | Easy | **Highest** | Prove inclusion proof soundness |
| 5 | `inclusion_proof()` | Easy | High | Complete Merkle correctness chain |
| 6 | `aggregate_overall()` | Medium | High | Prove verdict aggregation correctness (fail-closed property) |
| 7 | `merge_custom_guards()` | Medium | Medium | Prove upsert-by-key semantics |
| 8 | `Policy::merge()` | Medium | Medium | Prove policy inheritance correctness |
| 9 | `GuardConfigs::merge_with()` | Medium-Hard | Medium | Prove deep merge semantics (large surface area) |
| -- | `from_yaml_with_extends_internal_resolver()` | Infeasible | -- | Skip: I/O-entangled |
| -- | `Keypair` / `sign()` / `verify()` | Infeasible | -- | Skip: external crypto crate |

---

## Rust Patterns Requiring Refactoring

| Pattern | Occurrences | Aeneas Status | Remediation |
|---------|-------------|---------------|-------------|
| `serde` derives (`Serialize`, `Deserialize`) | All types | Not supported | Strip derives in extracted module; create parallel type definitions |
| `serde_json::Value` | `GuardResult.details`, `PolicyCustomGuardSpec.config`, `CustomGuardSpec.config` | Not supported (external type) | Replace with enum (`GuardDetails`) or opaque `Vec<u8>` in extracted version |
| `HashMap<String, usize>` | `merge_custom_guards()` | Partial support | Replace with `Vec<(String, usize)>` + linear scan |
| `BTreeSet<String>` | `GuardConfigs.spider_sense_present_fields` | Not supported | Replace with sorted `Vec<String>` or exclude (cfg-gated) |
| `#[cfg(feature = "...")]` | `GuardConfigs` (spider_sense fields) | Not supported | Pick one feature configuration for extraction |
| `impl Into<String>` parameters | `GuardResult` constructors | Partial support | Monomorphize to `String` |
| Generic `T: AsRef<[u8]>` | `MerkleTree::from_leaves()` | Partial support | Monomorphize to `&[&[u8]]` |
| `sha2::Sha256` / `sha3::Keccak256` | `leaf_hash`, `node_hash`, `sha256`, `keccak256` | Not supported (external) | Axiomatize as opaque hash function |
| `ed25519_dalek::*` | All signing types | Not supported (external) | Do not extract; axiomatize at protocol level |
| `Option::or_else(|| ...)` | `merge_with()`, `Policy::merge()` | Partial support | May need rewrite to explicit `match` |
| `Vec::push`, `Vec::with_capacity` | Merkle tree, merge functions | Supported | No change needed |
| `Iterator::map` + `collect` | `from_leaves()` | Partial support | May need explicit loop |
| `slice[i]` indexing | `aggregate_overall()`, Merkle tree | Supported (with bounds) | Aeneas generates bounds proof obligations |
| `div_ceil(2)` | Merkle tree | Should work | Simple integer method |
| `is_multiple_of(2)` | Merkle proof | Should work | Simple integer method |
| Recursive functions | extends resolver | Supported (with termination proof) | N/A -- function is infeasible for other reasons |

---

## Risk Assessment

### High-confidence risks

1. **Aeneas toolchain instability.** Aeneas requires nightly Rust and has known issues with recent Rust versions. The MSRV of 1.93 may conflict with Aeneas's required nightly. Mitigation: use a separate `aeneas-extract` crate with its own toolchain file.

2. **`serde_json::Value` pervasiveness.** This type appears in 3 of the 6 extractable targets. Each occurrence requires manual type abstraction. The `is_sanitized()` method's JSON inspection is particularly tricky -- it encodes a convention ("action" key equals "sanitized") that must be reified into a proper type for extraction.

3. **Large type surface for policy merge.** Extracting `GuardConfigs::merge_with()` meaningfully requires extracting ~12 sub-config types. Each has its own `merge_with()` implementation. This is not technically hard but represents significant boilerplate.

### Medium-confidence risks

4. **`div_ceil` and `is_multiple_of` support.** These are relatively recent stable methods. Aeneas may not have models for them yet. Fallback: replace with `(n + 1) / 2` and `n % 2 == 0`.

5. **Vec operations.** Aeneas's Vec model may not support all operations used (e.g., `Vec::with_capacity`, `push`, indexing). The Merkle tree code is Vec-heavy. Mitigation: Aeneas has been improving Vec support; test with the smoke-test function first.

6. **Proof obligations for slice indexing.** `aggregate_overall()` uses `&results[0]` and `&results[1..]` -- Aeneas will require proof that the slice is non-empty (which is checked by the early return). This should be straightforward but requires correct annotation.

### Low-confidence risks

7. **`Clone` derive interactions.** Aeneas extracts `Clone` but may generate suboptimal LEAN code for large structs with many fields. Performance of proof checking could be an issue for the 12-field `GuardConfigs`.

8. **Cross-crate extraction.** The Merkle module is in `hush-core` while the engine is in `clawdstrike`. Aeneas may need separate extraction per crate with manual linking in LEAN.

---

## Go/No-Go Recommendation

### GO, with the following scope and conditions:

**Scope for Phase 1:** Extract and verify the **Merkle tree module** (`hush-core/src/merkle.rs`) as the proof-of-concept. This includes:
- `leaf_hash()` and `node_hash()` (axiomatized SHA-256)
- `MerkleTree::from_leaves()`
- `MerkleProof::compute_root_from_hash()`
- `MerkleProof::verify()`
- `MerkleTree::inclusion_proof()`

**Target theorem:** For all valid leaf data `leaves` and valid index `i`, `tree.inclusion_proof(i).verify(leaves[i], &tree.root()) == true`.

**Scope for Phase 2:** Extract `severity_ord()` and `aggregate_overall()` with an abstracted `GuardResult` type (replacing `serde_json::Value` with a `Sanitized(bool)` flag).

**Target theorem:** `aggregate_overall` is fail-closed: if any result has `allowed == false`, then the aggregate result has `allowed == false`.

**Conditions:**
1. Phase 1 must successfully complete Aeneas extraction of `from_leaves()` before committing to Phase 2.
2. A separate `aeneas-extract` crate must be created with its own Rust toolchain, containing copies of target functions with serde/external-crate dependencies removed.
3. Do **not** attempt extraction of the signing module or the extends-resolution cycle detection. These provide negligible ROI for the effort required.
4. Budget 2-3 days for Aeneas toolchain setup and smoke testing before committing to the full Merkle extraction.

**Expected outcome:** Formally verified Merkle tree correctness and fail-closed verdict aggregation -- the two highest-value security invariants.
