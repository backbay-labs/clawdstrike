# Phase 3: Aeneas Merkle Tree Extraction Report

**Date:** 2026-03-17
**Status:** PARTIAL -- types extracted, function bodies blocked by SHA-256 and nested borrow limitations

---

## 1. Summary

Charon (v0.1.173) + Aeneas on `hush-core::merkle`. **Types extracted successfully; zero function bodies translated.** Three root causes:

1. **SHA-256 type errors** (digest/typenum complexity) -- blocked `leaf_hash`, `node_hash`
2. **Nested borrow limitation** -- blocked `inclusion_proof`
3. **Transitive failures** -- remaining 8 functions depend on (1) or (2)

Confirms Phase 0 prediction: SHA-256 must be axiomatized.

---

## 2. Methodology

### 2.1 Charon Extraction

```bash
charon cargo --preset=aeneas \
  --start-from 'crate::merkle' \
  --dest-file /tmp/charon-merkle/hush_core.llbc \
  -- --lib -p hush-core
```

**Result:** Produced 3.0 MB LLBC file. 443 warnings, 9 type errors (all in `digest-0.10.7/src/core_api/wrapper.rs` and `ct_variable.rs`). The type errors stem from Charon's inability to resolve typenum-level trait clause mismatches in the `digest` crate's heavily generic type machinery.

### 2.2 Aeneas Translation

```bash
aeneas -backend lean -dest /tmp/aeneas-merkle \
  -split-files -gen-lib-entry \
  /tmp/charon-merkle/hush_core.llbc
```

**Result:** Exit code 2. Produced four files:
- `Types.lean` (51 KB, 72 declarations, 922 lines)
- `Funs.lean` (3.5 KB, 7 trait impl wiring declarations, no function bodies)
- `FunsExternal_Template.lean` (146 KB, 149 axiom declarations)
- `TypesExternal_Template.lean` (7 KB, 9 opaque type axioms)

Of the 47 transparent functions Aeneas attempted to translate, all were from dependency crates (digest, typenum, etc.). None were from the Merkle module.

---

## 3. Per-Function Failure Analysis

### 3.1 `leaf_hash` -- FAILED (SHA-256 type error)

**Error:** `Found type error in the output of charon`
**Location:** `merkle.rs:28:21-28:34` (the `Sha256::new()` call)
**Root cause:** Charon produces a malformed LLBC type for `Sha256` because the `digest` crate uses deeply nested typenum-parameterized generics (`CoreWrapper<Sha256VarCore, ...>`) with trait clauses that Charon cannot fully resolve. Aeneas rejects the malformed type.

### 3.2 `node_hash` -- FAILED (SHA-256 type error)

**Error:** `Found type error in the output of charon`
**Location:** `merkle.rs:40:21-40:34` (the `Sha256::new()` call)
**Root cause:** Same as `leaf_hash`. Both functions call `Sha256::new()`, which triggers the identical type resolution failure.

### 3.3 `inclusion_proof` -- FAILED (nested borrows)

**Error:** `Nested borrows are not supported yet`
**Location:** `merkle.rs:163:8-178:9`
**Root cause:** The `for level in &self.levels` loop iterates over `&Vec<Vec<Hash>>`, creating a borrow of a borrow (`&&Vec<Hash>`). Aeneas's borrow checker does not yet support nested shared borrows in loop bodies.

### 3.4 `from_leaves` -- FAILED (transitive)

Not explicitly flagged by Aeneas, but depends on `leaf_hash` (which failed). The function's body calls `leaf_hash` and `node_hash` in a loop; since those functions have type errors in the LLBC, the entire function is skipped.

### 3.5 `from_hashes` -- FAILED (transitive)

Depends on `node_hash` (which failed).

### 3.6 `leaf_count` -- FAILED (transitive)

The closure `|l| l.len()` at `merkle.rs:127` could not be translated. This is likely due to the `Option::map` + `unwrap_or` chain operating on the nested `Vec<Vec<Hash>>` levels field.

### 3.7 `root` -- FAILED (transitive)

The closure at `merkle.rs:134:22-134:35` (`.and_then(|l| l.first())`) could not be translated. Same nested-borrow issue as `inclusion_proof` -- accessing `&Vec<Hash>` elements through `&Vec<Vec<Hash>>`.

### 3.8 `compute_root` / `compute_root_from_hash` -- FAILED (transitive)

Depends on `leaf_hash` and `node_hash` (SHA-256 type errors).

### 3.9 `verify` / `verify_hash` -- FAILED (transitive)

Depends on `compute_root`/`compute_root_from_hash`.

---

## 4. What Succeeded

### 4.1 Type Definitions (complete)

All Merkle-related types were correctly translated to Lean 4:

```lean
-- Hash type (32-byte array)
structure hashing.Hash where
  bytes : Array Std.U8 32#usize

-- Merkle tree (vector of level vectors)
structure merkle.MerkleTree where
  levels : alloc.vec.Vec (alloc.vec.Vec hashing.Hash)

-- Merkle inclusion proof
structure merkle.MerkleProof where
  tree_size : Std.Usize
  leaf_index : Std.Usize
  audit_path : alloc.vec.Vec hashing.Hash

-- Error enum (all variants)
inductive error.Error where
| InvalidSignature : error.Error
| InvalidPublicKey : String → error.Error
| ...
| MerkleProofFailed : error.Error
| EmptyTree : error.Error
| InvalidProofIndex : Std.Usize → Std.Usize → error.Error
| ...
```

### 4.2 Serde-generated types

The serde `Deserialize` machinery for `MerkleProof` was partially translated (types for `__Field`, `__FieldVisitor`, `__Visitor`), though the function bodies failed.

### 4.3 Dependency function bodies

47 functions from dependency crates (typenum, digest) were translated with full bodies, though these are not directly useful for Merkle verification.

### 4.4 Opaque Hash Functions (second run)

A second extraction with `--opaque crate::merkle::leaf_hash --opaque crate::merkle::node_hash` successfully produced clean axioms in Lean:

```lean
axiom merkle.leaf_hash : Slice Std.U8 → Result hashing.Hash
axiom merkle.node_hash : hashing.Hash → hashing.Hash → Result hashing.Hash
```

This confirms that the SHA-256 type errors can be fully sidestepped by marking the hash functions as opaque. However, the structural functions (`from_leaves`, `from_hashes`, `inclusion_proof`, `compute_root_from_hash`, `verify`) were still not translated because:
- `inclusion_proof` and `root` hit the nested-borrow limitation independently
- `from_leaves` uses `iter().map(|l| leaf_hash(l.as_ref())).collect()` -- closures + iterators + `collect`
- `from_hashes` has similar iterator patterns
- `compute_root_from_hash` uses `self.audit_path.iter()` (iterator over `&Vec<Hash>`)
- `verify`/`verify_hash` use `map(|root| &root == expected_root).unwrap_or(false)` closures

The opaque-hash run reduced Charon warnings from 443 to 72 and produced a 2.3 MB LLBC file (down from 3.0 MB).

---

## 5. Path Forward

### 5.1 Option A: Abstract SHA-256 Behind a Trait (Recommended)

Create a `Hasher` trait that `leaf_hash` and `node_hash` use instead of directly calling `sha2::Sha256`:

```rust
// In a cfg(feature = "formal") block or a separate extraction-friendly module:
pub trait MerkleHasher {
    fn hash(data: &[u8]) -> [u8; 32];
}

pub fn leaf_hash<H: MerkleHasher>(leaf_bytes: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + leaf_bytes.len());
    buf.push(0x00);
    buf.extend_from_slice(leaf_bytes);
    Hash::from_bytes(H::hash(&buf))
}
```

Then in Lean, axiomatize the hasher:
```lean
axiom merkle_hash : List UInt8 → Array UInt8 32
axiom merkle_hash_deterministic : merkle_hash x = merkle_hash x
axiom merkle_hash_domain_sep : merkle_hash (0x00 :: xs) ≠ merkle_hash (0x01 :: ys)
```

**Effort:** ~50 lines of Rust refactoring, plus cfg-gated impl for SHA-256.

### 5.2 Option B: Use `--opaque` Flags for SHA-256 Functions

Tell Charon/Aeneas to treat `leaf_hash` and `node_hash` as opaque (axioms), then only extract the structural functions (`from_leaves`, `from_hashes`, `inclusion_proof`, `compute_root_from_hash`, `verify`).

```bash
charon cargo --preset=aeneas \
  --start-from 'crate::merkle' \
  --opaque 'crate::merkle::leaf_hash' \
  --opaque 'crate::merkle::node_hash' \
  --dest-file /tmp/charon-merkle/hush_core.llbc \
  -- --lib -p hush-core
```

This would avoid the SHA-256 type errors entirely. The structural functions would still need the nested-borrow issue resolved for `inclusion_proof` and `root`.

**Effort:** Minimal Rust changes, but requires fixing the nested-borrow issue separately.

### 5.3 Option C: Rewrite to Avoid Nested Borrows, Closures, and Iterators

Aeneas has three unsupported patterns in the Merkle module. All can be rewritten:

**C1. Nested borrows** (`inclusion_proof`, `root`):
```rust
// Before (nested borrow -- &self.levels yields &&Vec<Hash>):
for level in &self.levels { ... }

// After (index-based, single borrow level):
let mut level_idx = 0;
while level_idx < self.levels.len() {
    let level_len = self.levels[level_idx].len();
    // ... use self.levels[level_idx][j] ...
    level_idx += 1;
}
```

**C2. Iterator + closure + collect** (`from_leaves`):
```rust
// Before:
let mut current: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l.as_ref())).collect();

// After:
let mut current: Vec<Hash> = Vec::with_capacity(leaves.len());
let mut i = 0;
while i < leaves.len() {
    current.push(leaf_hash(leaves[i].as_ref()));
    i += 1;
}
```

**C3. Option combinators** (`root`, `leaf_count`, `verify`):
```rust
// Before:
self.levels.last().and_then(|l| l.first()).copied().unwrap_or_else(Hash::zero)

// After:
if self.levels.is_empty() {
    Hash::zero()
} else {
    let last = &self.levels[self.levels.len() - 1];
    if last.is_empty() { Hash::zero() } else { last[0] }
}
```

**Effort:** ~20 lines per function, ~100 lines total across 10 functions.

### 5.4 Recommended Combined Approach

1. **Option B + C together**: Use `--opaque` for `leaf_hash`/`node_hash` (already confirmed working) AND rewrite loop/iterator patterns to index-based
2. Re-run Charon + Aeneas
3. If successful, write Lean proofs for:
   - P14: `from_leaves(ls).root() = from_leaves(ls).root()` (root determinism)
   - P15: `tree.inclusion_proof(i).verify(leaves[i], tree.root()) = true` (inclusion proof soundness)
   - P16: `leaf_hash(x) != node_hash(a, b)` (domain separation, from axiom)

Option B is preferable: zero Rust source changes, only the extraction command changes.

---

## 6. Output Artifacts

All Aeneas output files are saved in the Lean project for reference:

```
formal/lean4/ClawdStrike/ClawdStrike/Impl/Merkle/
├── Types.lean                    # 72 type declarations (usable)
├── Funs.lean                     # 7 trait impl wirings (no function bodies)
├── TypesExternal_Template.lean   # 9 opaque type axioms (digest, typenum, etc.)
└── FunsExternal_Template.lean    # 149 external function axioms
```

The type definitions (`MerkleTree`, `MerkleProof`, `Hash`, `Error`) are correct and can be used as-is in hand-written Lean proofs.

---

## 7. Statistics

### Run 1: Full extraction (no opaque flags)

| Metric | Count |
|--------|-------|
| Charon warnings | 443 |
| Charon type errors (digest crate) | 9 |
| Aeneas type declarations generated | 72 |
| Aeneas opaque type axioms | 9 |
| Aeneas external function axioms | 149 |
| Aeneas transparent functions translated | 47 (all from deps, 0 from merkle) |
| Merkle function bodies translated | **0 / 10** |
| Merkle type definitions translated | **5 / 5** (MerkleTree, MerkleProof, Hash, Error, closures) |
| LLBC file size | 3.0 MB |

### Run 2: Opaque leaf_hash + node_hash

| Metric | Count |
|--------|-------|
| Charon warnings | 72 |
| Charon type errors | 0 |
| LLBC file size | 2.3 MB |
| `leaf_hash` axiom generated | Yes |
| `node_hash` axiom generated | Yes |
| Merkle function bodies translated | **0 / 8** (remaining after opaque) |
| Remaining blockers | nested borrows, iterators, closures |

---

## 8. Comparison with Phase 0 Predictions

| Phase 0 Prediction | Actual Result |
|---|---|
| SHA-256 must be axiomatized | Confirmed -- `leaf_hash`/`node_hash` fail on Sha256::new() type errors |
| `from_leaves` is "Easy" extraction | FAILED -- transitively blocked by SHA-256; also uses `map` + closure |
| `inclusion_proof` is "Easy" | FAILED -- nested borrows in `for level in &self.levels` |
| `compute_root_from_hash` is "Easy" | FAILED -- transitively blocked by SHA-256 |
| Type definitions will extract cleanly | Confirmed -- all types translated correctly |
| `Vec` operations supported | Partially confirmed -- Vec types work; iteration patterns hit borrow limits |
| Cross-crate extraction works | Confirmed -- `hush-core` extracted independently |

---

## 9. Conclusion

Extractable in principle; requires ~100 lines of mechanical refactoring (iterators to while-loops, combinators to if-else) to avoid three unsupported patterns: nested borrows (2 functions), iterator+closure+collect (3 functions), Option combinator chains (3 functions).

The type definitions and `leaf_hash`/`node_hash` axioms from this run serve as the foundation for hand-written Lean specs in the interim.

**Next step:** Create `merkle_extractable.rs` with Aeneas-friendly rewrites and re-run.
