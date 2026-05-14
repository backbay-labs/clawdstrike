# Verification Targets: Prioritized Analysis

**Status**: Active
**Author**: Verification Engineering
**Date**: 2026-03-16
**Prerequisite**: [Landscape Survey](./landscape-survey.md)
**Feeds into**: [Aeneas Pipeline](./aeneas-pipeline.md), [Logos Integration](./logos-integration.md)

---

## Scoring Methodology

Each verification target is scored on two axes:

- **Security Value** (1-5): How damaging is a bug in this component to ClawdStrike's security guarantees? A score of 5 means a bug would silently allow forbidden actions or produce invalid attestations.
- **Feasibility** (1-5): How realistic is formal verification with available tools, given the component's code complexity, dependencies, and language features? A score of 5 means the component is pure, small, and maps directly to a known verification technique.

**Priority Score** = Security Value x Feasibility (max 25).

Scores of 20+ are immediate targets. Scores of 12-19 are near-term. Scores below 12 are deferred or addressed through testing.

Scores near boundaries should be evaluated on their merits rather than mechanically sorted.

---

## Target 1: Guard Aggregation (`aggregate_overall`)

**Priority Score: 25** (Security: 5, Feasibility: 5)

### Component Description

`aggregate_overall` (`engine.rs:1785-1818`) combines individual guard verdicts into a single decision. Blocking results beat allowing results; among equal blocking status, higher severity wins. A bug here (e.g., deny overridden by allow) collapses the entire security model.

### Correctness Properties

1. **Deny monotonicity** (P1.1): If any `GuardResult` in the input has `allowed: false`, the output has `allowed: false`. Formally: `(exists r in results, r.allowed = false) => aggregate_overall(results).allowed = false`.
2. **Severity preservation** (P1.2): The output severity is >= the maximum severity of any blocking result. Formally: `(forall r in results, r.allowed = false => severity_ord(r.severity) <= severity_ord(output.severity))`.
3. **Empty input default** (P1.3): `aggregate_overall([]) = GuardResult::allow("engine")`.
4. **Sanitize precedence** (P1.4): Among non-blocking results of equal severity, a sanitized result is preferred over a plain warning.
5. **Determinism** (P1.5): The output is deterministic given the same input sequence.

### Code Complexity Assessment

- **LOC**: ~42 (34 for `aggregate_overall` at lines 1785-1818, 8 for `severity_ord` at lines 1699-1706)
- **Traits**: None (free functions)
- **Generics**: None
- **Async**: None
- **Unsafe**: None
- **External deps**: `GuardResult` and `Severity` types (both simple structs/enums). Note: `aggregate_overall` calls `r.is_sanitized()` which inspects a `serde_json::Value` field; the core extraction must replace this with a plain `bool`.
- **Control flow**: Single loop with three conditional branches

### Recommended Tool

**Primary**: Aeneas/Lean 4 -- pure, small, no dependencies. Proofs are straightforward induction on the list.
**Secondary**: Logos/Z3 for deny-wins as normative formula.

### Estimated Effort: 2-3 days

### Current Implementation

```rust
fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

fn aggregate_overall(results: &[GuardResult]) -> GuardResult {
    if results.is_empty() {
        return GuardResult::allow("engine");
    }
    let mut best = &results[0];
    for r in &results[1..] {
        let best_blocks = !best.allowed;
        let r_blocks = !r.allowed;
        if r_blocks && !best_blocks {
            best = r;
            continue;
        }
        if r_blocks == best_blocks && severity_ord(&r.severity) > severity_ord(&best.severity) {
            best = r;
            continue;
        }
        if r_blocks == best_blocks
            && severity_ord(&r.severity) == severity_ord(&best.severity)
            && !r_blocks
            && r.is_sanitized()
            && !best.is_sanitized()
        {
            best = r;
        }
    }
    best.clone()
}
```

The existing test suite has `aggregate_overall_prefers_sanitize_over_plain_warning_on_tie` (line 2057), confirming property P1.4 is tested but not proven.

---

## Target 2: Merkle Tree Inclusion Proofs

**Priority Score: 20** (Security: 4, Feasibility: 5)

### Component Description

`crates/libs/hush-core/src/merkle.rs` implements an RFC 6962-compatible Merkle tree used for transparency log checkpoints. It provides tree construction from leaf data, root computation, and inclusion proof generation and verification. The tree uses left-balanced / append-only semantics (odd nodes are carried upward, not duplicated).

A bug here could allow forged inclusion proofs, letting an attacker claim a receipt was part of a checkpoint when it was not.

### Correctness Properties

1. **Inclusion proof completeness** (P2.1): For any tree built from `n` leaves and any index `i < n`, `tree.inclusion_proof(i).verify(leaves[i], tree.root()) = true`.
2. **Inclusion proof soundness** (P2.2): For any tree and index `i`, `tree.inclusion_proof(i).verify(wrong_data, tree.root()) = false` when `wrong_data != leaves[i]` (up to collision resistance).
3. **Domain separation** (P2.3): `leaf_hash` uses prefix `0x00`, `node_hash` uses prefix `0x01`. No leaf hash can equal a node hash (under collision resistance).
4. **Root determinism** (P2.4): `MerkleTree::from_leaves(leaves).root()` is deterministic and depends only on the ordered leaf sequence.
5. **Proof length bound** (P2.5): `inclusion_proof(i).audit_path.len() <= ceil(log2(n))`.
6. **Empty tree rejection** (P2.6): `MerkleTree::from_leaves([])` returns `Err`.

### Code Complexity Assessment

- **LOC**: 360 total (252 production code, 108 tests). The `#[cfg(test)]` block starts at line 253.
- **Traits**: `Serialize`, `Deserialize` on `MerkleProof` (remove for Aeneas extraction)
- **Generics**: `from_leaves<T: AsRef<[u8]>>` (monomorphize)
- **Async**: None
- **Unsafe**: None
- **External deps**: `sha2::Sha256` (axiomatize), `serde` (remove from core)
- **Control flow**: Nested while loops, index arithmetic, `div_ceil`, `is_multiple_of` (both may need inlining for Aeneas)
- **Recursion**: The test reference implementation `tree_hash_recursive` is recursive; the production code is iterative. The `compute_root_from_hash` verification method also uses iterative while loop with `div_ceil`.

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4. Merkle trees are a classic formal verification target with extensive prior art in Lean/Coq. The code is pure, uses only arrays and simple arithmetic. The SHA-256 calls are axiomatized.

**Complementary**: Differential testing against a reference Python implementation for the RFC 6962 test vectors.

### Estimated Effort

- Aeneas extraction (axiomatize sha256): 2 days
- Proof of P2.1 (completeness): 3-4 days (induction on tree height)
- Proof of P2.2 (soundness, modulo collision resistance): 2-3 days
- Proofs of P2.3-P2.6: 2-3 days
- **Total: 1-2 weeks**

---

## Target 3: Policy Cycle Detection

**Priority Score: 20** (Security: 4, Feasibility: 5)

### Component Description

`from_yaml_with_extends_internal_resolver` in `crates/libs/clawdstrike/src/policy.rs:1420-1465` handles the `extends` keyword in policy YAML. It recursively resolves parent policies, building a visited set to detect cycles and enforcing a maximum depth of 32 (`MAX_POLICY_EXTENDS_DEPTH`).

A bug in cycle detection could cause infinite recursion (stack overflow / OOM), or worse, silently skip a base policy, weakening security.

### Correctness Properties

1. **Cycle detection** (P3.1): If the extends chain contains a cycle (any key appears twice in the resolution path), the function returns `Err`.
2. **Depth bound** (P3.2): The function returns `Err` when `depth > MAX_POLICY_EXTENDS_DEPTH` (i.e., `depth > 32`), guaranteeing termination even without cycles. Note: this allows up to 33 levels of nesting (depth 0..=32) before rejection.
3. **Visited set monotonicity** (P3.3): The visited set grows on every recursive call (a key is inserted before recursion).
4. **Termination** (P3.4): The function terminates on all inputs (well-founded on `MAX_POLICY_EXTENDS_DEPTH - depth`).
5. **No silent skip** (P3.5): If a parent policy is reachable and non-cyclic, it is merged into the result.

### Code Complexity Assessment

- **LOC**: ~45 (the recursive function itself, lines 1420-1465)
- **Traits**: `PolicyResolver` trait (abstract over for verification, treat as function parameter)
- **Generics**: `&impl PolicyResolver`
- **Async**: None (this is sync resolution)
- **Unsafe**: None
- **External deps**: `HashSet<String>` (Aeneas support is partial; may need sorted `Vec` fallback), `serde_yaml` (called via `from_yaml_unvalidated` inside the function -- this must be factored out for Aeneas extraction)
- **Parameters**: `(yaml, location, resolver, visited, depth, validation)` -- 6 params; the pure recursive core only needs `(resolved_keys, visited, depth)` after abstracting away YAML parsing
- **Control flow**: Single `if let` with recursive call, guarded by depth and visited checks

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4. The recursive structure maps naturally to structural induction. The visited set is a finite set with insertion; the depth is a decreasing natural number.

**Alternative**: Logos/Z3 can encode the termination argument as a temporal formula with a bounded model.

### Estimated Effort

- Extract recursive core (abstract away YAML parsing and PolicyResolver): 1 day
- Aeneas extraction: 0.5 day
- Proof of P3.1 + P3.2 + P3.4 (cycle detection + depth bound + termination): 2-3 days
- Proof of P3.3 (visited set monotonicity): 0.5 day
- **Total: 3-5 days**

---

## Target 4: Ed25519 Signing Interface

**Priority Score: 20** (Security: 5, Feasibility: 4)

### Component Description

`crates/libs/hush-core/src/signing.rs` provides a thin wrapper around ed25519-dalek for key generation, signing, and verification. It includes `Keypair`, `PublicKey`, `Signature` types and serialization round-trips (hex, serde). The `Signer` trait abstracts over key storage backends (in-memory, TPM). Note: the inherent `Keypair::sign()` returns `Signature` (infallible), while `Signer::sign()` returns `Result<Signature>` (fallible for TPM backends).

A bug in the serialization/deserialization layer could cause keys to be silently corrupted, signatures to fail verification despite being valid, or -- worst case -- different keys to appear equivalent.

### Correctness Properties

1. **From-seed determinism** (P4.1): `Keypair::from_seed(s).public_key() = Keypair::from_seed(s).public_key()` for all seeds `s`.
2. **Public key round-trip** (P4.2): `PublicKey::from_bytes(pk.as_bytes()) = Ok(pk)`.
3. **Signature round-trip** (P4.3): `Signature::from_hex(sig.to_hex()) = Ok(sig)`.
4. **Sign-verify round-trip** (P4.4): `keypair.public_key().verify(msg, &keypair.sign(msg)) = true` (axiomatic on ed25519-dalek). This uses the inherent `Keypair::sign` which is infallible.
5. **Cross-format consistency** (P4.5): `PublicKey::from_hex(pk.to_hex()) = PublicKey::from_bytes(pk.as_bytes())`.
6. **ZeroizeOnDrop** (P4.6): Private key material is zeroed when `Keypair` is dropped. (Not provable via Aeneas; verified via code review of ed25519-dalek dependency.)

### Code Complexity Assessment

- **LOC**: 336
- **Traits**: `Signer`, `Serialize`, `Deserialize` (custom serde modules)
- **Generics**: None
- **Async**: None
- **Unsafe**: None in this file (ed25519-dalek has unsafe internally)
- **External deps**: `ed25519_dalek` (axiomatize), `hex` (pure, small), `rand_core` (for generation only)
- **Control flow**: Straightforward constructors and conversions

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4 with axiomatic crypto (see [Aeneas Pipeline, Section 5](./aeneas-pipeline.md#5-handling-crypto-axiomatically)). The interface layer is pure; the crypto operations are axioms.

**Complementary**: Differential testing of hex round-trips against a Python reference implementation.

### Estimated Effort

- Axiom set definition: 1 day
- Aeneas extraction of interface layer: 1 day
- Proofs of P4.1-P4.5: 3-4 days
- **Total: 1 week**

---

## Target 5: Receipt Canonical JSON

**Priority Score: 20** (Security: 5, Feasibility: 4)

### Component Description

`crates/libs/hush-core/src/canonical.rs` implements RFC 8785 (JSON Canonicalization Scheme / JCS). `crates/libs/hush-core/src/receipt.rs` uses it to produce the byte sequence that is signed. Together, they ensure that the same receipt always produces the same bytes, and therefore the same signature.

A bug in canonicalization (e.g., non-deterministic key ordering, incorrect number formatting) would cause cross-language signature mismatches or, worse, allow two semantically-identical receipts to have different hashes, breaking Merkle tree inclusion.

### Correctness Properties

1. **Determinism** (P5.1): `canonicalize(v) = canonicalize(v)` for all JSON values `v`.
2. **Key ordering** (P5.2): Object keys are sorted by UTF-16 code unit comparison per RFC 8785.
3. **Number normalization** (P5.3): `-0` becomes `0`. Scientific notation used iff `abs(v) < 1e-6 || abs(v) >= 1e21`. No trailing zeros.
4. **String escaping** (P5.4): Control characters are escaped. Only `\b`, `\f`, `\n`, `\r`, `\t`, `\"`, `\\` use shorthand; others use `\uXXXX`.
5. **Cross-language agreement** (P5.5): `canonicalize(v)` in Rust produces byte-identical output to `JSON.stringify` (with sorted keys) in JavaScript for the same JSON value.
6. **Receipt signing coverage** (P5.6): `SignedReceipt::sign` signs `receipt.to_canonical_json()`, so any mutation to the receipt changes the signed bytes (under canonicalize injectivity).

### Code Complexity Assessment

- **LOC**: 358 (canonical.rs) + ~50 (receipt.rs signing path)
- **Traits**: None in canonical.rs
- **Generics**: None
- **Async**: None
- **Unsafe**: None
- **External deps**: `serde_json::Value` (input type; structurally simple), `ryu` (float formatting; pure, deterministic)
- **Control flow**: Recursive match on JSON value variants, string iteration for escaping, float formatting with case analysis

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4 for P5.1-P5.4. The canonical.rs module is pure recursive. The main challenge is modeling `serde_json::Value` as an algebraic datatype in Lean 4.

**Complementary**: Differential testing (primary tool for P5.5). Run the RFC 8785 test vectors through Rust, TypeScript, Python, and Go implementations. Assert byte-identical output. This is already partially done in the existing test suite (see `jcs_vector_*` tests).

### Estimated Effort

- Model `serde_json::Value` as Lean inductive type: 1 day
- Aeneas extraction of `canonicalize`: 2 days (may need to adapt `ryu` usage)
- Proof of P5.1 (determinism): 1 day
- Proof of P5.2 (key ordering): 2 days (UTF-16 comparison requires careful encoding)
- Proofs of P5.3-P5.4: 2 days
- Cross-language differential test harness: 1 day (testing, not formal proof)
- **Total: 1-2 weeks**

---

## Target 6: Policy Merge (`extends`)

**Priority Score: 15** (Security: 5, Feasibility: 3)

### Component Description

`GuardConfigs::merge_with` in `crates/libs/clawdstrike/src/policy.rs:280-368` and the individual guard config `merge_with` methods implement the `extends` inheritance system. A child policy can extend a parent, selectively overriding, adding, or removing guard configurations. The merge logic differs by guard type:

- **ForbiddenPath**: `additional_patterns` added, `remove_patterns` removed, exceptions unioned
- **Egress**: `additional_allow`/`additional_block` added to base, `remove_allow`/`remove_block` applied, then non-empty child `allow`/`block` lists **replace** the result (order matters: additions/removals are applied first, then overwritten if child defines its own list)
- **McpTool, SecretLeak**: Similar additive/subtractive merge
- **ShellCommand, PatchIntegrity, PromptInjection, Jailbreak**: Child replaces parent (simple override)
- **Custom guards**: Child list replaces parent list if non-empty

A bug in merge could silently drop a forbidden path pattern from a `strict` parent when a child extends it, or could fail to apply a `remove_patterns` directive, leaving a supposedly-removed restriction in place.

### Correctness Properties

1. **Forbidden path monotonicity** (P6.1): If the base policy forbids pattern `P` and the child does not have `P` in `remove_patterns`, then the merged policy also forbids `P`.
2. **Remove effectiveness** (P6.2): If the child has pattern `P` in `remove_patterns`, then `P` does not appear in the merged forbidden patterns.
3. **Addition effectiveness** (P6.3): If the child has pattern `P` in `additional_patterns`, then `P` appears in the merged forbidden patterns (unless also in `remove_patterns`, which is applied after addition).
4. **Exception union** (P6.4): `merged.exceptions` is a superset of both `base.exceptions` and `child.exceptions`.
5. **Override semantics** (P6.5): For simple-override guards (shell_command, jailbreak, etc.), if the child defines the guard, the child's config is used; otherwise the parent's config is used.
6. **Merge determinism** (P6.6): `base.merge_with(child)` is deterministic.
7. **Egress block union** (P6.7): For egress merge, `additional_block` entries are always added to the block list.

### Code Complexity Assessment

- **LOC**: ~89 (GuardConfigs::merge_with, lines 280-368) + ~43 (ForbiddenPathConfig::merge_with, lines 139-181) + ~42 (EgressAllowlistConfig::merge_with, lines 78-119) + ~25 each for other configs = ~300 total
- **Traits**: None (method on structs)
- **Generics**: None
- **Async**: None
- **Unsafe**: None
- **External deps**: `serde` types as fields, `Vec<String>` operations
- **Control flow**: Nested `match` on `(Option, Option)` pairs, `Vec::contains`, `Vec::retain`, `Vec::push`
- **Complication**: 13 guard-specific merge strategies (4 deep-merge, 7 child-overrides, 1 spider_sense with `merge_with_present_fields`, 1 custom list replacement), `#[cfg(feature = "full")]` and `#[cfg(all(feature = "policy-event", not(feature = "full")))]` conditionals for spider_sense

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4 for the extracted merge core. Each guard's merge function can be verified independently.

**Secondary**: Logos/Z3 for the monotonicity property, encoding it as: `F_base(P) AND NOT remove(P) => F_merged(P)` (base prohibition persists unless explicitly removed).

**Tertiary**: Property testing with `proptest` as a practical supplement, generating random base/child config pairs and checking invariants.

### Estimated Effort

- Extract merge functions into `core/merge.rs`: 2 days
- Aeneas extraction: 1-2 days (Vec operations may need adaptation)
- Proof of P6.1 (forbidden path monotonicity): 3-4 days
- Proofs of P6.2-P6.4: 3-4 days
- Proofs of P6.5-P6.7: 2-3 days
- **Total: 2-3 weeks**

---

## Target 7: ForbiddenPath Symlink Safety

**Priority Score: 15** (Security: 5, Feasibility: 3)

### Component Description

`ForbiddenPathGuard::check` in `crates/libs/clawdstrike/src/guards/forbidden_path.rs:287+` checks whether a file access path matches a forbidden pattern. It uses `normalize_path_for_policy` (from `path_normalization.rs`) which resolves symlinks via `std::fs::canonicalize` when the path exists on disk.

The security concern: an attacker could create a symlink at an allowed path pointing to a forbidden path (e.g., `./safe-link -> /home/user/.ssh/id_rsa`). The guard must check the resolved target, not just the lexical path.

### Correctness Properties

1. **Resolved path check** (P7.1): If the resolved (canonicalized) path matches a forbidden pattern, the action is blocked, regardless of the original lexical path.
2. **Exception on resolved path** (P7.2): Exceptions must match the resolved path, not the lexical path, to prevent symlink bypass of forbidden patterns.
3. **Lexical fallback** (P7.3): If the path does not exist on disk (canonicalize fails), the lexical path is used. The guard must still block if the lexical path matches.
4. **Glob pattern matching** (P7.4): `glob::Pattern::matches_path` is called correctly on the normalized path.

### Code Complexity Assessment

- **LOC**: ~250 (forbidden_path.rs check logic + path_normalization.rs)
- **Traits**: `Guard` (async trait)
- **Async**: Yes (the `check` method is async, though it does no I/O beyond `canonicalize`)
- **Unsafe**: None
- **External deps**: `glob::Pattern`, `std::fs::canonicalize` (I/O)
- **Complication**: Filesystem interaction (canonicalize) makes this hard to verify formally. The security property depends on OS behavior.

### Recommended Verification Tool

**Primary**: Aeneas/Lean 4 for the pattern-matching logic, with the filesystem interaction mocked as a function parameter.

**Complementary**: Property testing with a controlled filesystem (tmpdir with symlinks) to exercise P7.1 and P7.2. Integration testing is essential here.

### Estimated Effort

- Extract pattern matching logic (abstract over canonicalize): 2 days
- Aeneas extraction: 2 days
- Proof of P7.1 under abstract filesystem model: 3-4 days
- Integration test harness with symlinks: 2 days
- **Total: 2 weeks**

---

## Target 8: Egress Allowlist Intersection

**Priority Score: 12** (Security: 4, Feasibility: 3)

### Component Description

`EgressAllowlistConfig::intersect_with` in `crates/libs/clawdstrike/src/guards/egress_allowlist.rs:128-168` computes the most restrictive combination of two egress configs (base policy + enclave policy). Allowlists are intersected, blocklists are unioned, and the stricter default action wins.

The intersection of glob-based domain patterns is inherently approximate. The code uses `representative_domain` to generate sample domains from patterns and checks cross-matching, falling back to pattern specificity comparison when both patterns match each other's samples.

### Correctness Properties

1. **Block union** (P8.1): `output.block` is a superset of `self.block` union `other.block`.
2. **Stricter default** (P8.2): `stricter_action(a, b)` returns `Block` if either input is `Block`, `Log` if either is `Log`, else `Allow`.
3. **Disabled identity** (P8.3): If one side is `enabled: false`, the other side is returned unchanged.
4. **Allow intersection conservatism** (P8.4): Every pattern in `output.allow` matches a subset of domains matched by some pattern in `self.allow` AND some pattern in `other.allow`.
5. **Intersection soundness** (P8.5): `intersect_domain_patterns` returns `Some(p)` only if `p` matches a subset of the intersection of the two input patterns' matched domains. (This is approximate due to glob complexity.)

### Code Complexity Assessment

- **LOC**: ~180 (intersect_with + helper functions)
- **Traits**: None
- **Generics**: None
- **Async**: None
- **Unsafe**: None
- **External deps**: `DomainPolicy` from `hush-proxy` (glob matching)
- **Complication**: Glob pattern intersection is undecidable in the general case. The code uses heuristics (representative domains, specificity). Formally verifying the approximation is possible but the guarantee is weaker than exact intersection.

### Recommended Verification Tool

**Primary**: Logos/Z3 for P8.1-P8.3 (set properties, boolean lattice). These are simple first-order logic properties.

**Secondary**: Property testing for P8.4-P8.5, generating random domain patterns and checking that the intersection result is conservative.

**Not recommended**: Aeneas for the glob-matching heuristics (too entangled with external crate).

### Estimated Effort

- Z3 encoding of P8.1-P8.3: 3-4 days
- Extract `stricter_action` for Aeneas: 0.5 day (trivial function)
- Property test harness for P8.4-P8.5: 3-4 days
- **Total: 2 weeks**

---

## Target 9: Shell Command Path Extraction

**Priority Score: 8** (Security: 4, Feasibility: 2)

### Component Description

`ShellCommandGuard` in `crates/libs/clawdstrike/src/guards/shell_command.rs` checks shell commands against forbidden regex patterns and extracts file paths from command strings for forbidden-path checking. The path extraction is heuristic: it splits the command using a custom shlex-like splitter and applies regex patterns to identify potential paths.

### Correctness Properties

1. **Regex match soundness** (P9.1): If a command matches a forbidden regex (e.g., `rm -rf / *`), the action is blocked.
2. **Path extraction coverage** (P9.2): Common path patterns in shell commands (quoted paths, paths after common flags like `-f`, `-o`, etc.) are extracted.
3. **No false negatives on critical patterns** (P9.3): The default forbidden patterns (`rm -rf /`, `curl | bash`, reverse shells, base64 exfil) always trigger on their intended inputs.

### Code Complexity Assessment

- **LOC**: 478
- **Traits**: `Guard` (async trait)
- **Async**: Yes (though no actual I/O)
- **Unsafe**: None
- **External deps**: `regex::Regex` (fundamental to behavior)
- **Complication**: Shell command parsing is inherently ambiguous. The shlex splitter is heuristic. Regex patterns are specified as strings and compiled at runtime. Formal verification of "does this regex match this class of inputs" is possible in theory (regex -> NFA -> equivalence checking) but extremely expensive.

### Recommended Verification Tool

**Primary**: Differential testing / fuzzing. Generate shell commands via grammar-based fuzzing, check that dangerous commands are caught. This is more practical than formal verification for regex-based heuristics.

**Secondary**: Manual audit of the default regex patterns against known bypass techniques.

**Not recommended**: Aeneas (regex crate is too complex) or Z3 (regex constraint solving is possible but not worth the effort for heuristic patterns).

### Estimated Effort

- Grammar-based fuzz harness: 3-4 days
- Regex pattern audit: 1-2 days
- **Total: 1 week (testing, not formal verification)**

---

## Target 10: Posture State Machine

**Priority Score: 12** (Security: 4, Feasibility: 3)

> Scoring note: Security raised from 3 to 4 because a posture bug could grant elevated capabilities (e.g., shell access in a restricted state) or prevent proper state demotion after violations.

### Component Description

The posture system in `crates/libs/clawdstrike/src/posture.rs` defines a state machine with named states, transitions triggered by events (violations, approvals, budget exhaustion), capabilities per state, and budget counters. The runtime evaluates the posture state on each action, transitioning states and adjusting available capabilities as warranted.

### Correctness Properties

1. **State reachability** (P10.1): Every state in `PostureConfig.states` is reachable from the initial state via some sequence of transitions.
2. **No stuck states** (P10.2): The state machine does not have dead-end states (states with no outgoing transitions) unless they are terminal by design.
3. **Budget monotonicity** (P10.3): Budget counters only decrease (never increase without a state transition that resets them).
4. **Capability restriction** (P10.4): A capability not listed in the current state's capabilities is always denied.
5. **Transition determinism** (P10.5): For a given (state, trigger) pair, at most one transition fires (or the behavior is well-defined when multiple match).

### Code Complexity Assessment

- **LOC**: ~250 (posture.rs config types + validation)
- **Traits**: None for config; runtime uses mutable state
- **Generics**: None
- **Async**: Runtime evaluation is async
- **Unsafe**: None
- **External deps**: `chrono`, `HashMap`, `BTreeMap`
- **Complication**: The state machine is dynamic (defined in YAML, not compiled). Verification must reason about arbitrary configs, not a fixed state machine.

### Recommended Verification Tool

**Primary**: TLA+ or Logos temporal logic. State machines are the canonical use case for temporal model checking. The posture config can be translated to a TLA+ spec, and temporal properties (reachability, liveness, deadlock freedom) can be checked.

**Secondary**: Property testing -- generate random posture configs and simulate transitions, checking that invariants hold.

**Not recommended**: Aeneas (mutable state, timestamps, budget counters make this a poor fit).

### Estimated Effort

- TLA+ specification: 3-4 days
- Model checking P10.1-P10.3: 2-3 days
- Model checking P10.4-P10.5: 2-3 days
- **Total: 1.5-2 weeks**

---

## Target 11: Async Guard Runtime

**Priority Score: 3** (Security: 3, Feasibility: 1)

### Component Description

The async guard runtime in `crates/libs/clawdstrike/src/async_guards/` provides timeout management, caching, circuit breaking, rate limiting, and retry logic for guards that make external HTTP calls (VirusTotal, Snyk, Safe Browsing). It uses `tokio` extensively, including `tokio::time::timeout`, `Arc<Mutex>`, and async trait objects.

### Correctness Properties

1. **Timeout enforcement** (P11.1): If an async guard exceeds its configured timeout, the `on_timeout` behavior is applied (Warn or Deny).
2. **Circuit breaker correctness** (P11.2): After N consecutive failures, the circuit opens and subsequent calls are short-circuited until the reset timer expires.
3. **Cache consistency** (P11.3): Cache entries expire after TTL and do not exceed `max_size_bytes`.
4. **Rate limit enforcement** (P11.4): Calls are throttled according to the configured rate limit.

### Code Complexity Assessment

- **LOC**: ~800 across 6 files
- **Traits**: `AsyncGuard` (async trait), `HttpClient` (trait object)
- **Async**: Pervasive
- **Unsafe**: None
- **External deps**: `tokio`, `reqwest`, `async-trait`
- **Complication**: Concurrent async code with shared mutable state. This is fundamentally difficult to verify formally.

### Recommended Verification Tool

**Primary**: Integration testing with controlled async runtimes and mock HTTP servers. Use `tokio::time::pause()` for deterministic timeout testing.

**Not recommended**: Any formal verification tool. Async Rust with tokio is beyond the reach of current verification tools.

### Estimated Effort

- Integration test improvements: 1-2 weeks
- **Formal verification: Not feasible with current tools.**

---

## Target 12: Origin Context / Enclave Resolution

**Priority Score: 3** (Security: 3, Feasibility: 1)

### Component Description

Origin resolution (`crates/libs/clawdstrike/src/origin.rs`, `enclave.rs`, `engine.rs:455+`) determines which enclave profile applies based on the incoming request's origin context (Slack channel, GitHub repo, etc.). It involves pattern matching against origin matchers, default behavior computation, bridge policy evaluation, and mutable runtime state.

### Correctness Properties

1. **Default deny** (P12.1): When `origins` is configured and no origin matches, the effective behavior is determined by `effective_default_behavior()`.
2. **Matcher precedence** (P12.2): More specific matchers take precedence over wildcards.
3. **Bridge policy enforcement** (P12.3): Cross-origin transitions respect bridge policies.

### Code Complexity Assessment

- **LOC**: ~1500 across origin.rs, enclave.rs, origin_runtime.rs
- **Traits**: Multiple trait objects
- **Async**: Yes (origin resolution is async)
- **Unsafe**: None
- **External deps**: `Arc<RwLock>`, complex state machine
- **Complication**: Deep integration with the engine's async evaluation pipeline. Mutable runtime state for session tracking.

### Recommended Verification Tool

**Primary**: Integration testing and code review.

**Not recommended**: Formal verification. The code is too entangled with async runtime and mutable state.

### Estimated Effort

- **Formal verification: Not feasible with current tools.**

---

## Target 13: Fail-Closed on Config Error

**Priority Score: 20** (Security: 5, Feasibility: 4)

> This target is listed as core property P2 in [INDEX.md](./INDEX.md) and [ROADMAP.md](./ROADMAP.md) but was missing from this document.

### Component Description

`check_action_report` in `crates/libs/clawdstrike/src/engine.rs:435-453` begins with an unconditional check of `self.config_error`. If `config_error` is `Some`, every call returns `Err(Error::ConfigError(...))` before any guard evaluation occurs. Similarly, `async_guard_init_error` at line 443 produces the same early-exit.

This is a foundational security property: a misconfigured engine must never silently allow actions.

### Correctness Properties

1. **Config error denial** (P13.1): `config_error.is_some() => check_action_report(action, context).is_err()` for all actions and contexts.
2. **Async init error denial** (P13.2): `async_guard_init_error.is_some() => check_action_report(action, context).is_err()` for all actions and contexts.
3. **Early exit** (P13.3): No guard is evaluated when either error is present. This means the error check dominates all other logic.

### Code Complexity Assessment

- **LOC**: ~6 (the two `if let` checks at lines 440-445)
- **Async**: The function is async, but the fail-closed check is synchronous (no `.await` before the return)
- **Complication**: Minimal. This is a syntactic property of control flow, not a semantic property of data.

### Recommended Verification Tool

**Primary**: Code review + structural assertion. This property is so simple that it can be verified by inspection or a trivial Lean 4 theorem. It can also be Aeneas-verified if the config_error field is included in the core module.

**Secondary**: Integration test: set `config_error = Some("test")`, assert all check_action variants return `Err`.

### Estimated Effort

- Lean 4 theorem (if Aeneas-extracted): 0.5 day
- Integration test: 0.5 day
- **Total: 1 day**

---

## Summary Table

| # | Target | Security | Feasibility | Priority | Recommended Tool | Estimated Effort |
|---|--------|----------|-------------|----------|-----------------|-----------------|
| 1 | Guard aggregation (`aggregate_overall`) | 5 | 5 | **25** | Aeneas/Lean 4 | 2-3 days |
| 2 | Merkle tree inclusion proofs | 4 | 5 | **20** | Aeneas/Lean 4 | 1-2 weeks |
| 3 | Policy cycle detection | 4 | 5 | **20** | Aeneas/Lean 4 | 3-5 days |
| 4 | Ed25519 signing interface | 5 | 4 | **20** | Aeneas/Lean 4 (axiomatic crypto) | 1 week |
| 5 | Receipt canonical JSON | 5 | 4 | **20** | Aeneas/Lean 4 + differential testing | 1-2 weeks |
| 13 | Fail-closed on config error | 5 | 4 | **20** | Code review + Lean 4 / integration test | 1 day |
| 6 | Policy merge (`extends`) | 5 | 3 | **15** | Aeneas/Lean 4 + Logos/Z3 | 2-3 weeks |
| 7 | ForbiddenPath symlink safety | 5 | 3 | **15** | Aeneas/Lean 4 (abstract FS) + integration tests | 2 weeks |
| 8 | Egress allowlist intersection | 4 | 3 | **12** | Logos/Z3 + property testing | 2 weeks |
| 10 | Posture state machine | 4 | 3 | **12** | TLA+ / Logos temporal logic | 1.5-2 weeks |
| 9 | Shell command path extraction | 4 | 2 | **8** | Differential testing / fuzzing | 1 week |
| 11 | Async guard runtime | 3 | 1 | **3** | Integration testing only | N/A (testing) |
| 12 | Origin context / enclave resolution | 3 | 1 | **3** | Integration testing only | N/A (testing) |

---

## Recommended Order of Attack

Sequence optimizes for early wins (building pipeline confidence) before harder targets.

| Wave | Targets | Calendar | Rationale |
|------|---------|----------|-----------|
| **1: Quick Wins** | Aggregation (P25), severity (free), fail-closed (P20), cycle detection (P20) | Weeks 1-2 | Validates the full pipeline. If aggregation takes >1 week, reassess the initiative. |
| **2: Crypto** | Merkle tree (P20), Ed25519 interface (P20) | Weeks 3-5 | Classic targets with prior art. Establishes axiomatic crypto framework. |
| **3: Policy** | Canonical JSON (P20), policy merge (P15) | Weeks 6-10 | Merge monotonicity is the highest-impact result for users. |
| **4: Defense in Depth** | Symlink safety (P15), egress intersection (P12), posture TLA+ (P12) | Weeks 11-15 | Abstract filesystem, set-theoretic properties, state machine checking. |
| **5: Testing** | Shell command fuzzing, async/origin integration tests | Ongoing | Not amenable to formal verification. |

---

## Effort Summary

| Wave | Targets | Calendar Time | Person-Weeks |
|------|---------|---------------|-------------|
| Wave 1 | Aggregation, cycle detection | 2 weeks | 2 |
| Wave 2 | Merkle tree, signing interface | 3 weeks | 3 |
| Wave 3 | Canonical JSON, policy merge | 5 weeks | 5 |
| Wave 4 | Symlink safety, egress intersection, posture TLA+ | 5 weeks | 6 |
| Wave 5 | Shell fuzzing, testing | Ongoing | 1+ |
| **Total** | | **~15 weeks** | **~17 person-weeks** |

Approximately one senior engineer full-time for one quarter. The first meaningful result (proven deny monotonicity) arrives in week 1.
