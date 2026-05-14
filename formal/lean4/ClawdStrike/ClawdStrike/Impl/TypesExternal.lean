-- External types for the Aeneas-generated ClawdStrike implementation.
-- Created from TypesExternal_Template.lean with axiom-based definitions.
import Aeneas
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/-- [core::iter::adapters::skip::Skip]
    Source: '/rustc/library/core/src/iter/adapters/skip.rs', lines 21:0-21:18
    Name pattern: [core::iter::adapters::skip::Skip] -/
@[rust_type "core::iter::adapters::skip::Skip"]
axiom core.iter.adapters.skip.Skip (I : Type) : Type

/-- [std::collections::hash::map::HashMap]
    Source: '/rustc/library/std/src/collections/hash/map.rs', lines 247:0-252:1
    Name pattern: [std::collections::hash::map::HashMap] -/
@[rust_type "std::collections::hash::map::HashMap"]
axiom std.collections.hash.map.HashMap (K : Type) (V : Type) (S : Type) (A :
  Type) : Type

/-- [std::hash::random::RandomState]
    Source: '/rustc/library/std/src/hash/random.rs', lines 35:0-35:22
    Name pattern: [std::hash::random::RandomState] -/
@[rust_type "std::hash::random::RandomState"]
axiom std.hash.random.RandomState : Type

/-- [std::collections::hash::set::HashSet]
    Source: '/rustc/library/std/src/collections/hash/set.rs', lines 126:0-130:1
    Name pattern: [std::collections::hash::set::HashSet] -/
@[rust_type "std::collections::hash::set::HashSet"]
axiom std.collections.hash.set.HashSet (T : Type) (S : Type) (A : Type) : Type

/-- [std::hash::random::DefaultHasher]
    Source: '/rustc/library/std/src/hash/random.rs', lines 94:0-94:24
    Name pattern: [std::hash::random::DefaultHasher] -/
@[rust_type "std::hash::random::DefaultHasher"]
axiom std.hash.random.DefaultHasher : Type
