-- External functions for the Aeneas-generated ClawdStrike implementation.
-- Created from FunsExternal_Template.lean with axiom-based stubs.
-- These axioms represent Rust standard library functions that Aeneas
-- could not translate directly.
import Aeneas
import ClawdStrike.Impl.Types
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000
open clawdstrike

/-- [core::borrow::{core::borrow::Borrow<T> for T}::borrow]:
    Source: '/rustc/library/core/src/borrow.rs', lines 214:4-214:26
    Name pattern: [core::borrow::{core::borrow::Borrow<@T, @T>}::borrow] -/
@[rust_fun "core::borrow::{core::borrow::Borrow<@T, @T>}::borrow"]
axiom core.borrow.Borrow.Blanket.borrow {T : Type} : T → Result T

/-- [core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field2_finish]:
    Source: '/rustc/library/core/src/fmt/mod.rs', lines 2466:4-2473:15
    Name pattern: [core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field2_finish] -/
@[rust_fun "core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field2_finish"]
axiom core.fmt.Formatter.debug_struct_field2_finish
  :
  core.fmt.Formatter → Str → Str → Dyn (fun _dyn => core.fmt.Debug _dyn)
    → Str → Dyn (fun _dyn => core.fmt.Debug _dyn) → Result
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field5_finish]:
    Source: '/rustc/library/core/src/fmt/mod.rs', lines 2532:4-2545:15
    Name pattern: [core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field5_finish] -/
@[rust_fun "core::fmt::{core::fmt::Formatter<'a>}::debug_struct_field5_finish"]
axiom core.fmt.Formatter.debug_struct_field5_finish
  :
  core.fmt.Formatter → Str → Str → Dyn (fun _dyn => core.fmt.Debug _dyn)
    → Str → Dyn (fun _dyn => core.fmt.Debug _dyn) → Str → Dyn (fun _dyn
    => core.fmt.Debug _dyn) → Str → Dyn (fun _dyn => core.fmt.Debug _dyn)
    → Str → Dyn (fun _dyn => core.fmt.Debug _dyn) → Result
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [core::fmt::{core::fmt::Display for str}::fmt]:
    Source: '/rustc/library/core/src/fmt/mod.rs', lines 2959:4-2959:50
    Name pattern: [core::fmt::{core::fmt::Display<str>}::fmt] -/
@[rust_fun "core::fmt::{core::fmt::Display<str>}::fmt"]
axiom Str.Insts.CoreFmtDisplay.fmt
  :
  Str → core.fmt.Formatter → Result ((core.result.Result Unit
    core.fmt.Error) × core.fmt.Formatter)

/-- [core::hash::impls::{core::hash::Hash for isize}::hash]:
    Source: '/rustc/library/core/src/hash/mod.rs', lines 812:16-812:56
    Name pattern: [core::hash::impls::{core::hash::Hash<isize>}::hash] -/
@[rust_fun "core::hash::impls::{core::hash::Hash<isize>}::hash"]
axiom Isize.Insts.CoreHashHash.hash
  {H : Type} (HasherInst : core.hash.Hasher H) : Std.Isize → H → Result H

/-- [core::hash::impls::{core::hash::Hash for str}::hash]:
    Source: '/rustc/library/core/src/hash/mod.rs', lines 864:8-864:48
    Name pattern: [core::hash::impls::{core::hash::Hash<str>}::hash] -/
@[rust_fun "core::hash::impls::{core::hash::Hash<str>}::hash"]
axiom Str.Insts.CoreHashHash.hash
  {H : Type} (HasherInst : core.hash.Hasher H) : Str → H → Result H

/-- [core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<(usize, Clause0_Item)> for core::iter::adapters::enumerate::Enumerate<I>}::next] -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::next"]
axiom
  core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.next
  {I : Type} {Clause0_Item : Type} (traitsiteratorIteratorInst :
  core.iter.traits.iterator.Iterator I Clause0_Item) :
  core.iter.adapters.enumerate.Enumerate I → Result ((Option (Std.Usize ×
    Clause0_Item)) × (core.iter.adapters.enumerate.Enumerate I))

/-- [core::iter::adapters::enumerate::...::collect] -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::collect"]
axiom
  core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.collect
  {I : Type} {B : Type} {Clause0_Item : Type} (traitsiteratorIteratorInst :
  core.iter.traits.iterator.Iterator I Clause0_Item)
  (traitscollectFromIteratorBPairUsizeClause0_ItemInst :
  core.iter.traits.collect.FromIterator B (Std.Usize × Clause0_Item)) :
  core.iter.adapters.enumerate.Enumerate I → Result B

/-- [core::iter::adapters::enumerate::...::skip] -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::skip"]
axiom
  core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.skip
  {I : Type} {Clause0_Item : Type} (traitsiteratorIteratorInst :
  core.iter.traits.iterator.Iterator I Clause0_Item) :
  core.iter.adapters.enumerate.Enumerate I → Std.Usize → Result
    (core.iter.adapters.skip.Skip (core.iter.adapters.enumerate.Enumerate I))

/-- [core::iter::adapters::enumerate::...::enumerate] -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::enumerate"]
axiom
  core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.enumerate
  {I : Type} {Clause0_Item : Type} (traitsiteratorIteratorInst :
  core.iter.traits.iterator.Iterator I Clause0_Item) :
  core.iter.adapters.enumerate.Enumerate I → Result
    (core.iter.adapters.enumerate.Enumerate
    (core.iter.adapters.enumerate.Enumerate I))

/-- [core::iter::adapters::enumerate::...::map] -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::map"]
axiom
  core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.map
  {I : Type} {B : Type} {F : Type} {Clause0_Item : Type}
  (traitsiteratorIteratorInst : core.iter.traits.iterator.Iterator I
  Clause0_Item) (opsfunctionFnMutFTuplePairUsizeClause0_ItemBInst :
  core.ops.function.FnMut F (Std.Usize × Clause0_Item) B) :
  core.iter.adapters.enumerate.Enumerate I → F → Result
    (core.iter.adapters.map.Map (core.iter.adapters.enumerate.Enumerate I) F)

/-- [core::iter::adapters::map::...::collect] -/
@[rust_fun
  "core::iter::adapters::map::{core::iter::traits::iterator::Iterator<core::iter::adapters::map::Map<@I, @F>, @B>}::collect"]
axiom core.iter.adapters.map.Map.Insts.CoreIterTraitsIteratorIterator.collect
  {B : Type} {I : Type} {F : Type} {B1 : Type} {Clause0_Item : Type}
  (traitsiteratorIteratorInst : core.iter.traits.iterator.Iterator I
  Clause0_Item) (opsfunctionFnMutFTupleClause0_ItemBInst :
  core.ops.function.FnMut F Clause0_Item B) (traitscollectFromIteratorInst :
  core.iter.traits.collect.FromIterator B1 B) :
  core.iter.adapters.map.Map I F → Result B1

/-- [core::iter::adapters::skip::...::next] -/
@[rust_fun
  "core::iter::adapters::skip::{core::iter::traits::iterator::Iterator<core::iter::adapters::skip::Skip<@I>, @Clause0_Item>}::next"]
axiom core.iter.adapters.skip.Skip.Insts.CoreIterTraitsIteratorIterator.next
  {I : Type} {Clause0_Item : Type} (traitsiteratorIteratorInst :
  core.iter.traits.iterator.Iterator I Clause0_Item) :
  core.iter.adapters.skip.Skip I → Result ((Option Clause0_Item) ×
    (core.iter.adapters.skip.Skip I))

/-- [core::iter::traits::iterator::Iterator::map] -/
@[rust_fun "core::iter::traits::iterator::Iterator::map"]
axiom core.iter.traits.iterator.Iterator.map.default
  {Self : Type} {B : Type} {F : Type} {Clause0_Item : Type} (IteratorInst :
  core.iter.traits.iterator.Iterator Self Clause0_Item)
  (opsfunctionFnMutFTupleClause0_ItemBInst : core.ops.function.FnMut F
  Clause0_Item B) :
  Self → F → Result (core.iter.adapters.map.Map Self F)

/-- [core::iter::traits::iterator::Iterator::enumerate] -/
@[rust_fun "core::iter::traits::iterator::Iterator::enumerate"]
axiom core.iter.traits.iterator.Iterator.enumerate.default
  {Self : Type} {Clause0_Item : Type} (IteratorInst :
  core.iter.traits.iterator.Iterator Self Clause0_Item) :
  Self → Result (core.iter.adapters.enumerate.Enumerate Self)

/-- [core::iter::traits::iterator::Iterator::skip] -/
@[rust_fun "core::iter::traits::iterator::Iterator::skip"]
axiom core.iter.traits.iterator.Iterator.skip.default
  {Self : Type} {Clause0_Item : Type} (IteratorInst :
  core.iter.traits.iterator.Iterator Self Clause0_Item) :
  Self → Std.Usize → Result (core.iter.adapters.skip.Skip Self)

/-- [core::option::{core::option::Option<T>}::or] -/
@[rust_fun "core::option::{core::option::Option<@T>}::or"]
axiom core.option.Option.or
  {T : Type} : Option T → Option T → Result (Option T)

/-- [core::option::{core::option::Option<T>}::or_else] -/
@[rust_fun "core::option::{core::option::Option<@T>}::or_else"]
axiom core.option.Option.or_else
  {T : Type} {F : Type} (opsfunctionFnOnceFTupleOptionInst :
  core.ops.function.FnOnce F Unit (Option T)) :
  Option T → F → Result (Option T)

/-- [core::option::{core::option::Option<&0 (T)>}::copied] -/
@[rust_fun "core::option::{core::option::Option<&'0 @T>}::copied"]
axiom core.option.OptionShared0T.copied
  {T : Type} (markerCopyInst : core.marker.Copy T) :
  Option T → Result (Option T)

/-- [core::option::{core::clone::Clone for core::option::Option<T>}::clone] -/
@[rust_fun
  "core::option::{core::clone::Clone<core::option::Option<@T>>}::clone"]
axiom core.option.Option.Insts.CoreCloneClone.clone
  {T : Type} (cloneCloneInst : core.clone.Clone T) :
  Option T → Result (Option T)

/-- [core::slice::iter::...::collect] -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Iter<'a, @T>, &'a @T>}::collect"]
axiom core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.collect
  {T : Type} {B : Type} (itertraitscollectFromIteratorBSharedATInst :
  core.iter.traits.collect.FromIterator B T) :
  core.slice.iter.Iter T → Result B

/-- [core::slice::iter::...::skip] -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Iter<'a, @T>, &'a @T>}::skip"]
axiom core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.skip
  {T : Type} :
  core.slice.iter.Iter T → Std.Usize → Result (core.iter.adapters.skip.Skip
    (core.slice.iter.Iter T))

/-- [core::slice::iter::...::map] -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Iter<'a, @T>, &'a @T>}::map"]
axiom core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.map
  {T : Type} {B : Type} {F : Type} (opsfunctionFnMutFTupleSharedATBInst :
  core.ops.function.FnMut F T B) :
  core.slice.iter.Iter T → F → Result (core.iter.adapters.map.Map
    (core.slice.iter.Iter T) F)

/-- [core::slice::iter::...::into_iter] -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::collect::IntoIterator<&'a [@T], &'a @T, core::slice::iter::Iter<'a, @T>>}::into_iter"]
axiom
  SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter
  {T : Type} : Slice T → Result (core.slice.iter.Iter T)

/-- [core::str::{str}::is_empty] -/
@[rust_fun "core::str::{str}::is_empty"]
axiom core.str.Str.is_empty : Str → Result Bool

/-- [core::str::traits::{core::cmp::PartialEq<str> for str}::eq] -/
@[rust_fun "core::str::traits::{core::cmp::PartialEq<str, str>}::eq"]
axiom Str.Insts.CoreCmpPartialEqStr.eq : Str → Str → Result Bool

/-- [core::str::traits::{core::cmp::Eq for str}::assert_receiver_is_total_eq] -/
@[rust_fun
  "core::str::traits::{core::cmp::Eq<str>}::assert_receiver_is_total_eq"]
axiom Str.Insts.CoreCmpEq.assert_receiver_is_total_eq : Str → Result Unit

/-- [std::collections::hash::map::HashMap::new] -/
@[rust_fun
  "std::collections::hash::map::{std::collections::hash::map::HashMap<@K, @V, std::hash::random::RandomState, alloc::alloc::Global>}::new"]
axiom std.collections.hash.map.HashMapKVRandomStateGlobal.new
  (K : Type) (V : Type) :
  Result (std.collections.hash.map.HashMap K V std.hash.random.RandomState
    Global)

/-- [std::collections::hash::map::HashMap::get] -/
@[rust_fun
  "std::collections::hash::map::{std::collections::hash::map::HashMap<@K, @V, @S, @A>}::get"]
axiom std.collections.hash.map.HashMap.get
  {K : Type} {V : Type} {S : Type} {A : Type} {Q : Type} {Clause2_Hasher :
  Type} (corecmpEqInst : core.cmp.Eq K) (corehashHashInst : core.hash.Hash K)
  (corehashBuildHasherInst : core.hash.BuildHasher S Clause2_Hasher)
  (coreborrowBorrowInst : core.borrow.Borrow K Q) (corehashHashInst1 :
  core.hash.Hash Q) (corecmpEqInst1 : core.cmp.Eq Q) :
  std.collections.hash.map.HashMap K V S A → Q → Result (Option V)

/-- [std::collections::hash::map::HashMap::insert] -/
@[rust_fun
  "std::collections::hash::map::{std::collections::hash::map::HashMap<@K, @V, @S, @A>}::insert"]
axiom std.collections.hash.map.HashMap.insert
  {K : Type} {V : Type} {S : Type} {A : Type} {Clause2_Hasher : Type}
  (corecmpEqInst : core.cmp.Eq K) (corehashHashInst : core.hash.Hash K)
  (corehashBuildHasherInst : core.hash.BuildHasher S Clause2_Hasher) :
  std.collections.hash.map.HashMap K V S A → K → V → Result ((Option V)
    × (std.collections.hash.map.HashMap K V S A))

/-- [std::collections::hash::set::HashSet::contains] -/
@[rust_fun
  "std::collections::hash::set::{std::collections::hash::set::HashSet<@T, @S, @A>}::contains"]
axiom std.collections.hash.set.HashSet.contains
  {T : Type} {S : Type} {A : Type} {Q : Type} {Clause2_Hasher : Type}
  (corecmpEqInst : core.cmp.Eq T) (corehashHashInst : core.hash.Hash T)
  (corehashBuildHasherInst : core.hash.BuildHasher S Clause2_Hasher)
  (coreborrowBorrowInst : core.borrow.Borrow T Q) (corehashHashInst1 :
  core.hash.Hash Q) (corecmpEqInst1 : core.cmp.Eq Q) :
  std.collections.hash.set.HashSet T S A → Q → Result Bool

/-- [std::hash::random::DefaultHasher::finish] -/
@[rust_fun
  "std::hash::random::{core::hash::Hasher<std::hash::random::DefaultHasher>}::finish"]
axiom std.hash.random.DefaultHasher.Insts.CoreHashHasher.finish
  : std.hash.random.DefaultHasher → Result Std.U64

/-- [std::hash::random::DefaultHasher::write] -/
@[rust_fun
  "std::hash::random::{core::hash::Hasher<std::hash::random::DefaultHasher>}::write"]
axiom std.hash.random.DefaultHasher.Insts.CoreHashHasher.write
  :
  std.hash.random.DefaultHasher → Slice Std.U8 → Result
    std.hash.random.DefaultHasher

/-- [std::hash::random::RandomState::build_hasher] -/
@[rust_fun
  "std::hash::random::{core::hash::BuildHasher<std::hash::random::RandomState, std::hash::random::DefaultHasher>}::build_hasher"]
axiom
  std.hash.random.RandomState.Insts.CoreHashBuildHasherDefaultHasher.build_hasher
  : std.hash.random.RandomState → Result std.hash.random.DefaultHasher

/-- [alloc::str::String::borrow] -/
@[rust_fun
  "alloc::str::{core::borrow::Borrow<alloc::string::String, str>}::borrow"]
axiom alloc.string.String.Insts.CoreBorrowBorrowStr.borrow
  : String → Result Str

/-- [alloc::string::String::eq] -/
@[rust_fun
  "alloc::string::{core::cmp::PartialEq<alloc::string::String, alloc::string::String>}::eq"]
axiom alloc.string.String.Insts.CoreCmpPartialEqString.eq
  : String → String → Result Bool

/-- [alloc::string::String::assert_receiver_is_total_eq] -/
@[rust_fun
  "alloc::string::{core::cmp::Eq<alloc::string::String>}::assert_receiver_is_total_eq"]
axiom alloc.string.String.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : String → Result Unit

/-- [alloc::string::String::clone] -/
@[rust_fun "alloc::string::{core::clone::Clone<alloc::string::String>}::clone"]
axiom alloc.string.String.Insts.CoreCloneClone.clone : String → Result String

/-- [alloc::string::String::Debug::fmt] -/
@[rust_fun "alloc::string::{core::fmt::Debug<alloc::string::String>}::fmt"]
axiom alloc.string.String.Insts.CoreFmtDebug.fmt
  :
  String → core.fmt.Formatter → Result ((core.result.Result Unit
    core.fmt.Error) × core.fmt.Formatter)

/-- [alloc::string::String::Hash::hash] -/
@[rust_fun "alloc::string::{core::hash::Hash<alloc::string::String>}::hash"]
axiom alloc.string.String.Insts.CoreHashHash.hash
  {H : Type} (corehashHasherInst : core.hash.Hasher H) :
  String → H → Result H

/-- [alloc::string::ToString::to_string] -/
@[rust_fun "alloc::string::{alloc::string::ToString<@T>}::to_string"]
axiom alloc.string.ToString.Blanket.to_string
  {T : Type} (corefmtDisplayInst : core.fmt.Display T) : T → Result String

/-- [alloc::string::String::from] -/
@[rust_fun
  "alloc::string::{core::convert::From<alloc::string::String, &'0 str>}::from"]
axiom alloc.string.String.Insts.CoreConvertFromShared0Str.from
  : Str → Result String
