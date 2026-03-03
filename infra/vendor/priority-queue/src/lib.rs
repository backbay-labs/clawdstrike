/*
 *  Copyright 2017 Gianmarco Garrisi and contributors
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version, or (at your option) under the terms
 *  of the Mozilla Public License version 2.0.
 *
 *  ----
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  ----
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public License,
 *  v. 2.0. If a copy of the MPL was not distributed with this file, You can
 *  obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

//! This crate provides 2 main data structures:
//!  *  a [priority queue](PriorityQueue)
//!  *  a [double priority queue](DoublePriorityQueue).
//!
//! Both data structures are backed by an hashmap, allowing
//! to change the priority of an element with some efficient methods in
//! **O(log(N))** time (worst case).
//!
//! The elements (called `Item`s, of type `I`) must implement
//! [`Hash`](https://doc.rust-lang.org/std/hash/trait.Hash.html)
//! and [`Eq`](https://doc.rust-lang.org/std/cmp/trait.Eq.html) traits.
//!
//! This can frequently be achieved by using `#[derive(PartialEq, Eq, Hash)]`.
//! If you implement these yourself, it is important that the following property holds:
//!
//! ```text
//! k1 == k2 -> hash(k1) == hash(k2)
//! ```
//!
//! In other words, if two keys are equal, their hashes must be equal.
//!
//! The priority `P` may be any type that implements
//! [`Ord`](https://doc.rust-lang.org/std/cmp/trait.Ord.html).
//! For reverse order remember the standard wrapper
//! [`Reverse<T>`](https://doc.rust-lang.org/std/cmp/struct.Reverse.html)
//!
//! # Examples
//! ```rust
//! # #[cfg(feature = "std")] {
//! use priority_queue::PriorityQueue;
//!
//! let mut pq = PriorityQueue::new();
//!
//! assert!(pq.is_empty());
//! pq.push("Apples", 5);
//! pq.push("Bananas", 8);
//! pq.push("Strawberries", 23);
//!
//! assert_eq!(pq.peek(), Some((&"Strawberries", &23)));
//!
//! pq.change_priority("Bananas", 25);
//! assert_eq!(pq.peek(), Some((&"Bananas", &25)));
//!
//! for (item, _) in pq.into_sorted_iter() {
//!     println!("{}", item); // Will print Bananas, Strawberries, Apples
//! }
//! # }
//! ```
//!
//! ## Reverse ordering
//! ```rust
//! # #[cfg(feature = "std")] {
//! use priority_queue::PriorityQueue;
//! use std::cmp::Reverse;
//!
//! let mut pq = PriorityQueue::new();
//!
//! assert!(pq.is_empty());
//! pq.push("Apples", Reverse(5));
//! pq.push("Bananas", Reverse(8));
//! pq.push("Strawberries", Reverse(23));
//!
//! assert_eq!(pq.peek(), Some((&"Apples", &Reverse(5))));
//!
//! for (item, _) in pq.into_sorted_iter() {
//!     println!("{}", item); // Will print Apples, Bananas, Strawberries
//! }
//! # }
//! ```
//!
//! # Crate features
//!
//! * **std** - Use the standard library. This enables the creation of queues
//!   with the standard hasher `RandomState` using the `new` and `with_capacity`
//!   static methods.
//!   This feature is **enabled by default** and can be disabled when compiling
//!   for no_std targets.
//! * **serde** - Enables serialization/deserialization using serde
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
pub(crate) mod std {
    pub use ::alloc::collections;
    pub use core::*;
}

pub mod core_iterators;
pub mod double_priority_queue;
pub mod priority_queue;
mod store;

pub use crate::double_priority_queue::DoublePriorityQueue;
pub use crate::priority_queue::PriorityQueue;
use crate::store::log2_fast;

use indexmap::TryReserveError as IndexMapTryReserveError;
use std::collections::TryReserveError as StdTryReserveError;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TryReserveError {
    kind: TryReserveErrorKind,
}

/// The error type for `try_reserve` methods.
#[derive(Clone, PartialEq, Eq, Debug)]
enum TryReserveErrorKind {
    Std(StdTryReserveError),
    IndexMap(IndexMapTryReserveError),
}

#[cfg(feature = "std")]
impl std::error::Error for TryReserveError {}

impl core::fmt::Display for TryReserveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            TryReserveErrorKind::Std(e) => core::fmt::Display::fmt(e, f),
            TryReserveErrorKind::IndexMap(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

use TryReserveErrorKind::*;
impl From<StdTryReserveError> for TryReserveError {
    fn from(source: StdTryReserveError) -> Self {
        Self { kind: Std(source) }
    }
}

impl From<IndexMapTryReserveError> for TryReserveError {
    fn from(source: IndexMapTryReserveError) -> Self {
        Self {
            kind: IndexMap(source),
        }
    }
}

// `rebuild` takes O(len1 + len2) operations
// and about 2 * (len1 + len2) comparisons in the worst case
// while `extend` takes O(len2 * log_2(len1)) operations
// and about 1 * len2 * log_2(len1) comparisons in the worst case,
// assuming len1 >= len2.
fn better_to_rebuild(len1: usize, len2: usize) -> bool {
    // log(1) == 0, so the inequation always falsy
    // log(0) is inapplicable and produces panic
    if len1 <= 1 {
        return false;
    }

    2 * (len1 + len2) < len2 * log2_fast(len1)
}
