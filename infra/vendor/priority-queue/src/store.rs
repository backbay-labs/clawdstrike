/*
 *  Copyright 2017 Gianmarco Garrisi
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
#[cfg(not(feature = "std"))]
use std::vec::Vec;

// an improvement in terms of complexity would be to use a bare HashMap
// as vec instead of the IndexMap
use crate::core_iterators::*;
use crate::TryReserveError;
use equivalent::Equivalent;

use std::cmp::{Eq, Ord};
#[cfg(feature = "std")]
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::iter::{FromIterator, IntoIterator, Iterator};
use std::mem::swap;

use indexmap::map::{IndexMap, MutableKeys};

/// The Index of the element in the Map
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Index(pub usize);

/// The Position of the element in the Heap
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Position(pub usize);

/// Compute the index of the left child of an item from its index
#[inline(always)]
pub(crate) const fn left(i: Position) -> Position {
    Position((i.0 * 2) + 1)
}
/// Compute the index of the right child of an item from its index
#[inline(always)]
pub(crate) const fn right(i: Position) -> Position {
    Position((i.0 * 2) + 2)
}
/// Compute the index of the parent element in the heap from its index
#[inline(always)]
pub(crate) const fn parent(i: Position) -> Position {
    Position((i.0 - 1) / 2)
}

// Compute the level of a node from its index
#[inline(always)]
pub(crate) const fn level(i: Position) -> usize {
    log2_fast(i.0 + 1)
}

#[inline(always)]
pub(crate) const fn log2_fast(x: usize) -> usize {
    (usize::BITS - x.leading_zeros() - 1) as usize
}

/// Internal storage of PriorityQueue and DoublePriorityQueue
#[derive(Clone)]
#[cfg(feature = "std")]
pub(crate) struct Store<I, P, H = RandomState> {
    pub map: IndexMap<I, P, H>, // Stores the items and assign them an index
    pub heap: Vec<Index>,       // Implements the heap of indexes
    pub qp: Vec<Position>,      // Performs the translation from the index
    // of the map to the index of the heap
    pub size: usize, // The size of the heap
}

#[derive(Clone)]
#[cfg(not(feature = "std"))]
pub(crate) struct Store<I, P, H> {
    pub map: IndexMap<I, P, H>, // Stores the items and assign them an index
    pub heap: Vec<Index>,       // Implements the heap of indexes
    pub qp: Vec<Position>,      // Performs the translation from the index
    // of the map to the index of the heap
    pub size: usize, // The size of the heap
}

impl<I, P, H> Default for Store<I, P, H>
where
    I: Hash + Eq,
    P: Ord,
    H: BuildHasher + Default,
{
    fn default() -> Self {
        Self::with_default_hasher()
    }
}

impl<I, P, H> Store<I, P, H>
where
    P: Ord,
    I: Hash + Eq,
    H: BuildHasher + Default,
{
    /// Creates an empty `Store` with the default hasher
    pub fn with_default_hasher() -> Self {
        Self::with_capacity_and_default_hasher(0)
    }

    /// Creates an empty `Store` with the specified capacity and default hasher
    pub fn with_capacity_and_default_hasher(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, H::default())
    }
}

impl<I, P, H> Store<I, P, H>
where
    P: Ord,
    I: Hash + Eq,
    H: BuildHasher,
{
    /// Creates an empty `Store` with the specified hasher
    pub const fn with_hasher(hash_builder: H) -> Self {
        Self {
            map: IndexMap::with_hasher(hash_builder),
            heap: Vec::new(),
            qp: Vec::new(),
            size: 0,
        }
    }

    /// Creates an empty `Store` with the specified capacity and hasher
    ///
    /// The internal collections will be able to hold at least `capacity`
    /// elements without reallocating.
    /// If `capacity` is 0, there will be no allocation.
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: H) -> Self {
        Self {
            map: IndexMap::with_capacity_and_hasher(capacity, hash_builder),
            heap: Vec::with_capacity(capacity),
            qp: Vec::with_capacity(capacity),
            size: 0,
        }
    }
}

impl<I, P, H> Store<I, P, H> {
    /// Returns an iterator in arbitrary order over the
    /// (item, priority) elements in the queue
    pub fn iter(&self) -> Iter<'_, I, P> {
        Iter {
            iter: self.map.iter(),
        }
    }

    /// Shrinks the capacity of the internal data structures
    /// that support this operation as much as possible.
    #[inline(always)]
    pub fn shrink_to_fit(&mut self) {
        self.heap.shrink_to_fit();
        self.qp.shrink_to_fit();
        self.map.shrink_to_fit();
    }

    /// Reserves capacity for at least `additional` more elements to be inserted
    /// in the given `PriorityQueue`. The collection may reserve more space to avoid
    /// frequent reallocations. After calling `reserve`, capacity will be
    /// greater than or equal to `self.len() + additional`. Does nothing if
    /// capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity overflows `usize`.
    ///
    /// Computes in O(n) time.
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional);
        self.heap.reserve(additional);
        self.qp.reserve(additional);
    }

    /// Reserve capacity for `additional` more elements, without over-allocating.
    ///
    /// Unlike `reserve`, this does not deliberately over-allocate the entry capacity to avoid
    /// frequent re-allocations. However, the underlying data structures may still have internal
    /// capacity requirements, and the allocator itself may give more space than requested, so this
    /// cannot be relied upon to be precisely minimal.
    ///
    /// Computes in **O(n)** time.
    pub fn reserve_exact(&mut self, additional: usize) {
        self.map.reserve_exact(additional);
        self.heap.reserve_exact(additional);
        self.qp.reserve_exact(additional);
    }

    /// Try to reserve capacity for at least `additional` more elements.
    ///
    /// Computes in O(n) time.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.map.try_reserve(additional)?;
        self.heap.try_reserve(additional)?;
        self.qp.try_reserve(additional)?;
        Ok(())
    }

    /// Try to reserve capacity for `additional` more elements, without over-allocating.
    ///
    /// Unlike `reserve`, this does not deliberately over-allocate the entry capacity to avoid
    /// frequent re-allocations. However, the underlying data structures may still have internal
    /// capacity requirements, and the allocator itself may give more space than requested, so this
    /// cannot be relied upon to be precisely minimal.
    ///
    /// Computes in **O(n)** time.
    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.map.try_reserve_exact(additional)?;
        self.heap.try_reserve_exact(additional)?;
        self.qp.try_reserve_exact(additional)?;
        Ok(())
    }

    /// Clears the store, returning an iterator over the removed elements in arbitrary order.
    /// If the iterator is dropped before being fully consumed, it drops the remaining elements in arbitrary order.
    pub fn drain(&mut self) -> Drain<'_, I, P> {
        self.heap.clear();
        self.qp.clear();
        self.size = 0;

        Drain {
            iter: self.map.drain(..),
        }
    }

    /// Returns the number of elements the internal map can hold without
    /// reallocating.
    ///
    /// This number is a lower bound; the map might be able to hold more,
    /// but is guaranteed to be able to hold at least this many.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Returns the number of elements in the priority queue.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns true if the priority queue contains no elements.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns the items not ordered
    pub fn into_vec(self) -> Vec<I> {
        self.map.into_iter().map(|(i, _)| i).collect()
    }

    /// Drops all items from the priority queue
    pub fn clear(&mut self) {
        self.heap.clear();
        self.qp.clear();
        self.map.clear();
        self.size = 0;
    }

    /// Swap two elements keeping a consistent state.
    ///
    /// Computes in **O(1)** time
    #[inline(always)]
    pub fn swap(&mut self, a: Position, b: Position) {
        self.qp.swap(
            unsafe { self.heap.get_unchecked(a.0) }.0,
            unsafe { self.heap.get_unchecked(b.0) }.0,
        );
        self.heap.swap(a.0, b.0);
    }

    /// Remove and return the element at index `idx`
    /// and swap it with the last element keeping a consistent
    /// state.
    ///
    /// Computes in **O(1)** time (average)
    pub fn swap_remove_index(&mut self, idx: Index) -> Option<(I, P)> {
        // swap_remove the position from the qp
        let position = self.qp.swap_remove(idx.0);
        self.size -= 1;

        if idx.0 < self.size {
            // SAFETY: head validity checked on the previous line.
            // All positions point to valid heap items because we already
            // updated the qp.
            unsafe {
                *self.heap.get_unchecked_mut(self.qp.get_unchecked(idx.0).0) = idx;
            }
        }
        self.heap.swap_remove(position.0);
        // Fix indexes and swap remove the old heap head from the qp
        if position.0 < self.size {
            // SAFETY: position validity checked on the previous line.
            // Indexes still point to valid qp items because we didn't
            // remove anything from qp yet
            unsafe {
                *self
                    .qp
                    .get_unchecked_mut(self.heap.get_unchecked(position.0).0) = position;
            }
        }

        // swap remove from the map and return to the client
        self.map.swap_remove_index(idx.0)
    }

    /// Remove and return the element in position `position`
    /// and swap it with the last element keeping a consistent
    /// state.
    ///
    /// Computes in **O(1)** time (average)
    pub fn swap_remove(&mut self, position: Position) -> Option<(I, P)> {
        // swap_remove the head
        let head: Index = self.heap.swap_remove(position.0);
        self.size -= 1;

        // Fix indexes and swap remove the old heap head from the qp
        if position.0 < self.size {
            // SAFETY: position validity checked on the previous line.
            // Indexes still point to valid qp items because we didn't
            // remove anything from qp yet
            unsafe {
                *self
                    .qp
                    .get_unchecked_mut(self.heap.get_unchecked(position.0).0) = position;
            }
        }
        self.qp.swap_remove(head.0);
        if head.0 < self.size {
            // SAFETY: head validity checked on the previous line.
            // All positions point to valid heap items because we already
            // updated the qp.
            unsafe {
                *self.heap.get_unchecked_mut(self.qp.get_unchecked(head.0).0) = head;
            }
        }
        // swap remove from the map and return to the client
        self.map.swap_remove_index(head.0)
    }

    #[inline(always)]
    pub unsafe fn get_priority_from_position(&self, position: Position) -> &P {
        unsafe {
            self.map
                .get_index(self.heap.get_unchecked(position.0).0)
                .unwrap()
                .1
        }
    }
}

impl<I, P, H> Store<I, P, H>
where
    P: Ord,
    I: Hash + Eq,
    H: BuildHasher,
{
    pub fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&I, &P) -> bool,
    {
        self.retain_mut(|i, p| predicate(&*i, &*p));
    }

    pub fn retain_mut<F>(&mut self, predicate: F)
    where
        F: FnMut(&mut I, &mut P) -> bool,
    {
        self.map.retain2(predicate);
        if self.map.len() != self.size {
            self.size = self.map.len();
            self.heap = (0..self.size).map(Index).collect();
            self.qp = (0..self.size).map(Position).collect();
        }
    }

    /// If the predicate returns true for the element in position `position`,
    /// remove it and swap it with the last element keeping a consistent
    /// state.
    ///
    /// Computes in **O(1)** time (average)
    pub fn swap_remove_if<F>(&mut self, position: Position, f: F) -> Option<(I, P)>
    where
        F: FnOnce(&mut I, &mut P) -> bool,
    {
        let head: Index = unsafe { *self.heap.get_unchecked(position.0) };
        let (i, p) = self.map.get_index_mut2(head.0).unwrap();

        if f(i, p) {
            self.swap_remove(position)
        } else {
            None
        }
    }

    /// Change the priority of an Item returning the old value of priority,
    /// or `None` if the item wasn't in the queue.
    ///
    /// The argument `item` is only used for lookup, and is not used to overwrite the item's data
    /// in the priority queue.
    ///
    /// The item is found in **O(1)** thanks to the hash table.
    /// The operation is performed in **O(log(N))** time.
    pub fn change_priority<Q>(&mut self, item: &Q, mut new_priority: P) -> Option<(P, Position)>
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        let Store { map, qp, .. } = self;
        map.get_full_mut(item).map(|(index, _, p)| {
            swap(p, &mut new_priority);
            let pos = unsafe { *qp.get_unchecked(index) };
            (new_priority, pos)
        })
    }

    /// Change the priority of an Item using the provided function.
    /// The item is found in **O(1)** thanks to the hash table.
    /// The operation is performed in **O(log(N))** time (worst case).
    pub fn change_priority_by<Q, F>(&mut self, item: &Q, priority_setter: F) -> Option<Position>
    where
        Q: ?Sized + Equivalent<I> + Hash,
        F: FnOnce(&mut P),
    {
        let Store { map, qp, .. } = self;
        map.get_full_mut(item).map(|(index, _, p)| {
            priority_setter(p);
            unsafe { *qp.get_unchecked(index) }
        })
    }

    /// Get the priority of an item, or `None`, if the item is not in the queue
    pub fn get_priority<Q>(&self, item: &Q) -> Option<&P>
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        self.map.get(item)
    }

    /// Check if the store contains `item`.
    ///
    /// Returns `true` if `item` is in the store, `false` if it is not.
    pub fn contains<Q>(&self, item: &Q) -> bool
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        self.map.contains_key(item)
    }

    /// Get the couple (item, priority) of an arbitrary element, as reference
    /// or `None` if the item is not in the queue.
    pub fn get<Q>(&self, item: &Q) -> Option<(&I, &P)>
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        self.map.get_full(item).map(|(_, k, v)| (k, v))
    }

    /// Get the couple (item, priority) of an arbitrary element, or `None`
    /// if the item was not in the queue.
    ///
    /// The item is a mutable reference, but it's a logic error to modify it
    /// in a way that change the result of  `Hash` or `Eq`.
    ///
    /// The priority cannot be modified with a call to this function.
    /// To modify the priority use `push`, `change_priority` or
    /// `change_priority_by`.
    pub fn get_mut<Q>(&mut self, item: &Q) -> Option<(&mut I, &P)>
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        self.map.get_full_mut2(item).map(|(_, k, v)| (k, &*v))
    }

    pub fn remove<Q>(&mut self, item: &Q) -> Option<(I, P, Position)>
    where
        Q: ?Sized + Equivalent<I> + Hash,
    {
        self.map.swap_remove_full(item).map(|(i, item, priority)| {
            let i = Index(i);
            self.size -= 1;

            let pos: Position = self.qp.swap_remove(i.0);
            self.heap.swap_remove(pos.0);
            if i.0 < self.size {
                unsafe {
                    let qpi = self.qp.get_unchecked_mut(i.0);
                    if qpi.0 == self.size {
                        *qpi = pos;
                    } else {
                        *self.heap.get_unchecked_mut(qpi.0) = i;
                    }
                }
            }
            if pos.0 < self.size {
                unsafe {
                    let heap_pos = self.heap.get_unchecked_mut(pos.0);
                    if heap_pos.0 == self.size {
                        *heap_pos = i;
                    } else {
                        *self.qp.get_unchecked_mut(heap_pos.0) = pos;
                    }
                }
            }
            (item, priority, pos)
        })
    }

    /// Move all items of the `other` queue to `self`
    /// ignoring the items Eq to elements already in `self`
    /// At the end, `other` will be empty.
    ///
    /// **Note** that at the end, the priority of the duplicated elements
    /// inside self may be the one of the elements in other,
    /// if other is longer than self
    pub fn append(&mut self, other: &mut Self) {
        if other.size > self.size {
            std::mem::swap(self, other);
        }
        if other.size == 0 {
            return;
        }
        // what should we do for duplicated keys?
        // ignore
        for (k, v) in other.drain() {
            if !self.map.contains_key(&k) {
                let i = self.size;
                self.map.insert(k, v);
                self.heap.push(Index(i));
                self.qp.push(Position(i));
                self.size += 1;
            }
        }
    }
}

impl<I, P, H> IntoIterator for Store<I, P, H> {
    type Item = (I, P);
    type IntoIter = IntoIter<I, P>;
    fn into_iter(self) -> IntoIter<I, P> {
        IntoIter {
            iter: self.map.into_iter(),
        }
    }
}

impl<'a, I, P, H> IntoIterator for &'a Store<I, P, H> {
    type Item = (&'a I, &'a P);
    type IntoIter = Iter<'a, I, P>;
    fn into_iter(self) -> Iter<'a, I, P> {
        Iter {
            iter: self.map.iter(),
        }
    }
}

use std::cmp::PartialEq;

impl<I, P1, H1, P2, H2> PartialEq<Store<I, P2, H2>> for Store<I, P1, H1>
where
    I: Hash + Eq,
    P1: Ord,
    P1: PartialEq<P2>,
    Option<P1>: PartialEq<Option<P2>>,
    P2: Ord,
    H1: BuildHasher,
    H2: BuildHasher,
{
    fn eq(&self, other: &Store<I, P2, H2>) -> bool {
        self.map == other.map
    }
}

impl<I, P, H> From<Vec<(I, P)>> for Store<I, P, H>
where
    I: Hash + Eq,
    P: Ord,
    H: BuildHasher + Default,
{
    fn from(vec: Vec<(I, P)>) -> Self {
        let mut store = Self::with_capacity_and_hasher(vec.len(), <_>::default());
        let mut i = 0;
        for (item, priority) in vec {
            if !store.map.contains_key(&item) {
                store.map.insert(item, priority);
                store.qp.push(Position(i));
                store.heap.push(Index(i));
                i += 1;
            }
        }
        store.size = i;
        store
    }
}

impl<I, P, H> FromIterator<(I, P)> for Store<I, P, H>
where
    I: Hash + Eq,
    P: Ord,
    H: BuildHasher + Default,
{
    fn from_iter<IT>(iter: IT) -> Self
    where
        IT: IntoIterator<Item = (I, P)>,
    {
        let iter = iter.into_iter();
        let (min, max) = iter.size_hint();
        let mut store = if let Some(max) = max {
            Self::with_capacity_and_hasher(max, <_>::default())
        } else if min > 0 {
            Self::with_capacity_and_hasher(min, <_>::default())
        } else {
            Self::with_hasher(<_>::default())
        };
        for (item, priority) in iter {
            if store.map.contains_key(&item) {
                let (_, old_item, old_priority) = store.map.get_full_mut2(&item).unwrap();
                *old_item = item;
                *old_priority = priority;
            } else {
                store.map.insert(item, priority);
                store.qp.push(Position(store.size));
                store.heap.push(Index(store.size));
                store.size += 1;
            }
        }
        store
    }
}

impl<I, P, H> Extend<(I, P)> for Store<I, P, H>
where
    I: Hash + Eq,
    P: Ord,
    H: BuildHasher,
{
    fn extend<T: IntoIterator<Item = (I, P)>>(&mut self, iter: T) {
        for (item, priority) in iter {
            if self.map.contains_key(&item) {
                let (_, old_item, old_priority) = self.map.get_full_mut2(&item).unwrap();
                *old_item = item;
                *old_priority = priority;
            } else {
                self.map.insert(item, priority);
                self.qp.push(Position(self.size));
                self.heap.push(Index(self.size));
                self.size += 1;
            }
        }
    }
}

use std::fmt;
impl<I, P, H> fmt::Debug for Store<I, P, H>
where
    I: fmt::Debug,
    P: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(
                self.heap
                    .iter()
                    .map(|&i| (i, self.map.get_index(i.0).unwrap())),
            )
            .finish()
    }
}

#[cfg(feature = "serde")]
mod serde {
    use crate::store::{Index, Position, Store};

    use core::cmp::{Eq, Ord};
    use core::hash::{BuildHasher, Hash};
    use core::marker::PhantomData;
    #[cfg(feature = "std")]
    use std::collections::hash_map::RandomState;

    use serde::ser::{Serialize, SerializeSeq, Serializer};

    impl<I, P, H> Serialize for Store<I, P, H>
    where
        I: Serialize,
        P: Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut map_serializer = serializer.serialize_seq(Some(self.size))?;
            for (k, v) in &self.map {
                map_serializer.serialize_element(&(k, v))?;
            }
            map_serializer.end()
        }
    }

    use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
    impl<'de, I, P, H> Deserialize<'de> for Store<I, P, H>
    where
        I: Hash + Eq + Deserialize<'de>,
        P: Ord + Deserialize<'de>,
        H: BuildHasher + Default,
    {
        fn deserialize<D>(deserializer: D) -> Result<Store<I, P, H>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(StoreVisitor {
                marker: PhantomData,
            })
        }
    }

    #[cfg(feature = "std")]
    struct StoreVisitor<I, P, H = RandomState>
    where
        I: Hash + Eq,
        P: Ord,
    {
        marker: PhantomData<Store<I, P, H>>,
    }

    #[cfg(not(feature = "std"))]
    struct StoreVisitor<I, P, H>
    where
        I: Hash + Eq,
        P: Ord,
    {
        marker: PhantomData<Store<I, P, H>>,
    }

    impl<'de, I, P, H> Visitor<'de> for StoreVisitor<I, P, H>
    where
        I: Hash + Eq + Deserialize<'de>,
        P: Ord + Deserialize<'de>,
        H: BuildHasher + Default,
    {
        type Value = Store<I, P, H>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(formatter, "A priority queue")
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Store::with_default_hasher())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut store: Store<I, P, H> = if let Some(size) = seq.size_hint() {
                Store::with_capacity_and_default_hasher(size)
            } else {
                Store::with_default_hasher()
            };

            while let Some((item, priority)) = seq.next_element()? {
                store.map.insert(item, priority);
                store.qp.push(Position(store.size));
                store.heap.push(Index(store.size));
                store.size += 1;
            }
            Ok(store)
        }
    }
}
