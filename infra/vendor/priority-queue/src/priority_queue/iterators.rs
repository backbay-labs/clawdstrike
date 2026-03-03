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
//! This module defines iterator types that are used only with the [`PriorityQueue`].
//!
//! Usually you don't need to explicitly `use` any of the types declared here.

#[cfg(not(feature = "std"))]
use crate::core_iterators::std;

use core::hash::BuildHasher;
use std::cmp::Ord;
#[cfg(feature = "std")]
use std::collections::hash_map::RandomState;
use std::iter::*;

use crate::PriorityQueue;

use super::Index;

/// An `Iterator` in arbitrary order which uses a `predicate` to determine if
/// an element should be removed from the `PriorityQueue`.
///
/// It can be obtained calling the [`extract_if`](PriorityQueue::extract_if) method.
///
/// The `predicate` has mutable access to the `(item, priority)` pairs.
///
/// It can update the priorities of the elements in the queue and the items
/// in a way that does not change the result of any of `hash` or `eq`.
///
/// When the iterator goes out of scope, the heap is rebuilt to restore the
/// structural properties.
#[cfg(feature = "std")]
pub struct ExtractIf<'a, I: 'a, P: 'a, F, H: 'a = RandomState>
where
    P: Ord,
{
    pq: &'a mut PriorityQueue<I, P, H>,
    predicate: F,
    idx: Index,
}

#[cfg(not(feature = "std"))]
pub struct ExtractIf<'a, I: 'a, P: 'a, F, H: 'a>
where
    P: Ord,
{
    pq: &'a mut PriorityQueue<I, P, H>,
    predicate: F,
    idx: Index,
}

impl<'a, I: 'a, P: 'a, F, H: 'a> ExtractIf<'a, I, P, F, H>
where
    P: Ord,
{
    pub(crate) fn new(pq: &'a mut PriorityQueue<I, P, H>, predicate: F) -> Self {
        ExtractIf {
            pq,
            predicate,
            idx: Index(0),
        }
    }
}

impl<'a, I: 'a, P: 'a, F, H: 'a> Iterator for ExtractIf<'a, I, P, F, H>
where
    P: Ord,
    F: FnMut(&mut I, &mut P) -> bool,
    H: BuildHasher,
{
    type Item = (I, P);
    fn next(&mut self) -> Option<Self::Item> {
        use indexmap::map::MutableKeys;

        loop {
            let r: Option<bool> = self
                .pq
                .store
                .map
                .get_index_mut2(self.idx.0)
                .map(|(i, p)| (self.predicate)(i, p));

            match r {
                Some(true) => return self.pq.store.swap_remove_index(self.idx),
                Some(false) => self.idx.0 += 1,
                None => return None,
            }
        }
    }
}

impl<'a, I: 'a, P: 'a, F, H: 'a> Drop for ExtractIf<'a, I, P, F, H>
where
    P: Ord,
{
    fn drop(&mut self) {
        self.pq.heap_build();
    }
}

/// A mutable iterator over the couples `(item, priority)` of the `PriorityQueue`
/// in arbitrary order.
///
/// It can be obtained calling the [`iter_mut`](PriorityQueue::iter_mut) method.
///
/// It can be used to update the priorities of the elements in the queue.
/// When the iterator goes out of scope, the heap is rebuilt to restore the
/// structural properties.
///
/// The item is mutable too, but it is a logical error to modify it in a way that
/// changes the result of any of `hash` or `eq`.
#[cfg(feature = "std")]
pub struct IterMut<'a, I: 'a, P: 'a, H: 'a = RandomState>
where
    P: Ord,
{
    pq: &'a mut PriorityQueue<I, P, H>,
    pos: usize,
}

#[cfg(not(feature = "std"))]
pub struct IterMut<'a, I: 'a, P: 'a, H: 'a>
where
    P: Ord,
{
    pq: &'a mut PriorityQueue<I, P, H>,
    pos: usize,
}

impl<'a, I: 'a, P: 'a, H: 'a> IterMut<'a, I, P, H>
where
    P: Ord,
{
    pub(crate) fn new(pq: &'a mut PriorityQueue<I, P, H>) -> Self {
        IterMut { pq, pos: 0 }
    }
}

impl<'a, I: 'a, P: 'a, H: 'a> Iterator for IterMut<'a, I, P, H>
where
    P: Ord,
    H: BuildHasher,
{
    type Item = (&'a mut I, &'a mut P);
    fn next(&mut self) -> Option<Self::Item> {
        use indexmap::map::MutableKeys;

        let r: Option<(&'a mut I, &'a mut P)> = self
            .pq
            .store
            .map
            .get_index_mut2(self.pos)
            .map(|(i, p)| (i as *mut I, p as *mut P))
            .map(|(i, p)| unsafe { (i.as_mut().unwrap(), p.as_mut().unwrap()) });
        self.pos += 1;
        r
    }
}

impl<'a, I: 'a, P: 'a, H: 'a> Drop for IterMut<'a, I, P, H>
where
    P: Ord,
{
    fn drop(&mut self) {
        self.pq.heap_build();
    }
}

/// A consuming iterator over the couples `(item, priority)` of the `PriorityQueue`
/// ordered by priority, from the highest to the lowest.
///
/// It can be obtained calling the [`into_sorted_iter`](PriorityQueue::into_sorted_iter) method.
#[cfg(feature = "std")]
pub struct IntoSortedIter<I, P, H = RandomState> {
    pub(crate) pq: PriorityQueue<I, P, H>,
}

#[cfg(not(feature = "std"))]
pub struct IntoSortedIter<I, P, H> {
    pub(crate) pq: PriorityQueue<I, P, H>,
}

impl<I, P, H> Iterator for IntoSortedIter<I, P, H>
where
    P: Ord,
{
    type Item = (I, P);
    fn next(&mut self) -> Option<(I, P)> {
        self.pq.pop()
    }
}
