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
//! This module defines iterator types that are used with
//! both the [`PriorityQueue`](super::PriorityQueue) and the [`DoublePriorityQueue`](super::DoublePriorityQueue)
//!
//! Usually you don't need to explicitly `use` any of the types declared here.

use core::iter::FusedIterator;

#[cfg(not(feature = "std"))]
pub(crate) mod std {
    pub use ::alloc::vec;
    pub use core::*;
}

/// A draining iterator in arbitrary order over the couples
/// `(item, priority)` in the queue.
///
/// It can be obtained calling the `drain` method.
pub struct Drain<'a, I: 'a, P: 'a> {
    pub(crate) iter: ::indexmap::map::Drain<'a, I, P>,
}

impl<'a, I: 'a, P: 'a> Iterator for Drain<'a, I, P> {
    type Item = (I, P);
    fn next(&mut self) -> Option<(I, P)> {
        self.iter.next()
    }
}

impl<I, P> DoubleEndedIterator for Drain<'_, I, P> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back()
    }
}

impl<I, P> ExactSizeIterator for Drain<'_, I, P> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<I, P> FusedIterator for Drain<'_, I, P> {}

/// An iterator in arbitrary order over the couples
/// `(item, priority)` in the queue.
///
/// It can be obtained calling the `iter` method.
pub struct Iter<'a, I: 'a, P: 'a> {
    pub(crate) iter: ::indexmap::map::Iter<'a, I, P>,
}

impl<'a, I: 'a, P: 'a> Iterator for Iter<'a, I, P> {
    type Item = (&'a I, &'a P);
    fn next(&mut self) -> Option<(&'a I, &'a P)> {
        self.iter.next()
    }
}

impl<I, P> DoubleEndedIterator for Iter<'_, I, P> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back()
    }
}

impl<I, P> ExactSizeIterator for Iter<'_, I, P> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<I, P> FusedIterator for Iter<'_, I, P> {}

/// An iterator in arbitrary order over the couples
/// `(item, priority)` that consumes the queue.
///
/// It can be obtained calling the `into_iter` method from the [`IntoIterator`] trait.
pub struct IntoIter<I, P> {
    pub(crate) iter: ::indexmap::map::IntoIter<I, P>,
}

impl<I, P> Iterator for IntoIter<I, P> {
    type Item = (I, P);
    fn next(&mut self) -> Option<(I, P)> {
        self.iter.next()
    }
}

impl<I, P> DoubleEndedIterator for IntoIter<I, P> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back()
    }
}

impl<I, P> ExactSizeIterator for IntoIter<I, P> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<I, P> FusedIterator for IntoIter<I, P> {}
