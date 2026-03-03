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

#![cfg_attr(feature = "benchmarks", feature(test))]

#[cfg(all(test, feature = "benchmarks"))]
mod benchmarks {
    extern crate test;
    use hashbrown::hash_map::DefaultHashBuilder;
    use priority_queue::{DoublePriorityQueue, PriorityQueue};
    use test::{black_box, Bencher};

    #[bench]
    fn push_and_pop(b: &mut Bencher) {
        type PqType = PriorityQueue<usize, i32>;
        let mut pq: PqType = PriorityQueue::new();
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop().unwrap().1, 0];
        });
    }

    #[bench]
    fn push_and_pop_double(b: &mut Bencher) {
        type PqType = DoublePriorityQueue<usize, i32>;
        let mut pq: PqType = DoublePriorityQueue::new();
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop_max().unwrap().1, 0];
        });
    }

    #[bench]
    fn push_and_pop_fx(b: &mut Bencher) {
        let mut pq = PriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop().unwrap().1, 0];
        });
    }

    #[bench]
    fn push_and_pop_double_fx(b: &mut Bencher) {
        let mut pq = DoublePriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop_max().unwrap().1, 0];
        });
    }

    //for comparison, using the BinaryHeap
    #[bench]
    fn push_and_pop_std(b: &mut Bencher) {
        use std::collections::BinaryHeap;
        type PqType = BinaryHeap<(usize, i32)>;
        let mut pq: PqType = BinaryHeap::new();
        b.iter(|| {
            pq.push((black_box(0), black_box(0)));
            assert_eq![pq.pop().unwrap().1, 0];
        });
    }

    #[bench]
    fn push_and_pop_on_large_queue(b: &mut Bencher) {
        type PqType = PriorityQueue<usize, i32>;
        let mut pq: PqType = PriorityQueue::new();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(100_000), black_box(100_000));
            assert_eq![pq.pop().unwrap().1, black_box(100_000)];
        });
    }

    #[bench]
    fn push_and_pop_on_large_double_queue(b: &mut Bencher) {
        type PqType = DoublePriorityQueue<usize, i32>;
        let mut pq: PqType = DoublePriorityQueue::new();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(100_000), black_box(100_000));
            assert_eq![pq.pop_max().unwrap().1, black_box(100_000)];
        });
    }

    #[bench]
    fn push_and_pop_min_on_large_double_queue(b: &mut Bencher) {
        type PqType = DoublePriorityQueue<usize, i32>;
        let mut pq: PqType = DoublePriorityQueue::new();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop_min().unwrap().1, black_box(0)];
        });
    }

    #[bench]
    fn push_and_pop_on_large_queue_fx(b: &mut Bencher) {
        let mut pq = PriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(100_000), black_box(100_000));
            assert_eq![pq.pop().unwrap().1, black_box(100_000)];
        });
    }

    #[bench]
    fn push_and_pop_on_large_double_queue_fx(b: &mut Bencher) {
        let mut pq = DoublePriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(100_000), black_box(100_000));
            assert_eq![pq.pop_max().unwrap().1, black_box(100_000)];
        });
    }

    #[bench]
    fn push_and_pop_min_on_large_double_queue_fx(b: &mut Bencher) {
        let mut pq = DoublePriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.push(black_box(0), black_box(0));
            assert_eq![pq.pop_min().unwrap().1, black_box(0)];
        });
    }

    #[bench]
    fn push_and_pop_on_large_queue_std(b: &mut Bencher) {
        use std::collections::BinaryHeap;
        type PqType = BinaryHeap<(usize, i32)>;
        let mut pq: PqType = BinaryHeap::new();
        for i in 0..100_000 {
            pq.push((black_box(i as usize), black_box(i)));
        }
        b.iter(|| {
            pq.push((black_box(100_000), black_box(100_000)));
            assert_eq![pq.pop().unwrap().1, black_box(100_000)];
        });
    }

    #[bench]
    fn priority_change_on_large_queue_std(b: &mut Bencher) {
        use std::collections::BinaryHeap;
        struct Entry(usize, i32);
        impl Ord for Entry {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }
        impl PartialOrd for Entry {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }
        impl Eq for Entry {}
        impl PartialEq for Entry {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
        type PqType = BinaryHeap<Entry>;
        let mut pq: PqType = BinaryHeap::new();
        for i in 0..100_000 {
            pq.push(Entry(black_box(i as usize), black_box(i)));
        }
        b.iter(|| {
            pq = pq
                .drain()
                .map(|Entry(i, p)| {
                    if i == 50_000 {
                        Entry(i, p / 2)
                    } else {
                        Entry(i, p)
                    }
                })
                .collect()
        });
    }

    #[bench]
    fn priority_change_on_large_queue(b: &mut Bencher) {
        type PqType = PriorityQueue<usize, i32>;
        let mut pq: PqType = PriorityQueue::new();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&50_000, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_large_double_queue(b: &mut Bencher) {
        type PqType = DoublePriorityQueue<usize, i32>;
        let mut pq: PqType = DoublePriorityQueue::new();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&50_000, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_large_queue_fx(b: &mut Bencher) {
        let mut pq = PriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&50_000, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_large_double_queue_fx(b: &mut Bencher) {
        let mut pq = DoublePriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..100_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&50_000, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_small_queue_std(b: &mut Bencher) {
        use std::collections::BinaryHeap;
        struct Entry(usize, i32);
        impl Ord for Entry {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }
        impl PartialOrd for Entry {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }
        impl Eq for Entry {}
        impl PartialEq for Entry {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
        type PqType = BinaryHeap<Entry>;
        let mut pq: PqType = BinaryHeap::new();
        for i in 0..1_000 {
            pq.push(Entry(black_box(i as usize), black_box(i)));
        }
        b.iter(|| {
            pq = pq
                .drain()
                .map(|Entry(i, p)| {
                    if i == 500 {
                        Entry(i, p / 2)
                    } else {
                        Entry(i, p)
                    }
                })
                .collect()
        });
    }

    #[bench]
    fn priority_change_on_small_queue(b: &mut Bencher) {
        type PqType = PriorityQueue<usize, i32>;
        let mut pq: PqType = PriorityQueue::new();
        for i in 0..1_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&500, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_small_double_queue(b: &mut Bencher) {
        type PqType = DoublePriorityQueue<usize, i32>;
        let mut pq: PqType = DoublePriorityQueue::new();
        for i in 0..1_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&500, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_small_queue_fx(b: &mut Bencher) {
        let mut pq = PriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..1_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&500, |p| *p = *p / 2);
        });
    }

    #[bench]
    fn priority_change_on_small_double_queue_fx(b: &mut Bencher) {
        let mut pq = DoublePriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();
        for i in 0..1_000 {
            pq.push(black_box(i as usize), black_box(i));
        }
        b.iter(|| {
            pq.change_priority_by(&500, |p| *p = *p / 2);
        });
    }
}
