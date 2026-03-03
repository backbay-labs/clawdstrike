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

#[cfg(feature = "std")]
#[cfg(test)]
mod pqueue_tests {
    pub use priority_queue::PriorityQueue;

    #[test]
    fn init() {
        let pq: PriorityQueue<String, i32> = PriorityQueue::new();
        println!("{:?}", pq);
    }

    #[test]
    fn push_len_clear() {
        let mut pq = PriorityQueue::new();
        assert_eq!(pq.len(), 0);
        pq.push("a", 1);
        pq.push("b", 2);
        println!("{:?}", pq);
        assert_eq!(pq.len(), 2);

        pq.clear();
        assert_eq!(pq.len(), 0);
        assert_eq!(None, pq.pop());
    }

    #[test]
    fn push_pop() {
        let mut pq = PriorityQueue::new();
        assert_eq!(pq.peek(), None);
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);
        pq.push("g", 4);
        pq.push("h", 3);
        println!("{:?}", pq);
        assert_eq!(pq.pop(), Some(("f", 7)));
        println!("{:?}", pq);
        assert_eq!(pq.peek(), Some((&"g", &4)));
        assert_eq!(pq.pop(), Some(("g", 4)));
        assert_eq!(pq.len(), 3);
    }

    #[test]
    fn push_pop_if() {
        let mut pq = PriorityQueue::new();
        assert_eq!(pq.pop_if(|_, _| true), None);
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);
        pq.push("g", 5);
        pq.push("h", 3);
        println!("{:?}", pq);
        assert_eq!(
            pq.pop_if(|i, p| {
                assert_eq!(&"f", i);
                assert_eq!(&7, p);
                *p = 4;
                false
            }),
            None
        );
        assert_eq!(
            pq.pop_if(|i, p| {
                assert_eq!(&"g", i);
                assert_eq!(&5, p);
                *p = 4;
                true
            }),
            Some(("g", 4))
        );
        println!("{:?}", pq);
        assert_eq!(pq.peek(), Some((&"f", &4)));
        assert_eq!(pq.pop(), Some(("f", 4)));
        assert_eq!(pq.len(), 3);
    }

    #[test]
    fn contains() {
        let mut pq = PriorityQueue::new();
        assert!(!pq.contains("a"));
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);
        pq.push("g", 5);
        pq.push("h", 3);

        assert!(pq.contains("f"));

        pq.pop();

        assert!(!pq.contains("f"));
    }

    #[test]
    fn peek_get_mut() {
        use std::hash::{Hash, Hasher};

        #[derive(Debug)]
        struct Person {
            id: u32,
            name: String,
            phone: u64,
        }

        impl Hash for Person {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.id.hash(state);
                self.phone.hash(state);
            }
        }

        impl PartialEq for Person {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id && self.phone == other.phone
            }
        }

        impl Eq for Person {}

        let mut pq = PriorityQueue::new();
        assert_eq!(pq.peek_mut(), None);
        pq.push(
            Person {
                id: 1,
                name: "a".to_string(),
                phone: 39281048279,
            },
            1,
        );
        pq.push(
            Person {
                id: 2,
                name: "b".to_string(),
                phone: 23912750234,
            },
            2,
        );
        pq.push(
            Person {
                id: 3,
                name: "c".to_string(),
                phone: 1298275802947,
            },
            3,
        );
        pq.push(
            Person {
                id: 4,
                name: "d".to_string(),
                phone: 65723012057,
            },
            4,
        );
        pq.push(
            Person {
                id: 5,
                name: "e".to_string(),
                phone: 7237569870239,
            },
            5,
        );
        pq.push(
            Person {
                id: 6,
                name: "f".to_string(),
                phone: 35756872497,
            },
            6,
        );
        println!("{:?}", pq);

        let (item, _) = pq.peek_mut().unwrap();
        item.name.push('g');

        let (item, priority) = pq.pop().unwrap();
        assert_eq!(
            item,
            Person {
                id: 6,
                // name is not used for checking equality
                name: "f".to_string(),
                phone: 35756872497
            }
        );
        assert_eq!(6, priority);
        assert_eq!("fg", item.name);

        let (item, _) = pq
            .get_mut(&Person {
                id: 4,
                // name is not used for checking equality
                name: String::new(),
                phone: 65723012057,
            })
            .unwrap();
        item.name.push('g');

        let (item, priority) = pq
            .get(&Person {
                id: 4,
                // name is not used for checking equality
                name: String::new(),
                phone: 65723012057,
            })
            .unwrap();
        assert_eq!(
            item,
            &Person {
                id: 4,
                // name is not used for checking equality
                name: String::new(),
                phone: 65723012057
            }
        );
        assert_eq!(&4, priority);
        assert_eq!("dg", item.name);

        println!("{:?}", pq);
        assert_eq!(pq.len(), 5);
    }

    #[test]
    fn append() {
        let mut pq1 = PriorityQueue::new();
        let mut pq2 = PriorityQueue::new();

        pq1.push("a", 9);
        pq1.push("b", 8);
        pq1.push("c", 7);
        pq1.push("d", 6);
        pq1.push("e", 5);
        pq1.push("f", 4);
        pq1.push("g", 10);
        pq1.push("k", 11);
        pq1.push("d", 20);

        pq2.push("h", 2);
        pq2.push("x", 18);
        pq2.push("v", 28);
        pq2.push("y", 0);
        pq2.push("z", 21);

        pq1.append(&mut pq2);

        let expected = [
            "v", "z", "d", "x", "k", "g", "a", "b", "c", "e", "f", "h", "y",
        ];
        let v = pq1.into_sorted_vec();
        assert_eq!(expected, v.as_slice());
    }

    #[test]
    fn push_update() {
        let mut pq = PriorityQueue::new();
        pq.push("a", 9);
        pq.push("b", 8);
        pq.push("c", 7);
        pq.push("d", 6);
        pq.push("e", 5);
        pq.push("f", 4);
        pq.push("g", 10);
        pq.push("k", 11);

        pq.push("d", 20);
        assert_eq!(pq.peek(), Some((&"d", &20)));
        assert_eq!(pq.pop(), Some(("d", 20)));
    }

    #[test]
    fn push_increase() {
        let mut pq = PriorityQueue::new();
        pq.push("Processor", 1);
        pq.push("Mainboard", 2);
        pq.push("RAM", 5);
        pq.push("GPU", 4);
        pq.push("Disk", 3);

        let processor_priority = |pq: &PriorityQueue<&str, i32>| {
            *pq.iter()
                .find_map(|(i, p)| if *i == "Processor" { Some(p) } else { None })
                .unwrap()
        };

        pq.push_increase("Processor", 3);
        assert_eq!(processor_priority(&pq), 3);

        pq.push_increase("Processor", 1);
        assert_eq!(processor_priority(&pq), 3);

        pq.push_increase("Processor", 6);
        assert_eq!(pq.peek(), Some((&"Processor", &6)));
    }

    #[test]
    fn push_decrease() {
        let mut pq = PriorityQueue::new();
        pq.push("Processor", 1);
        pq.push("Mainboard", 2);
        pq.push("RAM", 5);
        pq.push("GPU", 4);
        pq.push("Disk", 3);

        let processor_priority = |pq: &PriorityQueue<&str, i32>| *pq.get("Processor").unwrap().1;

        pq.push_decrease("Processor", 3);
        assert_eq!(processor_priority(&pq), 1);

        pq.push_decrease("Processor", 0);
        assert_eq!(processor_priority(&pq), 0);

        pq.push_decrease("Processor", 6);
        assert_eq!(pq.peek(), Some((&"RAM", &5)));
    }

    #[test]
    fn change_priority() {
        let mut pq = PriorityQueue::new();
        pq.push("Processor", 1);
        pq.push("Mainboard", 2);
        pq.push("RAM", 5);
        pq.push("GPU", 4);
        pq.push("Disk", 3);
        pq.change_priority("Processor", 10);
        assert_eq!(pq.peek(), Some((&"Processor", &10)));

        pq.change_priority("RAM", 11);
        assert_eq!(pq.peek(), Some((&"RAM", &11)));
    }

    #[test]
    fn change_priority_does_not_change_contents() {
        use std::hash::{Hash, Hasher};
        struct MyFn {
            name: &'static str,
            func: fn(&mut i32),
        }
        impl Default for MyFn {
            fn default() -> Self {
                Self {
                    name: "",
                    func: |_| {},
                }
            }
        }
        impl PartialEq for MyFn {
            fn eq(&self, other: &Self) -> bool {
                self.name == other.name
            }
        }
        impl Eq for MyFn {}
        impl Hash for MyFn {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.name.hash(state);
            }
        }
        impl std::fmt::Debug for MyFn {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write![f, "{:?}", self.name]
            }
        }

        let mut pq = PriorityQueue::new();
        pq.push(
            MyFn {
                name: "increment-one",
                func: |x| *x += 1,
            },
            2,
        );
        pq.push(
            MyFn {
                name: "increment-two",
                func: |x| *x += 2,
            },
            1,
        );

        let mut cnt = 0;
        assert_eq![
            pq.peek(),
            Some((
                &MyFn {
                    name: "increment-one",
                    func: |_| {}
                },
                &2
            ))
        ];
        pq.change_priority(
            &MyFn {
                name: "increment-one",
                func: |_| {},
            },
            0,
        );
        assert_eq![
            pq.peek(),
            Some((
                &MyFn {
                    name: "increment-two",
                    func: |_| {}
                },
                &1
            ))
        ];

        assert_eq![cnt, 0];

        (pq.pop().unwrap().0.func)(&mut cnt);
        assert_eq![cnt, 2];

        (pq.pop().unwrap().0.func)(&mut cnt);
        assert_eq![cnt, 3];
    }

    #[test]
    fn reversed_order() {
        use std::cmp::Reverse;
        let mut pq: PriorityQueue<_, Reverse<i32>> = PriorityQueue::new();
        pq.push("a", Reverse(1));
        pq.push("b", Reverse(2));
        assert_eq![pq.pop(), Some(("a", Reverse(1)))];
    }

    #[test]
    fn from_vec() {
        let v = vec![("a", 1), ("b", 2), ("f", 7)];
        let mut pq: PriorityQueue<_, _> = PriorityQueue::from(v);
        assert_eq!(pq.pop(), Some(("f", 7)));
        assert_eq!(pq.len(), 2);
    }

    #[test]
    fn into_vec() {
        let v = vec![("a", 1), ("b", 2), ("f", 7)];
        let pq: PriorityQueue<_, _> = PriorityQueue::from(v);

        let mut v = pq.into_vec();

        v.sort_unstable();

        assert!(v.iter().enumerate().all(|(i, x)| &["a", "b", "f"][i] == x));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn from_vec_with_repeated() {
        let v = vec![("a", 1), ("b", 2), ("f", 7), ("a", 2)];
        let mut pq: PriorityQueue<_, _> = v.into();
        assert_eq!(pq.pop(), Some(("f", 7)));
        assert_eq!(pq.len(), 2);
    }

    #[test]
    fn from_iter() {
        use std::iter::FromIterator;

        let v = vec![("a", 1), ("b", 2), ("f", 7)];
        let mut pq: PriorityQueue<_, _> = PriorityQueue::from_iter(v);
        assert_eq!(pq.pop(), Some(("f", 7)));
        assert_eq!(pq.len(), 2);
    }

    #[test]
    fn heap_sort() {
        type Pq<I, P> = PriorityQueue<I, P>;

        let v = vec![("a", 2), ("b", 7), ("f", 1)];
        let sorted = (Pq::from(v)).into_sorted_vec();
        assert_eq!(sorted.as_slice(), &["b", "a", "f"]);
    }

    #[test]
    fn change_priority_by() {
        use std::iter::FromIterator;

        let v = vec![("a", 1), ("b", 2), ("f", 7), ("g", 6), ("h", 5)];
        let mut pq: PriorityQueue<_, _> = PriorityQueue::from_iter(v);

        assert!(!pq.change_priority_by("z", |z| *z += 8));
        assert!(pq.change_priority_by("b", |b| *b += 8));
        assert_eq!(pq.into_sorted_vec().as_slice(), &["b", "f", "g", "h", "a"]);
    }

    #[test]
    fn remove_empty() {
        let mut pq: PriorityQueue<&str, i32> = PriorityQueue::new();

        pq.remove(&"b");
        assert_eq!(pq.len(), 0);
    }

    #[test]
    fn remove_one() {
        let mut pq = PriorityQueue::new();

        pq.push("b", 21);

        assert_eq!(Some(("b", 21)), pq.remove(&"b"));
        assert_eq!(pq.len(), 0);
    }

    #[test]
    fn remove() {
        use std::iter::FromIterator;
        type Pq<I, P> = PriorityQueue<I, P>;

        let v = vec![("a", 1), ("b", 2), ("f", 7), ("g", 6), ("h", 5)];
        let mut pq = Pq::from_iter(v);

        pq.remove(&"b").unwrap();
        pq.push("b", 2);
        pq.remove(&"b");
        assert_eq!(["f", "g", "h", "a"], pq.into_sorted_vec().as_slice());
    }

    #[test]
    fn remove2() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        for i in 0..7 {
            queue.push(i, i);
        }

        queue.remove(&0);

        let mut last_priority = *queue.peek().unwrap().1;
        while let Some((_, priority)) = queue.pop() {
            dbg!(priority);
            assert!(last_priority >= priority);
            last_priority = priority;
        }

        let mut queue: PriorityQueue<i32, i32, RandomState> =
            [20, 7, 19, 5, 6, 15, 18, 1, 2, 3, 4, 13, 14, 16, 17]
                .iter()
                .map(|i| (*i, *i))
                .collect();

        queue.remove(&1);

        let mut last_priority = *queue.peek().unwrap().1;
        while let Some((_, priority)) = queue.pop() {
            dbg!(priority);
            assert!(last_priority >= priority);
            last_priority = priority;
        }
    }

    #[test]
    fn drain() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        for i in 0..7 {
            queue.push(i, i);
        }

        let previous_capacity = queue.capacity();
        queue.drain();

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.capacity(), previous_capacity);
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn reserve() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        queue.reserve(100);

        assert_eq!(queue.len(), 0);
        assert!(queue.capacity() >= 100);
    }

    #[test]
    fn reserve_exact() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        queue.reserve_exact(100);

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.capacity(), 100);
    }

    #[test]
    fn try_reserve() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        queue.try_reserve(100).unwrap();

        assert_eq!(queue.len(), 0);
        assert!(queue.capacity() >= 100);
    }

    #[test]
    fn try_reserve_exact() {
        use std::collections::hash_map::RandomState;
        let mut queue = PriorityQueue::<i32, i32, RandomState>::default();

        queue.try_reserve_exact(100).unwrap();

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.capacity(), 100);
    }

    #[test]
    fn extend() {
        let mut pq = PriorityQueue::new();
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);

        let v = vec![("c", 4), ("d", 6), ("e", 3)];
        pq.extend(v);
        assert_eq!(pq.len(), 6);
        assert_eq!(
            pq.into_sorted_vec().as_slice(),
            &["f", "d", "c", "e", "b", "a"]
        );
    }

    #[test]
    fn extend_empty() {
        let mut pq = PriorityQueue::new();

        let v = vec![("c", 4), ("d", 6), ("e", 3)];
        pq.extend(v);
        assert_eq!(pq.len(), 3);
        assert_eq!(pq.into_sorted_vec().as_slice(), &["d", "c", "e"]);
    }

    #[test]
    fn iter() {
        let mut pq = PriorityQueue::new();
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);

        assert_eq!(pq.iter().count(), 3);
    }

    #[test]
    fn iter_mut() {
        let mut pq = PriorityQueue::new();
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);
        pq.push("g", 4);
        pq.push("h", 3);

        for (i, p) in &mut pq {
            if *i < "f" {
                *p += 18;
            }
        }

        assert_eq!(pq.pop(), Some(("b", 20)));

        /*
        As expected, this does not compile
        let iter_mut = pq.iter_mut();

        assert_eq!(pq.pop(), Some(("f", 9)));
        iter_mut.for_each(|(_, p)| {*p += 2});
        */
    }

    #[test]
    fn extract_if() {
        #[derive(Hash, PartialEq, Eq, Debug)]
        struct Animal {
            name: String,
            can_fly: bool,
            can_swim: bool,
        }

        impl Animal {
            pub fn new(name: String, can_fly: bool, can_swim: bool) -> Self {
                Animal {
                    name,
                    can_fly,
                    can_swim,
                }
            }
        }

        let mut pq = PriorityQueue::new();
        pq.push(Animal::new("dog".to_string(), false, true), 1);
        pq.push(Animal::new("cat".to_string(), false, false), 2);
        pq.push(Animal::new("bird".to_string(), true, false), 7);
        pq.push(Animal::new("fish".to_string(), false, true), 4);
        pq.push(Animal::new("cow".to_string(), false, false), 3);
        let swimming_animals: Vec<(Animal, i32)> = pq
            .extract_if(|i, p| {
                if i.can_fly {
                    *p -= 18;
                    return false;
                }

                i.can_swim
            })
            .collect();

        assert_eq!(
            swimming_animals,
            [
                (Animal::new("dog".to_string(), false, true), 1),
                (Animal::new("fish".to_string(), false, true), 4)
            ]
        );
        assert_eq!(
            pq.pop(),
            Some((Animal::new("cow".to_string(), false, false), 3))
        );
        assert_eq!(
            pq.pop(),
            Some((Animal::new("cat".to_string(), false, false), 2))
        );
        assert_eq!(
            pq.pop(),
            Some((Animal::new("bird".to_string(), true, false), -11))
        );

        /*
        // As expected, this does not compile
        let extract_if = pq.extract_if(|i, p| { i.can_fly });

        assert_eq!(pq.pop(), None);
        extract_if.for_each(|(_, p)| println!("{:?}", p)); */
    }

    #[test]
    fn retain() {
        #[derive(Hash, PartialEq, Eq, Debug)]
        struct Animal {
            name: String,
            can_fly: bool,
            can_swim: bool,
        }

        impl Animal {
            pub fn new(name: String, can_fly: bool, can_swim: bool) -> Self {
                Animal {
                    name,
                    can_fly,
                    can_swim,
                }
            }
        }

        let mut pq = PriorityQueue::new();
        pq.push(Animal::new("dog".to_string(), false, true), 1);
        pq.push(Animal::new("cat".to_string(), false, false), 2);
        pq.push(Animal::new("bird".to_string(), true, false), 7);
        pq.push(Animal::new("fish".to_string(), false, true), 4);
        pq.push(Animal::new("cow".to_string(), false, false), 3);

        pq.retain(|i, _| i.can_swim);

        assert_eq!(
            pq.pop(),
            Some((Animal::new("fish".to_string(), false, true), 4))
        );
        assert_eq!(
            pq.pop(),
            Some((Animal::new("dog".to_string(), false, true), 1))
        );
    }

    #[test]
    fn retain_mut() {
        #[derive(Hash, PartialEq, Eq, Debug)]
        struct Animal {
            name: String,
            can_fly: bool,
            can_swim: bool,
        }

        impl Animal {
            pub fn new(name: String, can_fly: bool, can_swim: bool) -> Self {
                Animal {
                    name,
                    can_fly,
                    can_swim,
                }
            }
        }

        let mut pq = PriorityQueue::new();
        pq.push(Animal::new("dog".to_string(), false, true), 1);
        pq.push(Animal::new("cat".to_string(), false, false), 2);
        pq.push(Animal::new("bird".to_string(), true, false), 7);
        pq.push(Animal::new("fish".to_string(), false, true), 4);
        pq.push(Animal::new("cow".to_string(), false, false), 3);

        pq.retain_mut(|i, p| {
            *p += 10;
            i.can_swim
        });

        assert_eq!(
            pq.pop(),
            Some((Animal::new("fish".to_string(), false, true), 14))
        );
        assert_eq!(
            pq.pop(),
            Some((Animal::new("dog".to_string(), false, true), 11))
        );
    }

    #[test]
    fn into_sorted_iter() {
        let mut pq = PriorityQueue::new();
        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);

        assert_eq!(
            pq.into_sorted_iter().collect::<Vec<_>>(),
            vec!(("f", 7), ("b", 2), ("a", 1))
        );
    }

    #[test]
    fn iter_mut1() {
        let mut queue: PriorityQueue<&'static str, i32> = Default::default();

        queue.push("a", 0);
        queue.push("b", 1);
        assert_eq!(queue.peek().unwrap().0, &"b");

        let iter_mut = queue.iter_mut();
        for (k, v) in iter_mut {
            if k == &"a" {
                *v = 2;
            }
        }

        assert_eq!(queue.peek().unwrap().0, &"a");
    }

    #[test]
    fn iter_mut_empty() {
        let mut queue: PriorityQueue<&'static str, i32> = Default::default();

        let iter_mut = queue.iter_mut();
        for (k, v) in iter_mut {
            if k == &"a" {
                *v = 2;
            }
        }
    }

    #[test]
    fn eq() {
        let mut a = PriorityQueue::new();
        let mut b = PriorityQueue::new();
        assert_eq!(a, b);

        a.push("a", 1);
        b.push("a", 1);
        assert_eq!(a, b);

        a.push("b", 2);
        assert_ne!(a, b);

        b.push("f", 7);
        b.push("g", 4);
        b.push("h", 3);
        b.push("b", 2);

        a.push("g", 4);
        a.push("f", 7);
        a.push("h", 3);
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn non_default_key() {
        use std::time::*;
        type PqType = PriorityQueue<i32, Instant>;
        let _: PqType = PriorityQueue::default();
    }

    #[test]
    fn conversion() {
        use priority_queue::DoublePriorityQueue;

        let mut dpq = DoublePriorityQueue::new();

        dpq.push('a', 3);
        dpq.push('b', 5);
        dpq.push('c', 1);

        let mut pq: PriorityQueue<_, _> = dpq.into();

        assert_eq!(pq.pop(), Some(('b', 5)));
    }

    #[test]
    fn equivalent_blanket_implementation() {
        let mut pq = PriorityQueue::new();

        // Push with owned String
        pq.push("Alice".to_string(), 10);
        pq.push("Bob".to_string(), 20);

        // Test get_priority with &str (uses String's blanket Equivalent impl)
        assert_eq!(pq.get_priority("Alice"), Some(&10));
        assert_eq!(pq.get_priority("Bob"), Some(&20));
        assert_eq!(pq.get_priority("Charlie"), None);

        // Test contains with &str
        assert!(pq.contains("Alice"));
        assert!(pq.contains("Bob"));
        assert!(!pq.contains("Charlie"));

        // Test change_priority with &str
        assert_eq!(pq.change_priority("Alice", 25), Some(10));
        assert_eq!(pq.get_priority("Alice"), Some(&25));

        // Test change_priority_by with &str
        assert!(pq.change_priority_by("Alice", |p| *p += 5));
        assert_eq!(pq.get_priority("Alice"), Some(&30));

        // Test get with &str
        let (item, priority) = pq.get("Bob").unwrap();
        assert_eq!(item, "Bob");
        assert_eq!(*priority, 20);

        // Test get_mut with &str
        let (item_mut, priority) = pq.get_mut("Bob").unwrap();
        assert_eq!(item_mut, "Bob");
        assert_eq!(*priority, 20);

        // Test remove with &str
        assert_eq!(pq.remove("Bob"), Some(("Bob".to_string(), 20)));
        assert!(!pq.contains("Bob"));
    }

    #[test]
    fn equivalent_custom_implementation() {
        use equivalent::Equivalent;
        use std::hash::Hash;

        #[derive(Debug, PartialEq, Eq, Hash)]
        struct Person {
            id: u32,
            name: String,
            age: u16,
        }

        #[derive(Debug, PartialEq, Eq, Hash)]
        struct PersonView<'a> {
            id: u32,
            name: &'a str,
            age: u16,
        }

        impl<'a> Equivalent<Person> for PersonView<'a> {
            fn equivalent(&self, key: &Person) -> bool {
                self.id == key.id && self.name == key.name && self.age == key.age
            }
        }

        let mut pq = PriorityQueue::new();

        // Create test persons
        let alice = Person {
            id: 1,
            name: "Alice".to_string(),
            age: 30,
        };
        let bob = Person {
            id: 2,
            name: "Bob".to_string(),
            age: 25,
        };

        // Push persons into queue
        pq.push(alice, 100);
        pq.push(bob, 200);

        // Create PersonView instances for querying
        let alice_view = PersonView {
            id: 1,
            name: "Alice",
            age: 30,
        };
        let bob_view = PersonView {
            id: 2,
            name: "Bob",
            age: 25,
        };
        let charlie_view = PersonView {
            id: 3,
            name: "Charlie",
            age: 35,
        };

        // Test get_priority with PersonView
        assert_eq!(pq.get_priority(&alice_view), Some(&100));
        assert_eq!(pq.get_priority(&bob_view), Some(&200));
        assert_eq!(pq.get_priority(&charlie_view), None);

        // Test contains with PersonView
        assert!(pq.contains(&alice_view));
        assert!(pq.contains(&bob_view));
        assert!(!pq.contains(&charlie_view));

        // Test change_priority with PersonView
        assert_eq!(pq.change_priority(&alice_view, 300), Some(100));
        assert_eq!(pq.get_priority(&alice_view), Some(&300));

        // Test change_priority_by with PersonView
        assert!(pq.change_priority_by(&alice_view, |p| *p += 50));
        assert_eq!(pq.get_priority(&alice_view), Some(&350));

        // Test get with PersonView
        let (person, priority) = pq.get(&bob_view).unwrap();
        assert_eq!(person.name, "Bob");
        assert_eq!(*priority, 200);

        // Test get_mut with PersonView
        let (person_mut, priority) = pq.get_mut(&bob_view).unwrap();
        assert_eq!(person_mut.name, "Bob");
        assert_eq!(*priority, 200);

        // Test remove with PersonView
        let removed = pq.remove(&bob_view);
        assert!(removed.is_some());
        let (removed_person, removed_priority) = removed.unwrap();
        assert_eq!(removed_person.id, 2);
        assert_eq!(removed_person.name, "Bob");
        assert_eq!(removed_priority, 200);
        assert!(!pq.contains(&bob_view));
    }
}

#[cfg(all(feature = "serde", test))]
mod serde_tests_basics {
    use priority_queue::PriorityQueue;
    use serde_test::{assert_tokens, Token};

    #[cfg(not(feature = "std"))]
    use core::hash::BuildHasherDefault;
    #[cfg(not(feature = "std"))]
    use twox_hash::XxHash64;

    #[test]
    fn serde_empty() {
        #[cfg(feature = "std")]
        let pq: PriorityQueue<String, i32> = PriorityQueue::new();
        #[cfg(not(feature = "std"))]
        let pq: PriorityQueue<String, i32, BuildHasherDefault<XxHash64>> = PriorityQueue::default();

        assert_tokens(&pq, &[Token::Seq { len: Some(0) }, Token::SeqEnd]);
    }

    #[test]
    fn serde() {
        #[cfg(feature = "std")]
        let mut pq = PriorityQueue::new();
        #[cfg(not(feature = "std"))]
        let mut pq: PriorityQueue<&str, i32, BuildHasherDefault<XxHash64>> =
            PriorityQueue::default();

        pq.push("a", 1);
        pq.push("b", 2);
        pq.push("f", 7);
        pq.push("g", 4);
        pq.push("h", 3);

        assert_tokens(
            &pq,
            &[
                Token::Seq { len: Some(5) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("a"),
                Token::I32(1),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("b"),
                Token::I32(2),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("f"),
                Token::I32(7),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("g"),
                Token::I32(4),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("h"),
                Token::I32(3),
                Token::TupleEnd,
                Token::SeqEnd,
            ],
        );
    }
}

//more complex tests
//thanks to ckaran
#[cfg(all(feature = "serde", test))]
mod serde_tests_custom_structs {
    use core::cmp::{Ord, Ordering, PartialOrd};
    use core::default::Default;
    use core::time::Duration;
    use priority_queue::PriorityQueue;
    use uuid::Uuid;

    #[cfg(not(feature = "std"))]
    use core::hash::BuildHasherDefault;
    #[cfg(not(feature = "std"))]
    use twox_hash::XxHash64;

    use serde::{Deserialize, Serialize};

    // Abusing Duration as a mutable std::time::Instant
    type ActivationDate = Duration;

    /// Events are compared by EventComparables instances.
    ///
    /// EventComparables instances are similar to instances of time, but with the
    /// extra wrinkle of having a Uuid instance.  When EventComparables instances
    /// are compared, they are first compared by their activation date, with the
    /// date that occurs earlier being greater than a date that occurs later. This
    /// ordering exists because of how priority_queue::PriorityQueue works; it is
    /// naturally a max priority queue; using this ordering makes it a min
    /// priority queue. EventComparables go one step beyond using time as the key
    /// though; they  also have uuid::Uuid instances which are used to guarantee
    /// that every EventComparables is unique.  This ensures that if a set of
    /// events all  occur at the same time, they will still be executed in a
    /// deterministic order, every single time the queue's contents are executed.
    /// This is  critical for deterministic simulators.
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
    #[serde(default)]
    #[serde(deny_unknown_fields)]
    struct EventComparables {
        /// This is when the event will be fired.
        activation_date: ActivationDate,

        /// This is a unique ID.  Except for ensuring that different events are
        /// guaranteed to compare as being different, it has no purpose.
        id: Uuid,
    }

    /// Default events activate at time (0, 0)
    ///
    /// All default events first at time (0, 0), but every single one has a unique
    /// id.  This ensures that regardless of the number of default events you
    /// create, they will always execute in the same order.
    impl Default for EventComparables {
        fn default() -> Self {
            EventComparables {
                activation_date: ActivationDate::new(0, 0),
                id: Uuid::new_v4(),
            }
        }
    }

    /// The priority queue depends on `Ord`. Explicitly implement the trait so the
    /// queue becomes a min-heap instead of a max-heap.
    impl Ord for EventComparables {
        fn cmp(&self, other: &Self) -> Ordering {
            // Notice that the we flip the ordering on costs. In case of a tie we
            // compare by id - this step is necessary to make implementations of
            // `PartialEq` and `Ord` consistent.

            other
                .activation_date
                .cmp(&self.activation_date)
                .then_with(|| self.id.cmp(&other.id))
        }
    }

    // `PartialOrd` needs to be implemented as well.
    impl PartialOrd for EventComparables {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    /// A fake event to fire on some date.
    ///
    /// This is a fake event that I'll fire when the corresponding
    /// EventComparables instance comes up.  The contents are immaterial; I'm just
    /// using it for testing
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
    #[serde(default)]
    #[serde(deny_unknown_fields)]
    struct ConcreteEvent1 {
        a: i32,
        b: i64,
    }

    impl Default for ConcreteEvent1 {
        fn default() -> Self {
            ConcreteEvent1 { a: 0, b: 0 }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // Test 1
    //////////////////////////////////////////////////////////////////////////////
    #[test]
    fn test1() {
        println!("test1()");

        #[cfg(feature = "std")]
        type PqType = PriorityQueue<i32, i32>;
        #[cfg(not(feature = "std"))]
        type PqType = PriorityQueue<i32, i32, BuildHasherDefault<XxHash64>>;

        let mut pq: PqType = PriorityQueue::default();
        pq.push(0, 0);
        pq.push(1, 1);

        let serialized = serde_json::to_string(&pq).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: PqType = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
    }

    //////////////////////////////////////////////////////////////////////////////
    // Test 2
    //////////////////////////////////////////////////////////////////////////////
    #[test]
    fn test2() {
        println!("\n\ntest2()");

        #[cfg(feature = "std")]
        type PqType = PriorityQueue<i32, EventComparables>;
        #[cfg(not(feature = "std"))]
        type PqType = PriorityQueue<i32, EventComparables, BuildHasherDefault<XxHash64>>;

        let mut pq: PqType = PriorityQueue::default();
        pq.push(0, Default::default()); // Uuids will be different
        pq.push(1, Default::default());

        let serialized = serde_json::to_string(&pq).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: PqType = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
    }

    //////////////////////////////////////////////////////////////////////////////
    // Test 3
    //////////////////////////////////////////////////////////////////////////////
    #[test]
    fn test3() {
        println!("\n\ntest3()");

        // Create some concrete events and comparables, and test to see that they
        // can be serialized/deserialized

        let ce1 = ConcreteEvent1 { a: 12, b: 45 };
        let ec1 = EventComparables {
            activation_date: ActivationDate::new(0, 1),
            id: Uuid::new_v4(),
        };

        let ce2 = ConcreteEvent1 { a: 37, b: 123 };
        let ec2 = EventComparables {
            activation_date: ActivationDate::new(0, 1),
            id: Uuid::new_v4(),
        };

        let serialized = serde_json::to_string(&ce1).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: ConcreteEvent1 = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        assert_eq!(ce1, deserialized);

        let serialized = serde_json::to_string(&ec1).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: EventComparables = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        assert_eq!(ec1, deserialized);

        let serialized = serde_json::to_string(&ce2).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: ConcreteEvent1 = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        assert_eq!(ce2, deserialized);

        let serialized = serde_json::to_string(&ec2).unwrap();
        println!("serialized = {:?}", serialized);
        let deserialized: EventComparables = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        assert_eq!(ec2, deserialized);

        {
            #[cfg(feature = "std")]
            type PqType = PriorityQueue<ConcreteEvent1, EventComparables>;
            #[cfg(not(feature = "std"))]
            type PqType =
                PriorityQueue<ConcreteEvent1, EventComparables, BuildHasherDefault<XxHash64>>;

            let mut pq: PqType = PriorityQueue::default();
            pq.push(ce1, ec1);
            pq.push(ce2, ec2);

            let serialized = serde_json::to_string(&pq).unwrap();
            println!("serialized = {:?}", serialized);
            let deserialized: PqType = serde_json::from_str(&serialized).unwrap();
            println!("deserialized = {:?}", deserialized);
        }
    }
}
