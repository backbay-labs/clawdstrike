mod level;
pub(crate) use self::level::Expiration;
use self::level::Level;

mod stack;
pub(crate) use self::stack::Stack;

use std::borrow::Borrow;
use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct Wheel<T> {
    elapsed: u64,
    levels: Vec<Level<T>>,
}

const NUM_LEVELS: usize = 6;

const MAX_DURATION: u64 = (1 << (6 * NUM_LEVELS)) - 1;

#[derive(Debug)]
pub(crate) enum InsertError {
    Elapsed,
    Invalid,
}

impl<T> Wheel<T>
where
    T: Stack,
{
    pub(crate) fn new() -> Wheel<T> {
        let levels = (0..NUM_LEVELS).map(Level::new).collect();

        Wheel { elapsed: 0, levels }
    }

    pub(crate) fn elapsed(&self) -> u64 {
        self.elapsed
    }

    pub(crate) fn insert(
        &mut self,
        when: u64,
        item: T::Owned,
        store: &mut T::Store,
    ) -> Result<(), (T::Owned, InsertError)> {
        if when <= self.elapsed {
            return Err((item, InsertError::Elapsed));
        } else if when - self.elapsed > MAX_DURATION {
            return Err((item, InsertError::Invalid));
        }

        // Get the level at which the entry should be stored
        let level = self.level_for(when);

        self.levels[level].add_entry(when, item, store);

        debug_assert!({
            self.levels[level]
                .next_expiration(self.elapsed)
                .map(|e| e.deadline >= self.elapsed)
                .unwrap_or(true)
        });

        Ok(())
    }

    #[track_caller]
    pub(crate) fn remove(&mut self, item: &T::Borrowed, store: &mut T::Store) {
        let when = T::when(item, store);

        assert!(
            self.elapsed <= when,
            "elapsed={}; when={}",
            self.elapsed,
            when
        );

        let level = self.level_for(when);

        self.levels[level].remove_entry(when, item, store);
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        self.next_expiration().map(|expiration| expiration.deadline)
    }

    pub(crate) fn poll(&mut self, now: u64, store: &mut T::Store) -> Option<T::Owned> {
        loop {
            let expiration = self.next_expiration().and_then(|expiration| {
                if expiration.deadline > now {
                    None
                } else {
                    Some(expiration)
                }
            });

            match expiration {
                Some(ref expiration) => {
                    if let Some(item) = self.poll_expiration(expiration, store) {
                        return Some(item);
                    }

                    self.set_elapsed(expiration.deadline);
                }
                None => {
                    // in this case the poll did not indicate an expiration
                    // _and_ we were not able to find a next expiration in
                    // the current list of timers.  advance to the poll's
                    // current time and do nothing else.
                    self.set_elapsed(now);
                    return None;
                }
            }
        }
    }

    fn next_expiration(&self) -> Option<Expiration> {
        // Check all levels
        for level in 0..NUM_LEVELS {
            if let Some(expiration) = self.levels[level].next_expiration(self.elapsed) {
                // There cannot be any expirations at a higher level that happen
                // before this one.
                debug_assert!(self.no_expirations_before(level + 1, expiration.deadline));

                return Some(expiration);
            }
        }

        None
    }

    fn no_expirations_before(&self, start_level: usize, before: u64) -> bool {
        let mut res = true;

        for l2 in start_level..NUM_LEVELS {
            if let Some(e2) = self.levels[l2].next_expiration(self.elapsed) {
                if e2.deadline < before {
                    res = false;
                }
            }
        }

        res
    }

    pub(crate) fn poll_expiration(
        &mut self,
        expiration: &Expiration,
        store: &mut T::Store,
    ) -> Option<T::Owned> {
        while let Some(item) = self.pop_entry(expiration, store) {
            if expiration.level == 0 {
                debug_assert_eq!(T::when(item.borrow(), store), expiration.deadline);

                return Some(item);
            } else {
                let when = T::when(item.borrow(), store);

                let next_level = expiration.level - 1;

                self.levels[next_level].add_entry(when, item, store);
            }
        }

        None
    }

    fn set_elapsed(&mut self, when: u64) {
        assert!(
            self.elapsed <= when,
            "elapsed={:?}; when={:?}",
            self.elapsed,
            when
        );

        if when > self.elapsed {
            self.elapsed = when;
        }
    }

    fn pop_entry(&mut self, expiration: &Expiration, store: &mut T::Store) -> Option<T::Owned> {
        self.levels[expiration.level].pop_entry_slot(expiration.slot, store)
    }

    fn level_for(&self, when: u64) -> usize {
        level_for(self.elapsed, when)
    }
}

fn level_for(elapsed: u64, when: u64) -> usize {
    const SLOT_MASK: u64 = (1 << 6) - 1;

    // Mask in the trailing bits ignored by the level calculation in order to cap
    // the possible leading zeros
    let masked = elapsed ^ when | SLOT_MASK;

    let leading_zeros = masked.leading_zeros() as usize;
    let significant = 63 - leading_zeros;
    significant / 6
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_level_for() {
        for pos in 0..64 {
            assert_eq!(
                0,
                level_for(0, pos),
                "level_for({}) -- binary = {:b}",
                pos,
                pos
            );
        }

        for level in 1..5 {
            for pos in level..64 {
                let a = pos * 64_usize.pow(level as u32);
                assert_eq!(
                    level,
                    level_for(0, a as u64),
                    "level_for({}) -- binary = {:b}",
                    a,
                    a
                );

                if pos > level {
                    let a = a - 1;
                    assert_eq!(
                        level,
                        level_for(0, a as u64),
                        "level_for({}) -- binary = {:b}",
                        a,
                        a
                    );
                }

                if pos < 64 {
                    let a = a + 1;
                    assert_eq!(
                        level,
                        level_for(0, a as u64),
                        "level_for({}) -- binary = {:b}",
                        a,
                        a
                    );
                }
            }
        }
    }
}
