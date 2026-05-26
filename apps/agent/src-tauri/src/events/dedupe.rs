//! Event ID dedupe ring buffer used to suppress replays between SSE and poll fallback.

use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
pub(super) struct EventDeduper {
    order: VecDeque<String>,
    set: HashSet<String>,
    max: usize,
}

impl EventDeduper {
    pub(super) fn new(max: usize) -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            max,
        }
    }

    pub(super) fn insert_if_new(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }

        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());

        while self.order.len() > self.max {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }

        true
    }
}
