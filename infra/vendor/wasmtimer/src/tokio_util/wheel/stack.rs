use std::borrow::Borrow;
use std::cmp::Eq;
use std::hash::Hash;

pub(crate) trait Stack: Default {
    type Owned: Borrow<Self::Borrowed>;
    type Borrowed: Eq + Hash;
    type Store;
    fn is_empty(&self) -> bool;
    fn push(&mut self, item: Self::Owned, store: &mut Self::Store);
    fn pop(&mut self, store: &mut Self::Store) -> Option<Self::Owned>;
    fn remove(&mut self, item: &Self::Borrowed, store: &mut Self::Store);
    fn when(item: &Self::Borrowed, store: &Self::Store) -> u64;
}
