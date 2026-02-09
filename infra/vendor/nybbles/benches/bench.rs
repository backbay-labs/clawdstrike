#![allow(clippy::incompatible_msrv)]
#![allow(unexpected_cfgs)]

use criterion::{criterion_group, criterion_main};

mod benches;
pub(crate) use benches::prelude;

criterion_group!(bench, benches::group);
criterion_main!(bench);
