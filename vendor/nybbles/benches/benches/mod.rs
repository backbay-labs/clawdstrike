mod clone;
mod cmp;
mod convert;
mod iter;
mod ops;
mod slice;

pub(crate) mod prelude;

pub fn group(c: &mut criterion::Criterion) {
    convert::group(c);
    ops::group(c);
    slice::group(c);
    iter::group(c);
    cmp::group(c);
    clone::group(c);
}
