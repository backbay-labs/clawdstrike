//! ⚠️ Collection of bignum algorithms.
//!
//! <div class="warning">
//! Functions in this module are currently not considered part of the stable API
//! and may be changed or removed in future minor releases, without prior
//! notice.
//! </div>

#![allow(missing_docs)] // TODO: document algorithms

macro_rules! unstable_warning {
    () => {
        "\n\n<div class=\"warning\">⚠️ This function is not part of the stable API.</div>\n\n"
    };
}
pub(crate) use unstable_warning;

use core::cmp::Ordering;

mod add;
pub mod div;
mod gcd;
mod mul;
mod mul_redc;
mod shift;

pub use self::{
    add::{borrowing_sub, borrowing_sub_n, carrying_add, carrying_add_n},
    div::div,
    gcd::{LehmerMatrix, gcd, gcd_extended, inv_mod},
    mul::{add_nx1, addmul, addmul_n, addmul_nx1, mul_nx1, submul_nx1},
    mul_redc::{mul_redc, square_redc},
    shift::{shift_left_small, shift_right_small},
};

pub(crate) trait DoubleWord<T: Default>: Sized + Copy {
    /// `high << 64 | low`
    fn join(high: T, low: T) -> Self;
    /// `(low, high)`
    fn split(self) -> (T, T);

    /// `a * b + c + d`
    fn muladd2(a: T, b: T, c: T, d: T) -> Self;

    /// `a + b`
    #[inline(always)]
    fn add(a: T, b: T) -> Self {
        Self::muladd2(T::default(), T::default(), a, b)
    }
    /// `a * b`
    #[inline(always)]
    fn mul(a: T, b: T) -> Self {
        Self::muladd2(a, b, T::default(), T::default())
    }
    /// `a * b + c`
    #[inline(always)]
    fn muladd(a: T, b: T, c: T) -> Self {
        Self::muladd2(a, b, c, T::default())
    }

    #[inline(always)]
    fn high(self) -> T {
        self.split().1
    }
    #[inline(always)]
    fn low(self) -> T {
        self.split().0
    }
}

#[allow(clippy::cast_possible_truncation)]
impl DoubleWord<u64> for u128 {
    #[inline(always)]
    fn join(high: u64, low: u64) -> Self {
        (Self::from(high) << 64) | Self::from(low)
    }

    #[inline(always)]
    fn split(self) -> (u64, u64) {
        (self as u64, (self >> 64) as u64)
    }

    #[inline(always)]
    fn muladd2(a: u64, b: u64, c: u64, d: u64) -> Self {
        #[cfg(feature = "nightly")]
        {
            let (low, high) = u64::carrying_mul_add(a, b, c, d);
            Self::join(high, low)
        }
        #[cfg(not(feature = "nightly"))]
        {
            Self::from(a) * Self::from(b) + Self::from(c) + Self::from(d)
        }
    }
}

/// ⚠️ Compare two limb slices in reverse order.
#[doc = crate::algorithms::unstable_warning!()]
/// Assumes that if the slices are of different length, the longer slice is
/// always greater than the shorter slice.
#[inline(always)]
#[must_use]
pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {}
        non_eq => return non_eq,
    }
    for i in (0..a.len()).rev() {
        match i8::from(a[i] > b[i]) - i8::from(a[i] < b[i]) {
            -1 => return Ordering::Less,
            0 => {}
            1 => return Ordering::Greater,
            _ => unsafe { core::hint::unreachable_unchecked() },
        }

        // Equivalent to the following code, but on older rustc versions
        // performs better:
        // match a[i].cmp(&b[i]) {
        //     Ordering::Equal => {}
        //     non_eq => return non_eq,
        // }
    }
    Ordering::Equal
}

#[inline]
pub(crate) const fn trim_end_zeros(mut x: &[u64]) -> &[u64] {
    while let [rest @ .., 0] = x {
        x = rest;
    }
    x
}

#[inline]
pub(crate) fn trim_end_zeros_mut(mut x: &mut [u64]) -> &mut [u64] {
    while let [rest @ .., 0] = x {
        x = rest;
    }
    x
}
