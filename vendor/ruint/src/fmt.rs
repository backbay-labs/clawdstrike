#![allow(clippy::missing_inline_in_public_items)] // allow format functions

use crate::Uint;
use core::{
    fmt::{self, Write},
    mem::MaybeUninit,
};

mod base {
    pub(super) trait Base {
        /// The base.
        const BASE: u64;
        /// The prefix for the base.
        const PREFIX: &'static str;

        /// Highest power of the base that fits in a `u64`.
        const MAX: u64 = crate::utils::max_pow_u64(Self::BASE);
        /// Number of characters written using `MAX` as the base in
        /// `to_base_be`.
        const WIDTH: usize = Self::MAX.ilog(Self::BASE) as _;
    }

    pub(super) struct Binary;
    impl Base for Binary {
        const BASE: u64 = 2;
        const PREFIX: &'static str = "0b";
    }

    pub(super) struct Octal;
    impl Base for Octal {
        const BASE: u64 = 8;
        const PREFIX: &'static str = "0o";
    }

    pub(super) struct Decimal;
    impl Base for Decimal {
        const BASE: u64 = 10;
        const PREFIX: &'static str = "";
    }

    pub(super) struct Hexadecimal;
    impl Base for Hexadecimal {
        const BASE: u64 = 16;
        const PREFIX: &'static str = "0x";
    }
}
use base::Base;

macro_rules! impl_fmt {
    ($tr:path; $base:ty, $base_char:literal) => {
        impl<const BITS: usize, const LIMBS: usize> $tr for Uint<BITS, LIMBS> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if let Ok(small) = u64::try_from(self) {
                    return <u64 as $tr>::fmt(&small, f);
                }
                if let Ok(small) = u128::try_from(self) {
                    return <u128 as $tr>::fmt(&small, f);
                }

                // Use `BITS` for all bases since `generic_const_exprs` is not yet stable.
                let mut s = StackString::<BITS>::new();
                let mut first = true;
                for spigot in self.to_base_be_2(<$base>::MAX) {
                    write!(
                        s,
                        concat!("{:0width$", $base_char, "}"),
                        spigot,
                        width = if first { 0 } else { <$base>::WIDTH },
                    )
                    .unwrap();
                    first = false;
                }
                f.pad_integral(true, <$base>::PREFIX, s.as_str())
            }
        }
    };
}

impl<const BITS: usize, const LIMBS: usize> fmt::Debug for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl_fmt!(fmt::Display; base::Decimal, "");
impl_fmt!(fmt::Binary; base::Binary, "b");
impl_fmt!(fmt::Octal; base::Octal, "o");
impl_fmt!(fmt::LowerHex; base::Hexadecimal, "x");
impl_fmt!(fmt::UpperHex; base::Hexadecimal, "X");

/// A stack-allocated buffer that implements [`fmt::Write`].
pub(crate) struct StackString<const SIZE: usize> {
    len: usize,
    buf: [MaybeUninit<u8>; SIZE],
}

impl<const SIZE: usize> StackString<SIZE> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            len: 0,
            buf: unsafe { MaybeUninit::uninit().assume_init() },
        }
    }

    #[inline]
    pub(crate) const fn as_str(&self) -> &str {
        // SAFETY: `buf` is only written to by the `fmt::Write::write_str`
        // implementation which writes a valid UTF-8 string to `buf` and
        // correctly sets `len`.
        unsafe { core::str::from_utf8_unchecked(self.as_bytes()) }
    }

    #[inline]
    const fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast(), self.len) }
    }
}

impl<const SIZE: usize> fmt::Write for StackString<SIZE> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.len + s.len() > SIZE {
            return Err(fmt::Error);
        }
        unsafe {
            let dst = self.buf.as_mut_ptr().add(self.len).cast();
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len());
        }
        self.len += s.len();
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        let clen = c.len_utf8();
        if self.len + clen > SIZE {
            return Err(fmt::Error);
        }
        c.encode_utf8(unsafe {
            core::slice::from_raw_parts_mut(self.buf.as_mut_ptr().add(self.len).cast(), clen)
        });
        self.len += clen;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert_eq, proptest};

    #[allow(unused_imports)]
    use alloc::string::ToString;

    #[allow(clippy::unreadable_literal)]
    const N: Uint<256, 4> = Uint::from_limbs([
        0xa8ec92344438aaf4_u64,
        0x9819ebdbd1faaab1_u64,
        0x573b1a7064c19c1a_u64,
        0xc85ef7d79691fe79_u64,
    ]);

    #[test]
    fn test_num() {
        assert_eq!(
            N.to_string(),
            "90630363884335538722706632492458228784305343302099024356772372330524102404852"
        );
        assert_eq!(
            format!("{N:x}"),
            "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"
        );
        assert_eq!(
            format!("{N:b}"),
            "1100100001011110111101111101011110010110100100011111111001111001010101110011101100011010011100000110010011000001100111000001101010011000000110011110101111011011110100011111101010101010101100011010100011101100100100100011010001000100001110001010101011110100"
        );
        assert_eq!(
            format!("{N:o}"),
            "14413675753626443771712563543234062301470152300636573364375252543243544443210416125364"
        );
    }

    #[test]
    fn test_fmt() {
        proptest!(|(value: u128)| {
            let n: Uint<128, 2> = Uint::from(value);

            prop_assert_eq!(format!("{n:b}"), format!("{value:b}"));
            prop_assert_eq!(format!("{n:064b}"), format!("{value:064b}"));
            prop_assert_eq!(format!("{n:#b}"), format!("{value:#b}"));

            prop_assert_eq!(format!("{n:o}"), format!("{value:o}"));
            prop_assert_eq!(format!("{n:064o}"), format!("{value:064o}"));
            prop_assert_eq!(format!("{n:#o}"), format!("{value:#o}"));

            prop_assert_eq!(format!("{n:}"), format!("{value:}"));
            prop_assert_eq!(format!("{n:064}"), format!("{value:064}"));
            prop_assert_eq!(format!("{n:#}"), format!("{value:#}"));
            prop_assert_eq!(format!("{n:?}"), format!("{value:?}"));
            prop_assert_eq!(format!("{n:064}"), format!("{value:064?}"));
            prop_assert_eq!(format!("{n:#?}"), format!("{value:#?}"));

            prop_assert_eq!(format!("{n:x}"), format!("{value:x}"));
            prop_assert_eq!(format!("{n:064x}"), format!("{value:064x}"));
            prop_assert_eq!(format!("{n:#x}"), format!("{value:#x}"));

            prop_assert_eq!(format!("{n:X}"), format!("{value:X}"));
            prop_assert_eq!(format!("{n:064X}"), format!("{value:064X}"));
            prop_assert_eq!(format!("{n:#X}"), format!("{value:#X}"));
        });
    }
}
