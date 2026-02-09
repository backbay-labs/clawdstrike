/// Wrapper for [`ruint_macro::uint!`]. See its documentation for details.
#[macro_export]
#[cfg(not(doc))] // Show the actual macro in docs.
#[doc(hidden)]
macro_rules! uint {
    ($($t:tt)*) => {
        $crate::__private::ruint_macro::uint_with_path! { [$crate] $($t)* }
    }
}

macro_rules! impl_bin_op {
    ($trait:ident, $fn:ident, $trait_assign:ident, $fn_assign:ident, $fdel:ident) => {
        impl<const BITS: usize, const LIMBS: usize> $trait_assign<Uint<BITS, LIMBS>>
            for Uint<BITS, LIMBS>
        {
            #[inline(always)]
            #[track_caller]
            fn $fn_assign(&mut self, rhs: Uint<BITS, LIMBS>) {
                *self = self.$fdel(rhs);
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $trait_assign<&Uint<BITS, LIMBS>>
            for Uint<BITS, LIMBS>
        {
            #[inline(always)]
            #[track_caller]
            fn $fn_assign(&mut self, rhs: &Uint<BITS, LIMBS>) {
                *self = self.$fdel(*rhs);
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $trait<Uint<BITS, LIMBS>>
            for Uint<BITS, LIMBS>
        {
            type Output = Uint<BITS, LIMBS>;

            #[inline(always)]
            #[track_caller]
            fn $fn(self, rhs: Uint<BITS, LIMBS>) -> Self::Output {
                self.$fdel(rhs)
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $trait<&Uint<BITS, LIMBS>>
            for Uint<BITS, LIMBS>
        {
            type Output = Uint<BITS, LIMBS>;

            #[inline(always)]
            #[track_caller]
            fn $fn(self, rhs: &Uint<BITS, LIMBS>) -> Self::Output {
                self.$fdel(*rhs)
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $trait<Uint<BITS, LIMBS>>
            for &Uint<BITS, LIMBS>
        {
            type Output = Uint<BITS, LIMBS>;

            #[inline(always)]
            #[track_caller]
            fn $fn(self, rhs: Uint<BITS, LIMBS>) -> Self::Output {
                self.$fdel(rhs)
            }
        }
        impl<const BITS: usize, const LIMBS: usize> $trait<&Uint<BITS, LIMBS>>
            for &Uint<BITS, LIMBS>
        {
            type Output = Uint<BITS, LIMBS>;

            #[inline(always)]
            #[track_caller]
            fn $fn(self, rhs: &Uint<BITS, LIMBS>) -> Self::Output {
                self.$fdel(*rhs)
            }
        }
    };
}

macro_rules! assume {
    ($e:expr $(,)?) => {
        if !$e {
            debug_unreachable!(stringify!($e));
        }
    };

    ($e:expr, $($t:tt)+) => {
        if !$e {
            debug_unreachable!($($t)+);
        }
    };
}

macro_rules! debug_unreachable {
    ($($t:tt)*) => {
        if cfg!(debug_assertions) {
            unreachable!($($t)*);
        } else {
            unsafe { core::hint::unreachable_unchecked() };
        }
    };
}

/// `let $id = &mut [0u64; nlimbs(2 * BITS)][..]`
macro_rules! let_double_bits {
    ($id:ident) => {
        // This array casting is a workaround for `generic_const_exprs` not being
        // stable.
        let mut double = [[0u64; 2]; LIMBS];
        let double_len = crate::nlimbs(2 * BITS);
        debug_assert!(2 * LIMBS >= double_len);
        // SAFETY: `[[u64; 2]; LIMBS] == [u64; 2 * LIMBS] >= [u64; nlimbs(2 * BITS)]`.
        let $id = unsafe {
            core::slice::from_raw_parts_mut(double.as_mut_ptr().cast::<u64>(), double_len)
        };
    };
}

/// Specialize an operation for u64, u128, u256 ([u128; 2])...
macro_rules! as_primitives {
    ($uint:expr, { $($arm:ident $t:tt => $e:expr),* $(,)? }) => {
        $(
            as_primitives!(@arm $uint; $arm $t => $e);
        )*
    };

    (@arm $uint:expr; u64($n:ident) => $e:expr) => {
        if LIMBS == 1 {
            let $n = $uint.limbs[0];
            $e
        }
    };
    (@arm $uint:expr; u128($n:ident) => $e:expr) => {
        if LIMBS == 2 {
            let $n = $uint.as_double_words()[0].get();
            $e
        }
    };
    (@arm $uint:expr; u256($lo:ident, $hi:ident) => $e:expr) => {
        if LIMBS == 4 {
            let &[lo, hi] = $uint.as_double_words() else { unreachable!() };
            let $lo = lo.get();
            let $hi = hi.get();
            $e
        }
    };
}

#[cfg(test)]
mod tests {
    // https://github.com/recmo/uint/issues/359
    ruint_macro::uint_with_path! {
        [crate]
        const _A: [crate::aliases::U256; 2] = [
            0x00006f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5_U256,
            0x00004b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8_U256,
        ];
    }

    crate::uint! {
        const _B: [crate::aliases::U256; 2] = [
            0x00006f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5_U256,
            0x00004b4110c9ae997782e1509b1d0fdb20a7c02bbd8bea7305462b9f8125b1e8_U256,
        ];
    }

    #[test]
    fn test_uint_macro_with_paths() {
        extern crate self as aaa;
        use crate as ruint;
        use crate as __ruint;
        let value = crate::aliases::U256::from(0x10);
        assert_eq!(value, uint!(0x10U256));
        assert_eq!(value, ruint_macro::uint_with_path!([crate] 0x10U256));
        assert_eq!(value, ruint_macro::uint_with_path!([aaa] 0x10U256));
        assert_eq!(value, ruint_macro::uint_with_path!([aaa] 0x10U256));
        assert_eq!(value, ruint_macro::uint_with_path!([ruint] 0x10U256));
        assert_eq!(value, ruint_macro::uint_with_path!([__ruint] 0x10U256));
    }
}
