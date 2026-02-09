macro_rules! impl_sha3 {
    ($name:ident, $output_size:ident, $rate:ident, $pad:expr, $alg_name:expr $(,)?) => {
        #[doc = concat!($alg_name, " hasher state.")]
        #[derive(Clone)]
        pub struct $name {
            #[doc(hidden)]
            state: Sha3State<{ <$output_size>::USIZE * 8 }, $pad>,
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self { state: Default::default() }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state.reset();
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                unsafe { self.state.update(data.as_ptr(), data.len()) }
            }
        }

        impl FixedOutput for $name {
            #[inline]
            fn finalize_into(mut self, out: &mut Output<Self>) {
                unsafe { self.state.finalize(out.as_mut_ptr()) }
            }
        }

        impl FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                unsafe { self.state.finalize(out.as_mut_ptr()) };
                Reset::reset(self);
            }
        }

        impl $name {
            /// Specialization of [`Digest::digest`] to avoid unnecessary intermediate stack copies.
            ///
            /// See: <https://github.com/rust-lang/rust/issues/146056>
            pub fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
                let data = data.as_ref();
                let mut s = Self::new();
                let mut out = core::mem::MaybeUninit::<Output<Self>>::uninit();
                unsafe {
                    s.state.update(data.as_ptr(), data.len());
                    s.state.finalize(out.as_mut_ptr().cast());
                    out.assume_init()
                }
            }
        }
    };

    (
        $name:ident, $output_size:ident, $rate:ident, $pad:expr, $alg_name:expr, $oid:literal $(,)?
    ) => {
        impl_sha3!($name, $output_size, $rate, $pad, $alg_name);

        #[cfg(feature = "oid")]
        #[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}
