use crate::{byte2hex, Output, HEX_DECODE_LUT, NIL};
use core::mem::size_of;

/// Set to `true` to use `check` + `decode_unchecked` for decoding. Otherwise uses `decode_checked`.
///
/// This should be set to `false` if `check` is not specialized.
#[allow(dead_code)]
pub(crate) const USE_CHECK_FN: bool = false;

/// Default encoding function.
///
/// # Safety
///
/// `output` must be at least `2 * input.len()` bytes long.
pub(crate) unsafe fn encode<const UPPER: bool>(input: &[u8], mut output: impl Output) {
    for &byte in input {
        let (high, low) = byte2hex::<UPPER>(byte);
        output.write_byte(high);
        output.write_byte(low);
    }
}

/// Encodes unaligned chunks of `T` in `input` to `output` using `encode_chunk`.
///
/// The remainder is encoded using the generic [`encode`].
#[inline]
#[allow(dead_code)]
pub(crate) unsafe fn encode_unaligned_chunks<const UPPER: bool, T: Copy, U: Copy>(
    input: &[u8],
    mut output: impl Output,
    mut encode_chunk: impl FnMut(T) -> U,
) {
    debug_assert_eq!(size_of::<U>(), size_of::<T>() * 2);
    let (chunks, remainder) = chunks_unaligned::<T>(input);
    for chunk in chunks {
        output.write(as_bytes(&encode_chunk(chunk)));
    }
    unsafe { encode::<UPPER>(remainder, output) };
}

/// Default check function.
#[inline]
pub(crate) const fn check(mut input: &[u8]) -> bool {
    while let &[byte, ref rest @ ..] = input {
        if HEX_DECODE_LUT[byte as usize] == NIL {
            return false;
        }
        input = rest;
    }
    true
}

/// Runs the given check function on unaligned chunks of `T` in `input`, with the remainder passed
/// to the generic [`check`].
#[inline]
#[allow(dead_code)]
pub(crate) fn check_unaligned_chunks<T: Copy>(
    input: &[u8],
    check_chunk: impl FnMut(T) -> bool,
) -> bool {
    let (mut chunks, remainder) = chunks_unaligned(input);
    chunks.all(check_chunk) && check(remainder)
}

/// Default checked decoding function.
///
/// # Safety
///
/// Assumes `output.len() == input.len() / 2`.
pub(crate) unsafe fn decode_checked(input: &[u8], output: &mut [u8]) -> bool {
    unsafe { decode_maybe_check::<true>(input, output) }
}

/// Default unchecked decoding function.
///
/// # Safety
///
/// Assumes `output.len() == input.len() / 2` and that the input is valid hex.
pub(crate) unsafe fn decode_unchecked(input: &[u8], output: impl Output) {
    #[allow(unused_braces)] // False positive on older rust versions.
    let success = unsafe { decode_maybe_check::<{ cfg!(debug_assertions) }>(input, output) };
    debug_assert!(success);
}

/// Default decoding function. Checks input validity if `CHECK` is `true`, otherwise assumes it.
///
/// # Safety
///
/// Assumes `output.len() == input.len() / 2` and that the input is valid hex if `CHECK` is `true`.
#[inline(always)]
unsafe fn decode_maybe_check<const CHECK: bool>(input: &[u8], mut output: impl Output) -> bool {
    macro_rules! next {
        ($var:ident, $i:expr) => {
            let hex = unsafe { *input.get_unchecked($i) };
            let $var = HEX_DECODE_LUT[hex as usize];
            if CHECK {
                if $var == NIL {
                    return false;
                }
            }
        };
    }

    let l = output.remaining().unwrap_or(input.len() / 2);
    debug_assert_eq!(l, input.len() / 2);
    let mut i = 0;
    while i < l {
        next!(high, i * 2);
        next!(low, i * 2 + 1);
        output.write_byte(high << 4 | low);
        i += 1;
    }
    true
}

/// Decodes unaligned chunks of `U` in `input` to `output` using `decode_chunk`.
///
/// The remainder is decoded using the generic [`decode_unchecked`].
#[inline]
#[allow(dead_code)]
pub(crate) unsafe fn decode_unchecked_unaligned_chunks<T: Copy, U: Copy>(
    input: &[u8],
    mut output: impl Output,
    mut decode_chunk: impl FnMut(U) -> T,
) {
    debug_assert_eq!(size_of::<U>(), size_of::<T>() * 2);
    let (chunks, remainder) = chunks_unaligned::<U>(input);
    for chunk in chunks {
        output.write(as_bytes(&decode_chunk(chunk)));
    }
    unsafe { decode_unchecked(remainder, output) };
}

#[inline]
fn chunks_unaligned<T: Copy>(input: &[u8]) -> (impl ExactSizeIterator<Item = T> + '_, &[u8]) {
    let chunks = input.chunks_exact(core::mem::size_of::<T>());
    let remainder = chunks.remainder();
    (
        chunks.map(|chunk| unsafe { chunk.as_ptr().cast::<T>().read_unaligned() }),
        remainder,
    )
}

#[inline]
const fn as_bytes<T: Copy>(x: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(x as *const _ as *const u8, size_of::<T>()) }
}
