use std::io::Read;
use crate::util::chunked_stream_reader::ChunkedStreamReader;
use crate::util::mix::{rapid_mix, rapid_mum};
use crate::util::read::{read_u32, read_u64};
use super::{DEFAULT_RAPID_SECRETS, RapidSecrets, rapidhash_finish};

/// Rapidhash a stream or file, matching the C++ implementation.
///
/// This is a streaming implementation of rapidhash v3. It will produce exactly the same output as
/// [`crate::v3::rapidhash_v3`], but accepts a streaming `Read` interface.
#[inline]
pub fn rapidhash_v3_file<R: Read>(data: R) -> std::io::Result<u64> {
    rapidhash_v3_file_inline::<R, false>(data, &DEFAULT_RAPID_SECRETS)
}

/// Rapidhash a stream or file, matching the C++ implementation, with a custom seed.
///
/// This is a streaming implementation of rapidhash v3. It will produce exactly the same output as
/// [`crate::v3::rapidhash_v3_seeded`], but accepts a streaming `Read` interface.
#[inline]
pub fn rapidhash_v3_file_seeded<R: Read>(data: R, secrets: &RapidSecrets) -> std::io::Result<u64> {
    rapidhash_v3_file_inline::<R, false>(data, secrets)
}

/// Rapidhash a stream or file, matching the C++ implementation.
///
/// This is a streaming implementation of rapidhash v3. It will produce exactly the same output as
/// [`crate::v3::rapidhash_v3_inline`], but accepts a streaming `Read` interface.
///
/// Is marked with `#[inline(always)]` to force the compiler to inline and optimize the method.
#[inline(always)]
pub fn rapidhash_v3_file_inline<R: Read, const PROTECTED: bool>(data: R, secrets: &RapidSecrets) -> std::io::Result<u64> {
    let mut reader = ChunkedStreamReader::new(data, 16);
    let hash = rapidhash_file_core::<R, PROTECTED>(secrets.seed, &secrets.secrets, &mut reader)?;
    Ok(hash)
}

#[inline(always)]
fn rapidhash_file_core<R: Read, const PROTECTED: bool>(mut seed: u64, secrets: &[u64; 7], iter: &mut ChunkedStreamReader<R>) -> std::io::Result<u64> {
    let mut a = 0;
    let mut b = 0;

    let mut chunk = iter.read_chunk(225)?;
    let remainder;

    if chunk.len() <= 16 {
        let len = chunk.len();
        if len >= 4 {
            seed ^= len as u64;
            if len >= 8 {
                let plast = len - 8;
                a = read_u64(chunk, 0);
                b = read_u64(chunk, plast);
            } else {
                let plast = len - 4;
                a = read_u32(chunk, 0) as u64;
                b = read_u32(chunk, plast) as u64;
            }
        } else if len > 0 {
            a = ((chunk[0] as u64) << 45) | chunk[len - 1] as u64;
            b = chunk[len >> 1] as u64;
        }
        remainder = chunk.len() as u64;
    } else {
        // because we're using a buffered reader, it might be worth unrolling this loop further
        let mut see1 = seed;
        let mut see2 = seed;
        let mut see3 = seed;
        let mut see4 = seed;
        let mut see5 = seed;
        let mut see6 = seed;

        while chunk.len() > 224 {
            seed = rapid_mix::<PROTECTED>(read_u64(chunk, 0) ^ secrets[0], read_u64(chunk, 8) ^ seed);
            see1 = rapid_mix::<PROTECTED>(read_u64(chunk, 16) ^ secrets[1], read_u64(chunk, 24) ^ see1);
            see2 = rapid_mix::<PROTECTED>(read_u64(chunk, 32) ^ secrets[2], read_u64(chunk, 40) ^ see2);
            see3 = rapid_mix::<PROTECTED>(read_u64(chunk, 48) ^ secrets[3], read_u64(chunk, 56) ^ see3);
            see4 = rapid_mix::<PROTECTED>(read_u64(chunk, 64) ^ secrets[4], read_u64(chunk, 72) ^ see4);
            see5 = rapid_mix::<PROTECTED>(read_u64(chunk, 80) ^ secrets[5], read_u64(chunk, 88) ^ see5);
            see6 = rapid_mix::<PROTECTED>(read_u64(chunk, 96) ^ secrets[6], read_u64(chunk, 104) ^ see6);

            seed = rapid_mix::<PROTECTED>(read_u64(chunk, 112) ^ secrets[0], read_u64(chunk, 120) ^ seed);
            see1 = rapid_mix::<PROTECTED>(read_u64(chunk, 128) ^ secrets[1], read_u64(chunk, 136) ^ see1);
            see2 = rapid_mix::<PROTECTED>(read_u64(chunk, 144) ^ secrets[2], read_u64(chunk, 152) ^ see2);
            see3 = rapid_mix::<PROTECTED>(read_u64(chunk, 160) ^ secrets[3], read_u64(chunk, 168) ^ see3);
            see4 = rapid_mix::<PROTECTED>(read_u64(chunk, 176) ^ secrets[4], read_u64(chunk, 184) ^ see4);
            see5 = rapid_mix::<PROTECTED>(read_u64(chunk, 192) ^ secrets[5], read_u64(chunk, 200) ^ see5);
            see6 = rapid_mix::<PROTECTED>(read_u64(chunk, 208) ^ secrets[6], read_u64(chunk, 216) ^ see6);

            iter.consume(224);
            chunk = iter.read_chunk(225)?;  // must read 1 more byte for > 224
        }

        if chunk.len() > 112 {
            seed = rapid_mix::<PROTECTED>(read_u64(chunk, 0) ^ secrets[0], read_u64(chunk, 8) ^ seed);
            see1 = rapid_mix::<PROTECTED>(read_u64(chunk, 16) ^ secrets[1], read_u64(chunk, 24) ^ see1);
            see2 = rapid_mix::<PROTECTED>(read_u64(chunk, 32) ^ secrets[2], read_u64(chunk, 40) ^ see2);
            see3 = rapid_mix::<PROTECTED>(read_u64(chunk, 48) ^ secrets[3], read_u64(chunk, 56) ^ see3);
            see4 = rapid_mix::<PROTECTED>(read_u64(chunk, 64) ^ secrets[4], read_u64(chunk, 72) ^ see4);
            see5 = rapid_mix::<PROTECTED>(read_u64(chunk, 80) ^ secrets[5], read_u64(chunk, 88) ^ see5);
            see6 = rapid_mix::<PROTECTED>(read_u64(chunk, 96) ^ secrets[6], read_u64(chunk, 104) ^ see6);

            chunk = &chunk[112..chunk.len()];
        }

        seed ^= see1;
        see2 ^= see3;
        see4 ^= see5;
        seed ^= see6;
        see2 ^= see4;
        seed ^= see2;

        if chunk.len() > 16 {
            seed = rapid_mix::<PROTECTED>(read_u64(chunk, 0) ^ secrets[2], read_u64(chunk, 8) ^ seed);
            if chunk.len() > 32 {
                seed = rapid_mix::<PROTECTED>(read_u64(chunk, 16) ^ secrets[2], read_u64(chunk, 24) ^ seed);
                if chunk.len() > 48 {
                    seed = rapid_mix::<PROTECTED>(read_u64(chunk, 32) ^ secrets[1], read_u64(chunk, 40) ^ seed);
                    if chunk.len() > 64 {
                        seed = rapid_mix::<PROTECTED>(read_u64(chunk, 48) ^ secrets[1], read_u64(chunk, 56) ^ seed);
                        if chunk.len() > 80 {
                            seed = rapid_mix::<PROTECTED>(read_u64(chunk, 64) ^ secrets[2], read_u64(chunk, 72) ^ seed);
                            if chunk.len() > 96 {
                                seed = rapid_mix::<PROTECTED>(read_u64(chunk, 80) ^ secrets[1], read_u64(chunk, 88) ^ seed);
                            }
                        }
                    }
                }
            }
        }

        remainder = chunk.len() as u64;
        let last = iter.last_read();
        a ^= read_u64(last, last.len() - 16) ^ remainder;
        b ^= read_u64(last, last.len() - 8);
    }

    a ^= secrets[1];
    b ^= seed;

    (a, b) = rapid_mum::<PROTECTED>(a, b);
    Ok(rapidhash_finish::<PROTECTED>(a, b, remainder, secrets))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use crate::util::macros::compare_rapidhash_file;
    use crate::v3::rapidhash_v3_inline;
    use super::*;

    compare_rapidhash_file!(compare_rapidhash_v1_file, rapidhash_v3_inline::<true, false, false>, rapidhash_v3_file_inline::<_, false>);
}
