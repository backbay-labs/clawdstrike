use crate::KzgSettings;
use alloc::{boxed::Box, sync::Arc};
use once_cell::race::OnceBox;

/// Default G1 monomial bytes.
const ETH_G1_MONOMIAL_POINTS: &[u8] = include_bytes!("./g1_monomial_bytes.bin");
/// Default G1 Lagrange bytes.
const ETH_G1_LAGRANGE_POINTS: &[u8] = include_bytes!("./g1_lagrange_bytes.bin");
/// Default G2 monomial bytes.
const ETH_G2_MONOMIAL_POINTS: &[u8] = include_bytes!("./g2_monomial_bytes.bin");

macro_rules! create_cache {
    ($name:ident) => {
        static $name: OnceBox<Arc<KzgSettings>> = OnceBox::new();
    };
}

// We use separate OnceBox instances for each precompute value.
// This avoids the need for any unsafe code or mutexes.
create_cache!(CACHE_0);
create_cache!(CACHE_1);
create_cache!(CACHE_2);
create_cache!(CACHE_3);
create_cache!(CACHE_4);
create_cache!(CACHE_5);
create_cache!(CACHE_6);
create_cache!(CACHE_7);
create_cache!(CACHE_8);
create_cache!(CACHE_9);
create_cache!(CACHE_10);
create_cache!(CACHE_11);
create_cache!(CACHE_12);
create_cache!(CACHE_13);
create_cache!(CACHE_14);
create_cache!(CACHE_15);

/// Returns default Ethereum mainnet KZG settings.
///
/// If you need a cloneable settings use `ethereum_kzg_settings_arc` instead.
///
/// Note: Precompute values 0-15 (inclusive) are supported.
pub fn ethereum_kzg_settings(precompute: u64) -> &'static KzgSettings {
    ethereum_kzg_settings_inner(precompute).as_ref()
}

/// Returns default Ethereum mainnet KZG settings as an `Arc`.
///
/// It is useful for sharing the settings in multiple places.
///
/// Note: Precompute values 0-15 (inclusive) are supported.
pub fn ethereum_kzg_settings_arc(precompute: u64) -> Arc<KzgSettings> {
    ethereum_kzg_settings_inner(precompute).clone()
}

fn ethereum_kzg_settings_inner(precompute: u64) -> &'static Arc<KzgSettings> {
    let cache_box = match precompute {
        0 => &CACHE_0,
        1 => &CACHE_1,
        2 => &CACHE_2,
        3 => &CACHE_3,
        4 => &CACHE_4,
        5 => &CACHE_5,
        6 => &CACHE_6,
        7 => &CACHE_7,
        8 => &CACHE_8,
        9 => &CACHE_9,
        10 => &CACHE_10,
        11 => &CACHE_11,
        12 => &CACHE_12,
        13 => &CACHE_13,
        14 => &CACHE_14,
        15 => &CACHE_15,
        _ => panic!(
            "Unsupported precompute value: {precompute}. Only values 0-15 (inclusive) are supported."
        ),
    };

    cache_box.get_or_init(|| {
        let settings = KzgSettings::load_trusted_setup(
            ETH_G1_MONOMIAL_POINTS,
            ETH_G1_LAGRANGE_POINTS,
            ETH_G2_MONOMIAL_POINTS,
            precompute,
        )
        .expect("failed to load default trusted setup");
        Box::new(Arc::new(settings))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bindings::BYTES_PER_BLOB, Blob, KzgSettings};
    use std::path::Path;

    #[test]
    pub fn compare_default_with_file() {
        let precompute = 0;
        let ts_settings =
            KzgSettings::load_trusted_setup_file(Path::new("src/trusted_setup.txt"), precompute)
                .unwrap();
        let eth_settings = ethereum_kzg_settings(precompute);
        let blob = Blob::new([1u8; BYTES_PER_BLOB]);

        // generate commitment
        let ts_commitment = ts_settings
            .blob_to_kzg_commitment(&blob)
            .unwrap()
            .to_bytes();
        let eth_commitment = eth_settings
            .blob_to_kzg_commitment(&blob)
            .unwrap()
            .to_bytes();
        assert_eq!(ts_commitment, eth_commitment);

        // generate proof
        let ts_proof = ts_settings
            .compute_blob_kzg_proof(&blob, &ts_commitment)
            .unwrap()
            .to_bytes();
        let eth_proof = eth_settings
            .compute_blob_kzg_proof(&blob, &eth_commitment)
            .unwrap()
            .to_bytes();
        assert_eq!(ts_proof, eth_proof);
    }
}
