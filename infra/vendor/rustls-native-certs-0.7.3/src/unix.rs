use crate::CertPaths;

use pki_types::CertificateDer;

use std::io::Error;

pub fn load_native_certs() -> Result<Vec<CertificateDer<'static>>, Error> {
    let likely_locations = openssl_probe::probe();
    CertPaths {
        file: likely_locations.cert_file,
        dir: likely_locations.cert_dir,
    }
    .load()
    .map(|certs| certs.unwrap_or_default())
}
