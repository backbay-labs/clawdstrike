//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It provides a single function [`load_native_certs()`], which returns a
//! collection of certificates found by reading the platform-native
//! certificate store.
//!
//! If the SSL_CERT_FILE environment variable is set, certificates (in PEM
//! format) are read from that file instead.
//!
//! If you want to load these certificates into a `rustls::RootCertStore`,
//! you'll likely want to do something like this:
//!
//! ```no_run
//! let mut roots = rustls::RootCertStore::empty();
//! for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
//!     roots.add(cert).unwrap();
//! }
//! ```

// Enable documentation for all features on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::BufReader;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use pki_types::CertificateDer;

/// Load root certificates found in the platform's native certificate store.
///
/// ## Environment Variables
///
/// | Env. Var.      | Description                                                                           |
/// |----------------|---------------------------------------------------------------------------------------|
/// | SSL_CERT_FILE  | File containing an arbitrary number of certificates in PEM format.                    |
/// | SSL_CERT_DIR   | Directory utilizing the hierarchy and naming convention used by OpenSSL's [c_rehash]. |
///
/// If **either** (or **both**) are set, certificates are only loaded from
/// the locations specified via environment variables and not the platform-
/// native certificate store.
///
/// ## Certificate Validity
///
/// All certificates are expected to be in PEM format. A file may contain
/// multiple certificates.
///
/// Example:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
/// CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
/// R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
/// MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
/// ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
/// EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
/// +1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
/// ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
/// AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
/// zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
/// tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/// /q4AaOeMSQ+2b1tbFfLn
/// -----END CERTIFICATE-----
/// -----BEGIN CERTIFICATE-----
/// MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
/// MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
/// Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
/// A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
/// Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
/// ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
/// QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
/// ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
/// BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
/// YyRIHN8wfdVoOw==
/// -----END CERTIFICATE-----
///
/// ```
///
/// For reasons of compatibility, an attempt is made to skip invalid sections
/// of a certificate file but this means it's also possible for a malformed
/// certificate to be skipped.
///
/// If a certificate isn't loaded, and no error is reported, check if:
///
/// 1. the certificate is in PEM format (see example above)
/// 2. *BEGIN CERTIFICATE* line starts with exactly five hyphens (`'-'`)
/// 3. *END CERTIFICATE* line ends with exactly five hyphens (`'-'`)
/// 4. there is a line break after the certificate.
///
/// ## Errors
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// ## Caveats
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
///
/// [c_rehash]: https://www.openssl.org/docs/manmaster/man1/c_rehash.html
pub fn load_native_certs() -> Result<Vec<CertificateDer<'static>>, Error> {
    match CertPaths::from_env().load()? {
        Some(certs) => Ok(certs),
        None => platform::load_native_certs(),
    }
}

/// Certificate paths from `SSL_CERT_FILE` and/or `SSL_CERT_DIR`.
struct CertPaths {
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
}

impl CertPaths {
    fn from_env() -> Self {
        Self {
            file: env::var_os(ENV_CERT_FILE).map(PathBuf::from),
            dir: env::var_os(ENV_CERT_DIR).map(PathBuf::from),
        }
    }

    /// Load certificates from the paths.
    ///
    /// If both are `None`, return `Ok(None)`.
    ///
    /// If `self.file` is `Some`, it is always used, so it must be a path to an existing,
    /// accessible file from which certificates can be loaded successfully. While parsing,
    /// the [rustls_pemfile::certs()] parser will ignore parts of the file which are
    /// not considered part of a certificate. Certificates which are not in the right
    /// format (PEM) or are otherwise corrupted may get ignored silently.
    ///
    /// If `self.dir` is defined, a directory must exist at this path, and all
    /// [hash files](`is_hash_file_name()`) contained in it must be loaded successfully,
    /// subject to the rules outlined above for `self.file`. The directory is not
    /// scanned recursively and may be empty.
    fn load(&self) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        if self.file.is_none() && self.dir.is_none() {
            return Ok(None);
        }

        let mut first_error = None;

        let mut certs = match &self.file {
            Some(cert_file) => match load_pem_certs(cert_file)
                .map_err(|err| Self::load_err(cert_file, "file", err))
            {
                Ok(certs) => certs,
                Err(err) => {
                    first_error = first_error.or(Some(err));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };

        if let Some(cert_dir) = &self.dir {
            match load_pem_certs_from_dir(cert_dir)
                .map_err(|err| Self::load_err(cert_dir, "dir", err))
            {
                Ok(mut from_dir) => certs.append(&mut from_dir),
                Err(err) => first_error = first_error.or(Some(err)),
            }
        }

        // promote first error if we have no certs to return
        if let (Some(error), []) = (first_error, certs.as_slice()) {
            return Err(error);
        }

        certs.sort_unstable_by(|a, b| a.cmp(b));
        certs.dedup();

        Ok(Some(certs))
    }

    fn load_err(path: &Path, typ: &str, err: Error) -> Error {
        Error::new(
            err.kind(),
            format!("could not load certs from {typ} {}: {err}", path.display()),
        )
    }
}

/// Load certificate from certificate directory (what OpenSSL calls CAdir)
///
/// This directory can contain other files and directories. CAfile tends
/// to be in here too. To avoid loading something twice or something that
/// isn't a valid certificate, we limit ourselves to loading those files
/// that have a hash-based file name matching the pattern used by OpenSSL.
/// The hash is not verified, however.
fn load_pem_certs_from_dir(dir: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let dir_reader = fs::read_dir(dir)?;
    let mut certs = Vec::new();
    for entry in dir_reader {
        let entry = entry?;
        let path = entry.path();
        let file_name = path
            .file_name()
            // We are looping over directory entries. Directory entries
            // always have a name (except "." and ".." which the iterator
            // never yields).
            .expect("dir entry with no name");

        // `openssl rehash` used to create this directory uses symlinks. So,
        // make sure we resolve them.
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Dangling symlink
                continue;
            }
            Err(e) => return Err(e),
        };
        if metadata.is_file() && is_hash_file_name(file_name) {
            certs.append(&mut load_pem_certs(&path)?);
        }
    }
    Ok(certs)
}

fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

/// Check if this is a hash-based file name for a certificate
///
/// According to the [c_rehash man page][]:
///
/// > The links created are of the form HHHHHHHH.D, where each H is a hexadecimal
/// > character and D is a single decimal digit.
///
/// `c_rehash` generates lower-case hex digits but this is not clearly documented.
/// Because of this, and because it could lead to issues on case-insensitive file
/// systems, upper-case hex digits are accepted too.
///
/// [c_rehash man page]: https://www.openssl.org/docs/manmaster/man1/c_rehash.html
fn is_hash_file_name(file_name: &OsStr) -> bool {
    let file_name = match file_name.to_str() {
        Some(file_name) => file_name,
        None => return false, // non-UTF8 can't be hex digits
    };

    if file_name.len() != 10 {
        return false;
    }
    let mut iter = file_name.chars();
    let iter = iter.by_ref();
    iter.take(8)
        .all(|c| c.is_ascii_hexdigit())
        && iter.next() == Some('.')
        && matches!(iter.next(), Some(c) if c.is_ascii_digit())
}

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";
const ENV_CERT_DIR: &str = "SSL_CERT_DIR";

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs::Permissions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn valid_hash_file_name() {
        let valid_names = [
            "f3377b1b.0",
            "e73d606e.1",
            "01234567.2",
            "89abcdef.3",
            "ABCDEF00.9",
        ];
        for name in valid_names {
            assert!(is_hash_file_name(OsStr::new(name)));
        }
    }

    #[test]
    fn invalid_hash_file_name() {
        let valid_names = [
            "f3377b1b.a",
            "e73d606g.1",
            "0123457.2",
            "89abcdef0.3",
            "name.pem",
        ];
        for name in valid_names {
            assert!(!is_hash_file_name(OsStr::new(name)));
        }
    }

    #[test]
    fn deduplication() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let cert1 = include_str!("../tests/badssl-com-chain.pem");
        let cert2 = include_str!("../integration-tests/one-existing-ca.pem");
        let file_path = temp_dir
            .path()
            .join("ca-certificates.crt");
        let dir_path = temp_dir.path().to_path_buf();

        {
            let mut file = File::create(&file_path).unwrap();
            write!(file, "{}", &cert1).unwrap();
            write!(file, "{}", &cert2).unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("71f3bb26.0")).unwrap();
            write!(file, "{}", &cert1).unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("912e7cd5.0")).unwrap();
            write!(file, "{}", &cert2).unwrap();
        }

        let certs_from_file = CertPaths {
            file: Some(file_path.clone()),
            dir: None,
        }
        .load()
        .unwrap();
        assert_eq!(certs_from_file.unwrap().len(), 2);

        let certs_from_dir = CertPaths {
            file: None,
            dir: Some(dir_path.clone()),
        }
        .load()
        .unwrap();
        assert_eq!(certs_from_dir.unwrap().len(), 2);

        let certs_from_both = CertPaths {
            file: Some(file_path),
            dir: Some(dir_path),
        }
        .load()
        .unwrap();
        assert_eq!(certs_from_both.unwrap().len(), 2);
    }

    #[test]
    fn malformed_file_from_env() {
        // Certificate parser tries to extract certs from file ignoring
        // invalid sections.
        let certs = load_pem_certs(Path::new(file!())).unwrap();
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn from_env_missing_file() {
        assert_eq!(
            load_pem_certs(Path::new("no/such/file"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn from_env_missing_dir() {
        assert_eq!(
            load_pem_certs_from_dir(Path::new("no/such/directory"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    #[cfg(unix)]
    fn from_env_with_non_regular_and_empty_file() {
        let certs = load_pem_certs(Path::new("/dev/null")).unwrap();
        assert_eq!(certs.len(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_dir_perms() {
        // Create a temp dir that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0)).unwrap();

        test_cert_paths_bad_perms(CertPaths {
            file: None,
            dir: Some(temp_dir.path().into()),
        })
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_file_perms() {
        // Create a tmp dir with a file inside that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("unreadable.pem");
        let cert_file = File::create(&file_path).unwrap();
        cert_file
            .set_permissions(Permissions::from_mode(0))
            .unwrap();

        test_cert_paths_bad_perms(CertPaths {
            file: Some(file_path.clone()),
            dir: None,
        });
    }

    #[cfg(unix)]
    fn test_cert_paths_bad_perms(cert_paths: CertPaths) {
        let err = cert_paths.load().unwrap_err();

        let affected_path = match (cert_paths.file, cert_paths.dir) {
            (Some(file), None) => file,
            (None, Some(dir)) => dir,
            _ => panic!("only one of file or dir should be set"),
        };
        let r#type = match affected_path.is_file() {
            true => "file",
            false => "dir",
        };

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err
            .to_string()
            .contains(&format!("certs from {type}")));
        assert!(err
            .to_string()
            .contains(&affected_path.display().to_string()));
    }
}
