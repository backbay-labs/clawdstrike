//! `.cpkg` archive format — zstd-compressed tar with content-hash integrity.

use std::fs;
use std::io::{Error as IoError, Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};

use hush_core::Hash;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};

/// Maximum uncompressed archive size (100 MB) to prevent zip bombs.
const MAX_UNCOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;
/// Maximum compressed archive size accepted for unpack.
const MAX_COMPRESSED_SIZE: u64 = MAX_UNCOMPRESSED_SIZE + (1024 * 1024);

/// Compression level for zstd.
const ZSTD_LEVEL: i32 = 3;

struct SizeLimitedWriter<W: IoWrite> {
    inner: W,
    max_bytes: u64,
    written: u64,
}

impl<W: IoWrite> SizeLimitedWriter<W> {
    fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            written: 0,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: IoWrite> IoWrite for SizeLimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written >= self.max_bytes {
            return Err(IoError::other(format!(
                "uncompressed archive size exceeds limit ({} bytes)",
                self.max_bytes
            )));
        }
        let remaining = (self.max_bytes - self.written) as usize;
        let chunk = &buf[..buf.len().min(remaining)];
        let written = self.inner.write(chunk)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn sha256_file(path: &Path) -> Result<Hash> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(Hash::from_bytes(out))
}

/// Pack a directory into a `.cpkg` archive (tar + zstd).
///
/// Returns the SHA-256 content hash of the compressed bytes.
pub fn pack(source_dir: &Path, output_path: &Path) -> Result<Hash> {
    if !source_dir.is_dir() {
        return Err(Error::PkgError(format!(
            "source path is not a directory: {}",
            source_dir.display()
        )));
    }

    let pack_result = (|| -> Result<()> {
        let out_file = fs::File::create(output_path)?;
        let out_buf = std::io::BufWriter::new(out_file);
        let encoder = zstd::stream::write::Encoder::new(out_buf, ZSTD_LEVEL)?;
        // Tar bytes flow into `limited` before being compressed by the encoder,
        // so this enforces a cap on the uncompressed tar stream size.
        let mut limited = SizeLimitedWriter::new(encoder, MAX_UNCOMPRESSED_SIZE);

        {
            let mut builder = tar::Builder::new(&mut limited);
            builder.append_dir_all(".", source_dir)?;
            builder.finish()?;
        }

        let encoder = limited.into_inner();
        let mut out_buf = encoder.finish()?;
        out_buf.flush()?;
        Ok(())
    })();

    if let Err(err) = pack_result {
        let _ = fs::remove_file(output_path);
        return Err(err);
    }

    sha256_file(output_path)
}

/// Unpack a `.cpkg` archive into a target directory.
///
/// Returns the SHA-256 content hash of the compressed archive bytes.
pub fn unpack(archive_path: &Path, target_dir: &Path) -> Result<Hash> {
    let compressed_size = fs::metadata(archive_path)?.len();
    if compressed_size > MAX_COMPRESSED_SIZE {
        return Err(Error::PkgError(format!(
            "compressed archive size ({} bytes) exceeds limit ({} bytes)",
            compressed_size, MAX_COMPRESSED_SIZE
        )));
    }
    let compressed = fs::read(archive_path)?;
    let hash = hush_core::sha256(&compressed);

    // Decompress with a hard size limit to prevent decompression bombs from
    // exhausting memory.  `take()` ensures we never read more than
    // MAX_UNCOMPRESSED_SIZE + 1 bytes, so an oversized payload is caught
    // cheaply without buffering the entire stream first.
    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())?;
    let mut tar_bytes: Vec<u8> = Vec::new();
    let mut limited = decoder.take(MAX_UNCOMPRESSED_SIZE + 1);
    limited.read_to_end(&mut tar_bytes)?;
    if tar_bytes.len() as u64 > MAX_UNCOMPRESSED_SIZE {
        return Err(Error::PkgError(format!(
            "uncompressed archive size exceeds limit ({} bytes)",
            MAX_UNCOMPRESSED_SIZE
        )));
    }

    // Extract, validating paths against traversal.
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let canonical_target = if target_dir.exists() {
        target_dir.canonicalize()?
    } else {
        fs::create_dir_all(target_dir)?;
        target_dir.canonicalize()?
    };

    for entry in archive.entries()? {
        let mut entry = entry?;

        // Skip anything that isn't a regular file or directory. This blocks
        // symlinks/hard-links (escape risk) and special entries like device
        // nodes/FIFOs that packages never need to materialize.
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            tracing::warn!(
                "skipping unsupported non-file archive entry: {}",
                entry.path().unwrap_or_default().display()
            );
            continue;
        }

        let entry_path = entry.path()?;

        // Resolve the destination and check for path traversal BEFORE
        // touching the filesystem.  We normalize the path lexically first
        // (collapsing `.` / `..` components) so the `starts_with` check
        // catches traversal attempts before any directories are created.
        let dest = canonical_target.join(&entry_path);

        // Lexically normalize the path to resolve `..` without requiring
        // the path to exist on disk yet.
        let mut normalized = PathBuf::new();
        for component in dest.components() {
            match component {
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::CurDir => {}
                other => normalized.push(other),
            }
        }

        // Check for traversal BEFORE creating any directories.
        if !normalized.starts_with(&canonical_target) {
            return Err(Error::PkgError(format!(
                "path traversal detected: {}",
                entry_path.display()
            )));
        }

        // Tar archives may include an explicit root directory entry ("."), which
        // normalizes to canonical_target itself. Skip parent checks for that
        // synthetic root entry to avoid comparing against target's parent.
        if normalized != canonical_target {
            let parent = normalized.parent().ok_or_else(|| {
                Error::PkgError(format!(
                    "missing parent for archive entry: {}",
                    entry_path.display()
                ))
            })?;
            fs::create_dir_all(parent)?;
            // Re-canonicalize after creation to ensure we are not writing
            // through a pre-existing symlinked directory.
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(&canonical_target) {
                return Err(Error::PkgError(format!(
                    "path escapes extraction root via symlink: {}",
                    entry_path.display()
                )));
            }
        }

        entry.unpack(&normalized)?;
    }

    Ok(hash)
}

/// Compute the SHA-256 content hash of an archive file without extracting it.
pub fn content_hash(archive_path: &Path) -> Result<Hash> {
    let bytes = fs::read(archive_path)?;
    Ok(hush_core::sha256(&bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn round_trip_pack_unpack() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("hello.txt"), b"hello world").unwrap();
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/nested.txt"), b"nested").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let pack_hash = pack(&src, &archive).unwrap();

        let dest = tmp.path().join("dest");
        let unpack_hash = unpack(&archive, &dest).unwrap();

        assert_eq!(pack_hash, unpack_hash);
        assert_eq!(
            fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            fs::read_to_string(dest.join("sub/nested.txt")).unwrap(),
            "nested"
        );
    }

    #[test]
    fn content_hash_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("data.bin"), b"deterministic").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let pack_hash = pack(&src, &archive).unwrap();
        let hash = content_hash(&archive).unwrap();

        assert_eq!(pack_hash, hash);
    }

    #[test]
    fn rejects_non_directory_source() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        fs::write(&file, b"not a dir").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let err = pack(&file, &archive).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn size_limited_writer_rejects_oversized_write() {
        let mut writer = SizeLimitedWriter::new(Vec::<u8>::new(), 4);
        writer.write_all(b"abcd").unwrap();
        let err = writer.write_all(b"ef").unwrap_err();
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn size_limited_writer_allows_partial_write_up_to_limit() {
        struct OneByteWriter;

        impl IoWrite for OneByteWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                Ok(1)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = SizeLimitedWriter::new(OneByteWriter, 4);
        writer.write_all(b"abc").unwrap();
        let wrote = writer.write(b"zzzz").unwrap();
        assert_eq!(wrote, 1);
        let err = writer.write(b"z").unwrap_err();
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn path_traversal_rejected() {
        // Craft a tar that contains `../escape.txt` by writing raw header bytes.
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("evil.cpkg");

        // Build tar in memory with a traversal path.
        // We write the path directly into the header name field to bypass
        // the `tar` crate's safety checks on `set_path`.
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let data = b"malicious";
            let mut header = tar::Header::new_gnu();
            // Write the traversal path directly into the name field bytes.
            {
                let raw = header.as_gnu_mut().unwrap();
                let name_bytes = b"../escape.txt\0";
                raw.name[..name_bytes.len()].copy_from_slice(name_bytes);
            }
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        // Compress with zstd.
        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder =
                zstd::stream::write::Encoder::new(&mut compressed, ZSTD_LEVEL).unwrap();
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        fs::write(&archive_path, &compressed).unwrap();

        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let err = unpack(&archive_path, &dest).unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn rejects_oversized_compressed_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("oversized.cpkg");
        let file = fs::File::create(&archive_path).unwrap();
        file.set_len(MAX_COMPRESSED_SIZE + 1).unwrap();

        let err = unpack(&archive_path, &tmp.path().join("dest")).unwrap_err();
        assert!(err.to_string().contains("compressed archive size"));
    }

    #[test]
    fn skips_special_tar_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("special.cpkg");

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);

            // Special entry type that should be ignored during extraction.
            let mut fifo_header = tar::Header::new_gnu();
            fifo_header.set_entry_type(tar::EntryType::Fifo);
            fifo_header.set_size(0);
            fifo_header.set_mode(0o644);
            fifo_header.set_cksum();
            builder
                .append_data(&mut fifo_header, "named-pipe", std::io::empty())
                .unwrap();

            // Keep a normal file in the same archive to ensure extraction
            // continues for valid entries.
            let data = b"safe";
            let mut file_header = tar::Header::new_gnu();
            file_header.set_entry_type(tar::EntryType::Regular);
            file_header.set_size(data.len() as u64);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "ok.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder =
                zstd::stream::write::Encoder::new(&mut compressed, ZSTD_LEVEL).unwrap();
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        fs::write(&archive_path, &compressed).unwrap();

        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        unpack(&archive_path, &dest).unwrap();

        assert_eq!(fs::read_to_string(dest.join("ok.txt")).unwrap(), "safe");
        assert!(!dest.join("named-pipe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_writes_through_preexisting_symlink_parent() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("evil-symlink.cpkg");

        // Build tar with a regular file at link/owned.txt.
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let data = b"owned";
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "link/owned.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder =
                zstd::stream::write::Encoder::new(&mut compressed, ZSTD_LEVEL).unwrap();
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        fs::write(&archive_path, &compressed).unwrap();

        let dest = tmp.path().join("dest");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dest.join("link")).unwrap();

        let err = unpack(&archive_path, &dest).unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert!(!outside.join("owned.txt").exists());
    }
}
