#![deny(unsafe_code)]

use std::fs;
use std::io;
use std::path::Path;

/// System-wide file descriptor limits and statistics.
///
/// These values are read from and written to the **proc** filesystem under `/proc/sys/fs/`.
///
/// See <https://www.kernel.org/doc/Documentation/sysctl/fs.txt> and
/// <https://man7.org/linux/man-pages/man5/proc.5.html>.
///
#[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "android"))))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SysLimits {
    /// System-wide limit on the total number of file descriptors that can be allocated.
    ///
    /// This corresponds to `/proc/sys/fs/file-max`.
    pub file_max: Option<u64>,

    /// Current file descriptor usage statistics.
    ///
    /// This corresponds to `/proc/sys/fs/file-nr` and contains three values:
    /// - `allocated`: Number of allocated file descriptors
    /// - `free`: Number of free file descriptors (deprecated, always 0 in modern kernels)
    /// - `maximum`: Maximum number of file descriptors (same as `file_max`)
    ///
    /// This field is read-only.
    pub file_nr: Option<FileNr>,

    /// Per-process maximum number of file descriptors that can be allocated.
    ///
    /// This corresponds to `/proc/sys/fs/nr_open`. This is the ceiling value that
    /// can be set for the per-process NOFILE limit (both hard and soft).
    pub nr_open: Option<u64>,
}

/// File descriptor usage statistics from `/proc/sys/fs/file-nr`.
///
/// **Note:** The "free" field has been deprecated since Linux 2.6 and is always 0 in modern kernels.
#[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "android"))))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileNr {
    /// Number of allocated file descriptors.
    pub allocated: u64,
    /// Number of free file descriptors.
    ///
    /// **Deprecated:** This field has been deprecated since Linux 2.6 and is always 0 in modern kernels.
    /// It does not contain meaningful data.
    pub free: u64,
    /// Maximum number of file descriptors (same as `file_max`).
    pub maximum: u64,
}

impl SysLimits {
    /// Reads system-wide file descriptor limits from `/proc/sys/fs/`.
    ///
    /// # Errors
    /// Returns an error if any IO operation failed or if the file format is invalid.
    ///
    /// # Examples
    /// ```no_run
    /// # #[cfg(any(target_os = "linux", target_os = "android"))]
    /// # {
    /// use rlimit::SysLimits;
    ///
    /// let limits = SysLimits::read().unwrap();
    /// println!("System file-max: {:?}", limits.file_max);
    /// println!("Current usage: {:?}", limits.file_nr);
    /// println!("Per-process nr_open: {:?}", limits.nr_open);
    /// # }
    /// ```
    pub fn read() -> io::Result<Self> {
        let file_max = read_u64_from_file("/proc/sys/fs/file-max").ok();
        let file_nr = read_file_nr("/proc/sys/fs/file-nr").ok();
        let nr_open = read_u64_from_file("/proc/sys/fs/nr_open").ok();

        Ok(Self {
            file_max,
            file_nr,
            nr_open,
        })
    }

    /// Writes the `file_max` value to `/proc/sys/fs/file-max`.
    ///
    /// This operation typically requires root privileges or `CAP_SYS_ADMIN` capability.
    ///
    /// # Errors
    /// Returns an error if the write operation failed, which can happen if:
    /// - The process lacks sufficient privileges
    /// - The value is invalid
    /// - The filesystem is read-only
    ///
    /// # Examples
    /// ```no_run
    /// # #[cfg(any(target_os = "linux", target_os = "android"))]
    /// # {
    /// use rlimit::SysLimits;
    ///
    /// // This typically requires root privileges
    /// SysLimits::set_file_max(1048576).unwrap();
    /// # }
    /// ```
    pub fn set_file_max(value: u64) -> io::Result<()> {
        write_u64_to_file("/proc/sys/fs/file-max", value)
    }

    /// Writes the `nr_open` value to `/proc/sys/fs/nr_open`.
    ///
    /// This operation typically requires root privileges or `CAP_SYS_ADMIN` capability.
    ///
    /// # Errors
    /// Returns an error if the write operation failed, which can happen if:
    /// - The process lacks sufficient privileges
    /// - The value is invalid
    /// - The filesystem is read-only
    ///
    /// # Examples
    /// ```no_run
    /// # #[cfg(any(target_os = "linux", target_os = "android"))]
    /// # {
    /// use rlimit::SysLimits;
    ///
    /// // This typically requires root privileges
    /// SysLimits::set_nr_open(1048576).unwrap();
    /// # }
    /// ```
    pub fn set_nr_open(value: u64) -> io::Result<()> {
        write_u64_to_file("/proc/sys/fs/nr_open", value)
    }
}

/// Reads a u64 value from a file in `/proc/sys/fs/`.
fn read_u64_from_file(path: impl AsRef<Path>) -> io::Result<u64> {
    let content = fs::read_to_string(path)?;
    content
        .trim()
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads file descriptor statistics from `/proc/sys/fs/file-nr`.
///
/// The file contains three whitespace-separated values: allocated, free, and maximum.
fn read_file_nr(path: impl AsRef<Path>) -> io::Result<FileNr> {
    let content = fs::read_to_string(path)?;
    let parts: Vec<&str> = content.split_whitespace().collect();

    if parts.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected 3 values in file-nr, got {}", parts.len()),
        ));
    }

    let allocated = parts[0]
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let free = parts[1]
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let maximum = parts[2]
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(FileNr {
        allocated,
        free,
        maximum,
    })
}

/// Writes a u64 value to a file in `/proc/sys/fs/`.
fn write_u64_to_file(path: impl AsRef<Path>, value: u64) -> io::Result<()> {
    fs::write(path, value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_system_limits() {
        // This test only verifies that the function doesn't crash
        // The actual values depend on the system configuration
        let result = SysLimits::read();

        // Should succeed on Linux/Android systems
        if cfg!(any(target_os = "linux", target_os = "android")) {
            let limits = result.unwrap();

            // At least one of the fields should be populated
            assert!(
                limits.file_max.is_some() || limits.file_nr.is_some() || limits.nr_open.is_some(),
                "At least one limit should be readable"
            );

            // If file_nr is present, validate its structure
            if let Some(file_nr) = limits.file_nr {
                // Maximum should match file_max if both are present
                if let Some(file_max) = limits.file_max {
                    assert_eq!(file_nr.maximum, file_max);
                }
            }
        }
    }

    #[test]
    fn test_file_nr_parsing() {
        // Test the internal parsing logic with mock data
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!(
            "test_file_nr_{:?}.txt",
            std::thread::current().id()
        ));

        // Write test data
        let mut file = fs::File::create(&test_file).unwrap();
        write!(file, "2208\t0\t9223372036854775807").unwrap();
        file.flush().unwrap();
        drop(file);

        // Read and verify
        let result = read_file_nr(&test_file).unwrap();
        assert_eq!(result.allocated, 2208);
        assert_eq!(result.free, 0);
        assert_eq!(result.maximum, 9_223_372_036_854_775_807);

        // Clean up
        fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_u64_parsing() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!(
            "test_u64_{:?}.txt",
            std::thread::current().id()
        ));

        // Write test data
        let mut file = fs::File::create(&test_file).unwrap();
        writeln!(file, "1048576").unwrap();
        file.flush().unwrap();
        drop(file);

        // Read and verify
        let result = read_u64_from_file(&test_file).unwrap();
        assert_eq!(result, 1_048_576);

        // Clean up
        fs::remove_file(&test_file).ok();
    }
}
