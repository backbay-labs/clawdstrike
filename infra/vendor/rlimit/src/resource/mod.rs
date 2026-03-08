mod generated;

use crate::{getrlimit, setrlimit};

use std::fmt;
use std::io;

/// A kind of resource.
///
/// All resource constants are available on all unix platforms.
/// Passing an unsupported resource to `[set|get|p]rlimit` will
/// result in a custom IO error.
///
/// **Be careful**: The documentation of [`Resource`](Resource) constants are based on a few systems.
///
/// It may be inconsistent with other platforms.
///
/// ## References
///
/// Linux: <https://man7.org/linux/man-pages/man2/getrlimit.2.html>
///
/// FreeBSD: <https://www.freebsd.org/cgi/man.cgi?query=getrlimit>
///
/// NetBSD: <https://man.netbsd.org/getrlimit.2>
///
/// AIX: <https://www.ibm.com/docs/en/aix/7.3?topic=g-getrlimit-getrlimit64-setrlimit-setrlimit64-vlimit-subroutine>
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Resource {
    tag: u8,
    value: u8,
}

impl fmt::Debug for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::find_ident_by_tag(self.tag) {
            Some(ident) => write!(f, "Resource::{ident}"),
            None => unreachable!(),
        }
    }
}

/// An error returned when `Resource::from_str` fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseResourceError(());

impl fmt::Display for ParseResourceError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse Resource")
    }
}

impl std::error::Error for ParseResourceError {}

impl Resource {
    /// Set resource limits.
    /// # Errors
    /// See [`setrlimit`]
    #[inline]
    pub fn set(self, soft: u64, hard: u64) -> io::Result<()> {
        setrlimit(self, soft, hard)
    }

    /// Get resource limits.
    /// # Errors
    /// See [`getrlimit`]
    #[inline]
    pub fn get(self) -> io::Result<(u64, u64)> {
        getrlimit(self)
    }

    /// Get soft resource limit (`rlim_cur`)
    /// # Errors
    /// See [`getrlimit`]
    pub fn get_soft(self) -> io::Result<u64> {
        self.get().map(|(soft, _)| soft)
    }

    /// Get hard resource limit (`rlim_max`)
    /// # Errors
    /// See [`getrlimit`]
    pub fn get_hard(self) -> io::Result<u64> {
        self.get().map(|(_, hard)| hard)
    }

    /// Returns the name of the resource.
    ///
    /// # Example
    /// ```
    /// # #[cfg(unix)]
    /// # {
    /// # use rlimit::Resource;
    /// assert_eq!(Resource::NOFILE.as_name(), "RLIMIT_NOFILE");
    /// # }
    /// ```
    #[must_use]
    pub fn as_name(self) -> &'static str {
        match Self::find_name_by_tag(self.tag) {
            Some(name) => name,
            None => unreachable!(),
        }
    }

    /// Returns true if the current platform supports this resource.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.value != u8::MAX
    }

    /// `u8::MAX` indicates unsupported resource.
    #[inline]
    #[must_use]
    pub(crate) const fn as_raw(self) -> u8 {
        self.value
    }
}
