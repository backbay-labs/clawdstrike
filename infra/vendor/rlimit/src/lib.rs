//! rlimit - Resource limits.
//!
//! ## Set resource limit
//! ```no_run
//! # #[cfg(unix)]
//! # {
//! use rlimit::{setrlimit, Resource};
//!
//! const DEFAULT_SOFT_LIMIT: u64 = 4 * 1024 * 1024;
//! const DEFAULT_HARD_LIMIT: u64 = 8 * 1024 * 1024;
//! assert!(Resource::FSIZE.set(DEFAULT_SOFT_LIMIT, DEFAULT_HARD_LIMIT).is_ok());
//!
//! let soft = 16384;
//! let hard = soft * 2;
//! assert!(setrlimit(Resource::NOFILE, soft, hard).is_ok());
//! # }
//! ```
//!
//! ## Get resource limit
//! ```no_run
//! # #[cfg(unix)]
//! # {
//! use rlimit::{getrlimit, Resource};
//!
//! assert!(Resource::NOFILE.get().is_ok());
//! assert_eq!(getrlimit(Resource::CPU).unwrap(), (rlimit::INFINITY, rlimit::INFINITY));
//! # }
//! ```
//!
//! ## Windows
//!
//! Windows does not have Unix-like resource limits.
//! It only supports changing the number of simultaneously open files currently permitted at the stdio level.
//!
//! See the official documentation of
//! [`_getmaxstdio`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/getmaxstdio?view=msvc-170)
//! and
//! [`_setmaxstdio`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setmaxstdio?view=msvc-170).
//!
//! ```no_run
//! # #[cfg(windows)]
//! # {
//! println!("{}", rlimit::getmaxstdio()); // 512
//! rlimit::setmaxstdio(2048).unwrap();
//! println!("{}", rlimit::getmaxstdio()); // 2048
//! # }
//! ```
//!
//! ## Increase NOFILE limit
//! See the example [nofile](https://github.com/Nugine/rlimit/blob/main/examples/nofile.rs).
//!
//! You can also use the tool function [`rlimit::increase_nofile_limit`][`crate::increase_nofile_limit`]
//!
//! ```no_run
//! rlimit::increase_nofile_limit(10240).unwrap();
//! rlimit::increase_nofile_limit(u64::MAX).unwrap();
//! ```
//!
//! # Troubleshoot
//!
//! ## Failed to increase NOFILE to hard limit on macOS
//! On macOS, getrlimit by default reports that the hard limit is
//! unlimited, but there is usually a stricter hard limit discoverable
//! via sysctl (`kern.maxfilesperproc`). Failing to discover this secret stricter hard limit will
//! cause the call to setrlimit to fail.
//!
//! [`rlimit::increase_nofile_limit`][`crate::increase_nofile_limit`]
//! respects `kern.maxfilesperproc`.
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    missing_docs,
    missing_debug_implementations,
    clippy::all,
    clippy::pedantic,
    clippy::cargo
)]
#![allow(
    clippy::option_if_let_else,  // I don't like it. The match expression is more readable.
)]

#[allow(unused_macros)]
macro_rules! group {
    ($($item:item)*) => {
        $($item)*
    }
}

#[cfg(any(doc, windows))]
group! {
    mod windows;

    #[doc(inline)]
    pub use self::windows::*;
}

#[cfg(any(doc, unix))]
group! {
    mod bindings;

    mod unix;
    mod resource;

    #[doc(inline)]
    pub use self::unix::*;

    #[doc(inline)]
    pub use self::resource::Resource;
}

#[cfg(any(doc, target_os = "linux", target_os = "android"))]
group! {
    mod proc_limits;

    #[doc(inline)]
    pub use self::proc_limits::*;

    mod sys_limits;

    #[doc(inline)]
    pub use self::sys_limits::*;
}

mod tools;
#[doc(inline)]
pub use self::tools::*;

#[cfg(test)]
mod tests {
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn build_cfg() {
        if cfg!(target_os = "linux") || cfg!(target_os = "android") {
            assert!(cfg!(rlimit__has_prlimit64));
            assert!(cfg!(not(rlimit__get_kern_max_files_per_proc)));
        }

        if cfg!(target_os = "macos") {
            assert!(cfg!(not(rlimit__has_prlimit64)));
            assert!(cfg!(rlimit__get_kern_max_files_per_proc));
        }
    }
}
