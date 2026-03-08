mod utils;
use self::utils::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;
