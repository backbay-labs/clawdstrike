use std::io;

/// Returns the value of `kern.maxfilesperproc` by sysctl.
/// # Errors
/// Returns an error if any syscall failed.
#[cfg(rlimit__get_kern_max_files_per_proc)]
fn get_kern_max_files_per_proc() -> io::Result<u64> {
    use std::mem;
    use std::ptr;

    let mut mib = [libc::CTL_KERN, libc::KERN_MAXFILESPERPROC];
    let mut max_files_per_proc: libc::c_int = 0;
    let mut oldlen = mem::size_of::<libc::c_int>();
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            &mut max_files_per_proc as *mut libc::c_int as *mut libc::c_void,
            &mut oldlen,
            ptr::null_mut(),
            0,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: sysctl should return a non-negative value for KERN_MAXFILESPERPROC.
    // Casting a non-negative c_int to u64 is always safe (widening conversion).
    debug_assert!(max_files_per_proc >= 0);
    Ok(max_files_per_proc as u64)
}

/// Try to increase NOFILE limit and return the current soft limit.
///
/// `lim` is the expected limit which can be up to [`u64::MAX`].
///
/// This function does nothing and returns `Ok(lim)`
/// if `RLIMIT_NOFILE` does not exist on current platform.
///
/// # Errors
/// Returns an error if any syscall failed.
pub fn increase_nofile_limit(lim: u64) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use crate::Resource;

        if !Resource::NOFILE.is_supported() {
            return Ok(lim);
        }

        let (soft, hard) = Resource::NOFILE.get()?;

        if soft >= hard {
            return Ok(hard);
        }

        if soft >= lim {
            return Ok(soft);
        }

        let mut lim = lim;

        lim = lim.min(hard);

        #[cfg(rlimit__get_kern_max_files_per_proc)]
        {
            lim = lim.min(get_kern_max_files_per_proc()?)
        }

        Resource::NOFILE.set(lim, hard)?;

        Ok(lim)
    }
    #[cfg(windows)]
    {
        Ok(lim)
    }
}
