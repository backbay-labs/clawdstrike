use std::io::ErrorKind;
use std::ops::Not;

use rlimit::{prlimit, Resource};

use super::{atomically, expect_err, expect_ok};

#[test]
fn linux_prlimit() {
    const SOFT: u64 = 4 * 1024 * 1024;
    const HARD: u64 = 8 * 1024 * 1024;

    atomically(|| {
        let res = Resource::CORE;

        expect_ok(prlimit(0, res, Some((SOFT, HARD)), None));

        let mut soft = 0;
        let mut hard = 0;

        expect_ok(prlimit(0, res, None, Some((&mut soft, &mut hard))));

        assert_eq!((soft, hard), (SOFT, HARD));

        expect_err(
            prlimit(0, res, Some((HARD, SOFT)), None),
            ErrorKind::InvalidInput,
        );

        expect_err(
            prlimit(0, res, Some((HARD, HARD + 1)), None),
            ErrorKind::PermissionDenied,
        );
    });
}

#[test]
fn linux_proc_limits() {
    use rlimit::ProcLimits;

    atomically(|| {
        let self_limits = ProcLimits::read_self().unwrap();
        assert!(self_limits.max_cpu_time.is_some());
        assert!(self_limits.max_file_size.is_some());
        assert!(self_limits.max_data_size.is_some());
        assert!(self_limits.max_stack_size.is_some());
        assert!(self_limits.max_core_file_size.is_some());
        assert!(self_limits.max_resident_set.is_some());
        assert!(self_limits.max_processes.is_some());
        assert!(self_limits.max_open_files.is_some());
        assert!(self_limits.max_locked_memory.is_some());
        assert!(self_limits.max_address_space.is_some());
        assert!(self_limits.max_file_locks.is_some());
        assert!(self_limits.max_pending_signals.is_some());
        assert!(self_limits.max_msgqueue_size.is_some());
        assert!(self_limits.max_nice_priority.is_some());
        assert!(self_limits.max_realtime_priority.is_some());
        assert!(self_limits.max_realtime_timeout.is_some());

        let self_pid = unsafe { libc::getpid() };
        let process_limits = ProcLimits::read_process(self_pid).unwrap();

        macro_rules! assert_limit_eq{
            {$lhs:expr, $rhs:expr, [$($field:tt,)+]} => {
                $(
                    assert_eq!($lhs.$field, $rhs.$field, stringify!($field));
                )+
            }
        }

        assert_limit_eq!(
            self_limits,
            process_limits,
            [
                max_cpu_time,
                max_file_size,
                max_data_size,
                max_stack_size,
                max_core_file_size,
                max_resident_set,
                max_processes,
                max_open_files,
                max_locked_memory,
                max_address_space,
                max_file_locks,
                max_pending_signals,
                max_msgqueue_size,
                max_nice_priority,
                max_realtime_priority,
                max_realtime_timeout,
            ]
        );
    });
}

#[test]
fn linux_sys_limits() {
    use rlimit::SysLimits;

    atomically(|| {
        // Test reading system limits
        let limits = SysLimits::read().unwrap();

        // file_max should be present
        assert!(limits.file_max.is_some(), "file_max should be readable");
        let file_max = limits.file_max.unwrap();
        println!("file_max: {file_max}");

        // file_nr should be present and valid
        assert!(limits.file_nr.is_some(), "file_nr should be readable");
        let file_nr = limits.file_nr.as_ref().unwrap();
        println!(
            "file_nr: allocated={}, free={}, maximum={}",
            file_nr.allocated, file_nr.free, file_nr.maximum
        );

        // file_nr.maximum should match file_max
        assert_eq!(
            file_nr.maximum, file_max,
            "file_nr.maximum should match file_max"
        );

        // nr_open should be present
        assert!(limits.nr_open.is_some(), "nr_open should be readable");
        let nr_open = limits.nr_open.unwrap();
        println!("nr_open: {nr_open}");

        // nr_open should be greater than 0
        assert!(nr_open > 0, "nr_open should be positive");

        // Note: We don't test writing to system limits here because it requires root privileges
        // and would affect the entire system
    });
}

#[test]
fn unsupported() {
    assert!(Resource::UMTXP.is_supported().not());
    let err = Resource::UMTXP.get().unwrap_err();
    assert!(err.kind() == std::io::ErrorKind::Other);
}
