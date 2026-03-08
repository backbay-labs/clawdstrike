use super::ParseResourceError;
use super::Resource;
use crate::bindings as C;

impl Resource {
    /// The maximum size (in bytes) of the process's virtual memory (address space).
    pub const AS: Self = Self {
        tag: 1,
        value: C::RLIMIT_AS,
    };

    /// The maximum size (in bytes) of a core file that the process may dump.
    pub const CORE: Self = Self {
        tag: 2,
        value: C::RLIMIT_CORE,
    };

    /// A limit (in seconds) on the amount of CPU time that the process can consume.
    pub const CPU: Self = Self {
        tag: 3,
        value: C::RLIMIT_CPU,
    };

    /// The maximum size (in bytes) of the process's data segment (initialized data, uninitialized data, and heap).
    pub const DATA: Self = Self {
        tag: 4,
        value: C::RLIMIT_DATA,
    };

    /// The maximum size (in bytes) of files that the process may create.
    pub const FSIZE: Self = Self {
        tag: 5,
        value: C::RLIMIT_FSIZE,
    };

    /// The maximum number of kqueues this user id is allowed to create.
    pub const KQUEUES: Self = Self {
        tag: 6,
        value: C::RLIMIT_KQUEUES,
    };

    /// (early Linux 2.4 only)
    ///
    /// A limit on the combined number of `flock(2)` locks and `fcntl(2)` leases that this process may establish.
    pub const LOCKS: Self = Self {
        tag: 7,
        value: C::RLIMIT_LOCKS,
    };

    /// The maximum number (in bytes) of memory that may be locked into RAM.
    pub const MEMLOCK: Self = Self {
        tag: 8,
        value: C::RLIMIT_MEMLOCK,
    };

    /// A limit on the number of bytes that can be allocated for POSIX message queues for the real user ID of the calling process.
    pub const MSGQUEUE: Self = Self {
        tag: 9,
        value: C::RLIMIT_MSGQUEUE,
    };

    /// This specifies a ceiling to which the process's nice value can be raised using `setpriority(2)` or `nice(2)`.
    pub const NICE: Self = Self {
        tag: 10,
        value: C::RLIMIT_NICE,
    };

    /// This specifies a value one greater than the maximum file descriptor number that can be opened by this process.
    pub const NOFILE: Self = Self {
        tag: 11,
        value: C::RLIMIT_NOFILE,
    };

    /// The number of open vnode monitors.
    pub const NOVMON: Self = Self {
        tag: 12,
        value: C::RLIMIT_NOVMON,
    };

    /// A limit on the number of extant process (or, more precisely on Linux, threads) for the real user ID of the calling process.
    pub const NPROC: Self = Self {
        tag: 13,
        value: C::RLIMIT_NPROC,
    };

    /// The maximum number of pseudo-terminals this user id is allowed to create.
    pub const NPTS: Self = Self {
        tag: 14,
        value: C::RLIMIT_NPTS,
    };

    /// The maximum number of simultaneous threads (Lightweight Processes) for this user id.
    /// Kernel threads and the first thread of each process are not counted against this limit.
    pub const NTHR: Self = Self {
        tag: 15,
        value: C::RLIMIT_NTHR,
    };

    /// The maximum number of POSIX-type advisory-mode locks available to this user.
    pub const POSIXLOCKS: Self = Self {
        tag: 16,
        value: C::RLIMIT_POSIXLOCKS,
    };

    /// A limit (in bytes) on the process's resident set (the number of virtual pages resident in RAM).
    pub const RSS: Self = Self {
        tag: 17,
        value: C::RLIMIT_RSS,
    };

    /// This specifies a ceiling on the real-time priority that may be set for this process using `sched_setscheduler(2)` and `sched_setparam(2)`.
    pub const RTPRIO: Self = Self {
        tag: 18,
        value: C::RLIMIT_RTPRIO,
    };

    /// A limit (in microseconds) on the amount of CPU time that a process scheduled under a real-time scheduling policy may consume without making a blocking system call.
    pub const RTTIME: Self = Self {
        tag: 19,
        value: C::RLIMIT_RTTIME,
    };

    /// The maximum size (in bytes) of socket buffer usage for this user. This limits the amount of network memory, and hence the amount of mbufs, that this user may hold at any time.
    pub const SBSIZE: Self = Self {
        tag: 20,
        value: C::RLIMIT_SBSIZE,
    };

    /// A limit on the number of signals that may be queued for the real user ID ofthe calling process.
    pub const SIGPENDING: Self = Self {
        tag: 21,
        value: C::RLIMIT_SIGPENDING,
    };

    /// The maximum size (in bytes) of the process stack.
    pub const STACK: Self = Self {
        tag: 22,
        value: C::RLIMIT_STACK,
    };

    /// The maximum size (in bytes) of the swap space that may be reserved or used by all of this user id's processes.
    pub const SWAP: Self = Self {
        tag: 23,
        value: C::RLIMIT_SWAP,
    };

    /// **AIX**: The maximum number of threads each process can create. This limit is enforced by the kernel and the pthread debug library.
    pub const THREADS: Self = Self {
        tag: 24,
        value: C::RLIMIT_THREADS,
    };

    /// The number of shared locks a given user may create simultaneously.
    pub const UMTXP: Self = Self {
        tag: 25,
        value: C::RLIMIT_UMTXP,
    };

    /// An alias for [`RLIMIT_AS`](Resource::AS). The maximum size of a process's mapped address space in bytes.
    pub const VMEM: Self = Self {
        tag: 26,
        value: C::RLIMIT_VMEM,
    };
}

impl Resource {
    pub(super) const fn find_name_by_tag(tag: u8) -> Option<&'static str> {
        match tag {
            1 => Some("RLIMIT_AS"),
            2 => Some("RLIMIT_CORE"),
            3 => Some("RLIMIT_CPU"),
            4 => Some("RLIMIT_DATA"),
            5 => Some("RLIMIT_FSIZE"),
            6 => Some("RLIMIT_KQUEUES"),
            7 => Some("RLIMIT_LOCKS"),
            8 => Some("RLIMIT_MEMLOCK"),
            9 => Some("RLIMIT_MSGQUEUE"),
            10 => Some("RLIMIT_NICE"),
            11 => Some("RLIMIT_NOFILE"),
            12 => Some("RLIMIT_NOVMON"),
            13 => Some("RLIMIT_NPROC"),
            14 => Some("RLIMIT_NPTS"),
            15 => Some("RLIMIT_NTHR"),
            16 => Some("RLIMIT_POSIXLOCKS"),
            17 => Some("RLIMIT_RSS"),
            18 => Some("RLIMIT_RTPRIO"),
            19 => Some("RLIMIT_RTTIME"),
            20 => Some("RLIMIT_SBSIZE"),
            21 => Some("RLIMIT_SIGPENDING"),
            22 => Some("RLIMIT_STACK"),
            23 => Some("RLIMIT_SWAP"),
            24 => Some("RLIMIT_THREADS"),
            25 => Some("RLIMIT_UMTXP"),
            26 => Some("RLIMIT_VMEM"),
            _ => None,
        }
    }

    pub(super) const fn find_ident_by_tag(tag: u8) -> Option<&'static str> {
        match tag {
            1 => Some("AS"),
            2 => Some("CORE"),
            3 => Some("CPU"),
            4 => Some("DATA"),
            5 => Some("FSIZE"),
            6 => Some("KQUEUES"),
            7 => Some("LOCKS"),
            8 => Some("MEMLOCK"),
            9 => Some("MSGQUEUE"),
            10 => Some("NICE"),
            11 => Some("NOFILE"),
            12 => Some("NOVMON"),
            13 => Some("NPROC"),
            14 => Some("NPTS"),
            15 => Some("NTHR"),
            16 => Some("POSIXLOCKS"),
            17 => Some("RSS"),
            18 => Some("RTPRIO"),
            19 => Some("RTTIME"),
            20 => Some("SBSIZE"),
            21 => Some("SIGPENDING"),
            22 => Some("STACK"),
            23 => Some("SWAP"),
            24 => Some("THREADS"),
            25 => Some("UMTXP"),
            26 => Some("VMEM"),
            _ => None,
        }
    }
}
impl std::str::FromStr for Resource {
    type Err = ParseResourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RLIMIT_AS" => Ok(Self::AS),
            "RLIMIT_CORE" => Ok(Self::CORE),
            "RLIMIT_CPU" => Ok(Self::CPU),
            "RLIMIT_DATA" => Ok(Self::DATA),
            "RLIMIT_FSIZE" => Ok(Self::FSIZE),
            "RLIMIT_KQUEUES" => Ok(Self::KQUEUES),
            "RLIMIT_LOCKS" => Ok(Self::LOCKS),
            "RLIMIT_MEMLOCK" => Ok(Self::MEMLOCK),
            "RLIMIT_MSGQUEUE" => Ok(Self::MSGQUEUE),
            "RLIMIT_NICE" => Ok(Self::NICE),
            "RLIMIT_NOFILE" => Ok(Self::NOFILE),
            "RLIMIT_NOVMON" => Ok(Self::NOVMON),
            "RLIMIT_NPROC" => Ok(Self::NPROC),
            "RLIMIT_NPTS" => Ok(Self::NPTS),
            "RLIMIT_NTHR" => Ok(Self::NTHR),
            "RLIMIT_POSIXLOCKS" => Ok(Self::POSIXLOCKS),
            "RLIMIT_RSS" => Ok(Self::RSS),
            "RLIMIT_RTPRIO" => Ok(Self::RTPRIO),
            "RLIMIT_RTTIME" => Ok(Self::RTTIME),
            "RLIMIT_SBSIZE" => Ok(Self::SBSIZE),
            "RLIMIT_SIGPENDING" => Ok(Self::SIGPENDING),
            "RLIMIT_STACK" => Ok(Self::STACK),
            "RLIMIT_SWAP" => Ok(Self::SWAP),
            "RLIMIT_THREADS" => Ok(Self::THREADS),
            "RLIMIT_UMTXP" => Ok(Self::UMTXP),
            "RLIMIT_VMEM" => Ok(Self::VMEM),
            _ => Err(ParseResourceError(())),
        }
    }
}
