//! Process snapshot collector using libproc FFI.
//!
//! Polls the process table at a configurable interval, diffs against the
//! previous snapshot, and emits `ProcessSpawn` / `ProcessExit` events.
//! The first poll emits a single `ProcessSnapshot` event.

#[cfg(target_os = "macos")]
mod platform {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::mem;
    use std::time::Duration;

    use serde_json::json;
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    use crate::error::Error;
    use crate::event::{DarwinEvent, DarwinEventType, EventSource, ProcessInfo};

    // libproc constants
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

    #[repr(C)]
    #[derive(Default)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        _reserved: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    extern "C" {
        fn proc_listallpids(buffer: *mut libc::c_void, buffersize: i32) -> i32;
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    /// List all PIDs currently running.
    fn list_all_pids() -> Result<Vec<i32>, Error> {
        // First call to get required buffer size
        let num_pids = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if num_pids <= 0 {
            return Err(Error::Process("proc_listallpids returned 0".to_string()));
        }

        // Allocate with some headroom
        let capacity = (num_pids as usize) + 64;
        let mut pids: Vec<i32> = vec![0; capacity];
        let buf_size = (capacity * mem::size_of::<i32>()) as i32;

        let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), buf_size) };
        if count < 0 {
            return Err(Error::Process(format!(
                "proc_listallpids failed with {count}"
            )));
        }

        pids.truncate(count as usize);
        Ok(pids)
    }

    /// Get BSD info for a single PID.
    fn get_bsd_info(pid: i32) -> Option<ProcBsdInfo> {
        let mut info = ProcBsdInfo::default();
        let size = mem::size_of::<ProcBsdInfo>() as i32;

        let ret = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };

        if ret <= 0 {
            return None;
        }
        Some(info)
    }

    /// Get the path for a PID.
    fn get_pid_path(pid: i32) -> String {
        let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
        let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast(), PROC_PIDPATHINFO_MAXSIZE) };
        if ret <= 0 {
            return String::new();
        }
        // SAFETY: proc_pidpath writes a null-terminated C string
        match CStr::from_bytes_until_nul(&buf) {
            Ok(cs) => cs.to_string_lossy().into_owned(),
            Err(_) => String::new(),
        }
    }

    /// Extract the process name from ProcBsdInfo.
    fn extract_name(info: &ProcBsdInfo) -> String {
        // Try pbi_name first (longer), fall back to pbi_comm
        let name_bytes = if info.pbi_name[0] != 0 {
            &info.pbi_name[..]
        } else {
            &info.pbi_comm[..]
        };
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        String::from_utf8_lossy(&name_bytes[..end]).into_owned()
    }

    /// Take a snapshot of all running processes.
    fn snapshot_processes() -> Result<HashMap<i32, ProcessInfo>, Error> {
        let pids = list_all_pids()?;
        let mut procs = HashMap::with_capacity(pids.len());

        for pid in pids {
            if pid <= 0 {
                continue;
            }
            if let Some(info) = get_bsd_info(pid) {
                let path = get_pid_path(pid);
                let name = extract_name(&info);
                procs.insert(
                    pid,
                    ProcessInfo {
                        pid,
                        ppid: info.pbi_ppid as i32,
                        uid: info.pbi_uid,
                        name,
                        path,
                        start_time: info.pbi_start_tvsec as i64,
                    },
                );
            }
        }

        Ok(procs)
    }

    /// Process collector that polls at intervals and emits diff-based events.
    pub struct ProcessCollector {
        interval: Duration,
    }

    impl ProcessCollector {
        pub fn new(poll_interval_secs: u64) -> Self {
            Self {
                interval: Duration::from_secs(poll_interval_secs),
            }
        }

        /// Run the collector, sending events to the provided channel.
        pub async fn run(self, tx: mpsc::Sender<DarwinEvent>) -> Result<(), Error> {
            let mut prev: Option<HashMap<i32, ProcessInfo>> = None;

            loop {
                match snapshot_processes() {
                    Ok(current) => {
                        match &prev {
                            None => {
                                // First snapshot — emit a single ProcessSnapshot event
                                let procs: Vec<_> = current.values().cloned().collect();
                                let event = DarwinEvent {
                                    event_type: DarwinEventType::ProcessSnapshot,
                                    source: EventSource::Process,
                                    timestamp: spine::now_rfc3339(),
                                    payload: json!({
                                        "process_count": procs.len(),
                                        "processes": procs,
                                    }),
                                };
                                if tx.send(event).await.is_err() {
                                    debug!("process collector channel closed");
                                    return Ok(());
                                }
                            }
                            Some(previous) => {
                                // Diff: find spawns, exits, and PID reuse.
                                // A PID present in both snapshots but with a
                                // different start_time indicates PID reuse —
                                // emit both an exit (old) and spawn (new).
                                for (pid, info) in &current {
                                    match previous.get(pid) {
                                        None => {
                                            // New PID — process spawned.
                                            let event = DarwinEvent {
                                                event_type: DarwinEventType::ProcessSpawn,
                                                source: EventSource::Process,
                                                timestamp: spine::now_rfc3339(),
                                                payload: serde_json::to_value(info)
                                                    .unwrap_or_default(),
                                            };
                                            if tx.send(event).await.is_err() {
                                                return Ok(());
                                            }
                                        }
                                        Some(prev_info)
                                            if prev_info.start_time != info.start_time =>
                                        {
                                            // PID reused — emit exit for old, spawn for new.
                                            let exit_event = DarwinEvent {
                                                event_type: DarwinEventType::ProcessExit,
                                                source: EventSource::Process,
                                                timestamp: spine::now_rfc3339(),
                                                payload: serde_json::to_value(prev_info)
                                                    .unwrap_or_default(),
                                            };
                                            if tx.send(exit_event).await.is_err() {
                                                return Ok(());
                                            }
                                            let spawn_event = DarwinEvent {
                                                event_type: DarwinEventType::ProcessSpawn,
                                                source: EventSource::Process,
                                                timestamp: spine::now_rfc3339(),
                                                payload: serde_json::to_value(info)
                                                    .unwrap_or_default(),
                                            };
                                            if tx.send(spawn_event).await.is_err() {
                                                return Ok(());
                                            }
                                        }
                                        _ => {
                                            // Same PID, same start_time — still running.
                                        }
                                    }
                                }
                                for (pid, info) in previous {
                                    if !current.contains_key(pid) {
                                        let event = DarwinEvent {
                                            event_type: DarwinEventType::ProcessExit,
                                            source: EventSource::Process,
                                            timestamp: spine::now_rfc3339(),
                                            payload: serde_json::to_value(info).unwrap_or_default(),
                                        };
                                        if tx.send(event).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                        }
                        prev = Some(current);
                    }
                    Err(e) => {
                        warn!(error = %e, "process snapshot failed");
                    }
                }

                tokio::time::sleep(self.interval).await;
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use platform::ProcessCollector;
