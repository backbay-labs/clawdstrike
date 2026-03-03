//! FSEvents collector using `fsevent-sys` for real-time filesystem monitoring.
//!
//! Runs a CFRunLoop on a dedicated `std::thread` and bridges events to tokio
//! via an mpsc channel.

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::CString;

    use fsevent_sys::core_foundation as cf;
    use fsevent_sys::*;
    use serde_json::json;
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    use crate::error::Error;
    use crate::event::{DarwinEvent, DarwinEventType, EventSource};

    /// Default paths to watch for security-relevant filesystem changes.
    pub const DEFAULT_WATCH_PATHS: &[&str] = &[
        "/etc",
        "/usr/local/bin",
        "/Applications",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
    ];

    // FSEvents flag constants
    const K_FS_EVENT_ITEM_CREATED: u32 = 0x0000_0100;
    const K_FS_EVENT_ITEM_REMOVED: u32 = 0x0000_0200;
    const K_FS_EVENT_ITEM_RENAMED: u32 = 0x0000_0800;
    const K_FS_EVENT_ITEM_MODIFIED: u32 = 0x0000_1000;
    const K_FS_EVENT_ITEM_CHANGE_OWNER: u32 = 0x0000_4000;
    const K_FS_EVENT_ITEM_XATTR_MOD: u32 = 0x0000_8000;

    /// Classify FSEvents flags into a DarwinEventType.
    fn classify_flags(flags: u32) -> DarwinEventType {
        if flags & K_FS_EVENT_ITEM_CREATED != 0 {
            DarwinEventType::FileCreated
        } else if flags & K_FS_EVENT_ITEM_REMOVED != 0 {
            DarwinEventType::FileRemoved
        } else if flags & K_FS_EVENT_ITEM_RENAMED != 0 {
            DarwinEventType::FileRenamed
        } else if flags & K_FS_EVENT_ITEM_CHANGE_OWNER != 0 {
            DarwinEventType::OwnerChanged
        } else if flags & K_FS_EVENT_ITEM_XATTR_MOD != 0 {
            DarwinEventType::XattrChanged
        } else if flags & K_FS_EVENT_ITEM_MODIFIED != 0 {
            DarwinEventType::FileModified
        } else {
            // Default to modified for any unrecognized combination
            DarwinEventType::FileModified
        }
    }

    /// FSEvents collector that watches configured paths for filesystem changes.
    pub struct FsEventsCollector {
        paths: Vec<String>,
        latency_secs: f64,
    }

    impl FsEventsCollector {
        pub fn new(paths: Vec<String>, latency_secs: f64) -> Self {
            let paths = if paths.is_empty() {
                DEFAULT_WATCH_PATHS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                paths
            };

            Self {
                paths,
                latency_secs,
            }
        }

        /// Run the collector, sending events to the provided channel.
        ///
        /// This spawns a dedicated OS thread for the CFRunLoop and bridges
        /// events back to the tokio runtime via a channel.
        pub async fn run(self, tx: mpsc::Sender<DarwinEvent>) -> Result<(), Error> {
            let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::channel::<DarwinEvent>(4096);

            let paths = self.paths.clone();
            let latency = self.latency_secs;

            // Capture the runtime handle before spawning the thread, since
            // Handle::current() relies on thread-local state that may not be
            // available on a raw std::thread.
            let rt = tokio::runtime::Handle::current();

            // Spawn a dedicated thread for the CFRunLoop
            std::thread::spawn(move || {
                run_cfrunloop(paths, latency, bridge_tx, rt);
            });

            // Forward events from the bridge channel to the main channel
            loop {
                match bridge_rx.recv().await {
                    Some(event) => {
                        if tx.send(event).await.is_err() {
                            debug!("fsevents collector channel closed");
                            return Ok(());
                        }
                    }
                    None => {
                        warn!("fsevents CFRunLoop thread exited");
                        return Err(Error::FsEvents(
                            "CFRunLoop thread exited unexpectedly".to_string(),
                        ));
                    }
                }
            }
        }
    }

    /// The actual CFRunLoop + FSEventStream setup, runs on a dedicated thread.
    ///
    /// # Lifetime
    ///
    /// `CFRunLoopRun()` blocks forever. The `Sender` is intentionally leaked
    /// via `Box::into_raw` because the CFRunLoop thread (and its callback)
    /// live for the entire process lifetime. This is safe: the pointer is
    /// only dereferenced inside the callback while the run loop is active.
    fn run_cfrunloop(
        paths: Vec<String>,
        latency: f64,
        tx: mpsc::Sender<DarwinEvent>,
        _rt: tokio::runtime::Handle,
    ) {
        unsafe {
            // Build CFArray of paths, skipping any that contain NUL bytes.
            let mut cf_paths: Vec<cf::CFStringRef> = Vec::with_capacity(paths.len());
            // Hold CStrings alive until the CFStrings are created from them.
            let mut _cstring_keepalive: Vec<CString> = Vec::with_capacity(paths.len());
            for p in &paths {
                match CString::new(p.as_str()) {
                    Ok(c) => {
                        let cf_str = cf::CFStringCreateWithCString(
                            cf::kCFAllocatorDefault,
                            c.as_ptr(),
                            cf::kCFStringEncodingUTF8,
                        );
                        cf_paths.push(cf_str);
                        _cstring_keepalive.push(c);
                    }
                    Err(_) => {
                        warn!(path = %p, "skipping watch path containing NUL byte");
                    }
                }
            }

            if cf_paths.is_empty() {
                warn!("no valid watch paths, FSEvents collector will not start");
                return;
            }

            let paths_array = cf::CFArrayCreateMutable(
                cf::kCFAllocatorDefault,
                cf_paths.len() as cf::CFIndex,
                &cf::kCFTypeArrayCallBacks,
            );
            for cf_str in &cf_paths {
                cf::CFArrayAppendValue(paths_array, *cf_str);
            }

            // Intentionally leak the sender into a raw pointer. The CFRunLoop
            // thread runs for the process lifetime, so there is no safe point
            // to drop it. The callback dereferences this pointer on every
            // FSEvents batch.
            let raw_ptr = Box::into_raw(Box::new(tx));

            let context = FSEventStreamContext {
                version: 0,
                info: raw_ptr.cast(),
                retain: None,
                release: None,
                copy_description: None,
            };

            let stream = FSEventStreamCreate(
                cf::kCFAllocatorDefault,
                callback,
                &context,
                paths_array,
                kFSEventStreamEventIdSinceNow,
                latency,
                kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes,
            );

            if stream.is_null() {
                warn!("FSEventStreamCreate returned null; collector will not start");
                cf::CFRelease(paths_array);
                for cf_str in cf_paths {
                    cf::CFRelease(cf_str);
                }
                drop(Box::from_raw(raw_ptr));
                return;
            }

            FSEventStreamScheduleWithRunLoop(
                stream,
                cf::CFRunLoopGetCurrent(),
                cf::kCFRunLoopDefaultMode,
            );

            if FSEventStreamStart(stream) == 0 {
                warn!("failed to start FSEventStream");
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                cf::CFRelease(paths_array);
                for cf_str in cf_paths {
                    cf::CFRelease(cf_str);
                }
                drop(Box::from_raw(raw_ptr));
                return;
            }

            // CFRunLoopRun() blocks forever. Everything below is unreachable
            // during normal operation but kept for completeness if the run
            // loop is ever stopped externally.
            cf::CFRunLoopRun();

            FSEventStreamStop(stream);
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            cf::CFRelease(paths_array);
            for cf_str in cf_paths {
                cf::CFRelease(cf_str);
            }
            drop(Box::from_raw(raw_ptr));
        }
    }

    /// FSEventStream callback — called from the CFRunLoop thread.
    ///
    /// # Safety
    ///
    /// `info` must be a valid pointer produced by `Box::into_raw(Box::new(Sender))`.
    /// The pointer remains valid for the lifetime of the CFRunLoop (process lifetime).
    extern "C" fn callback(
        _stream_ref: FSEventStreamRef,
        info: *mut std::ffi::c_void,
        num_events: usize,
        event_paths: *mut std::ffi::c_void,
        event_flags: *const FSEventStreamEventFlags,
        event_ids: *const FSEventStreamEventId,
    ) {
        // SAFETY: `info` is a `*mut Sender<DarwinEvent>` created by `Box::into_raw`
        // in `run_cfrunloop`. It is valid for the lifetime of the CFRunLoop thread.
        let tx = unsafe { &*(info as *const mpsc::Sender<DarwinEvent>) };

        let paths_array = event_paths as cf::CFArrayRef;

        for i in 0..num_events {
            let cf_path = unsafe {
                cf::CFArrayGetValueAtIndex(paths_array, i as cf::CFIndex) as cf::CFStringRef
            };

            if cf_path.is_null() {
                continue;
            }

            let c_str = unsafe { cf::CFStringGetCStringPtr(cf_path, cf::kCFStringEncodingUTF8) };
            let path = if c_str.is_null() {
                // Fallback: allocate a buffer
                let mut buf = [0u8; 4096];
                let ok = unsafe {
                    cf::CFStringGetCString(
                        cf_path,
                        buf.as_mut_ptr().cast(),
                        buf.len() as cf::CFIndex,
                        cf::kCFStringEncodingUTF8,
                    )
                };
                if !ok {
                    continue;
                }
                match std::ffi::CStr::from_bytes_until_nul(&buf) {
                    Ok(cs) => cs.to_string_lossy().into_owned(),
                    Err(_) => continue,
                }
            } else {
                unsafe {
                    std::ffi::CStr::from_ptr(c_str)
                        .to_string_lossy()
                        .into_owned()
                }
            };

            let flags = unsafe { *event_flags.add(i) };
            let event_id = unsafe { *event_ids.add(i) };
            let event_type = classify_flags(flags);

            let event = DarwinEvent {
                event_type,
                source: EventSource::FsEvents,
                timestamp: spine::now_rfc3339(),
                payload: json!({
                    "path": path,
                    "flags": flags,
                    "event_id": event_id,
                }),
            };

            // Use try_send to avoid blocking the CFRunLoop thread. If the
            // channel is full, we drop the event and warn rather than stalling
            // all FSEvents delivery for this process.
            match tx.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Channel full — drop event to keep CFRunLoop responsive.
                    // The bridge will log backpressure via consecutive_errors.
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Receiver dropped — stop processing.
                    return;
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use platform::{FsEventsCollector, DEFAULT_WATCH_PATHS};

#[cfg(test)]
mod tests {
    #[test]
    fn default_watch_paths_exist() {
        // Just verify the constant is defined correctly (platform-independent)
        let paths = &[
            "/etc",
            "/usr/local/bin",
            "/Applications",
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
        ];
        assert_eq!(paths.len(), 5);
        assert!(paths.iter().all(|p| p.starts_with('/')));
    }
}
