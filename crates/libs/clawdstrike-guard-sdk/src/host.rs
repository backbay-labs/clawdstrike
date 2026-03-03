//! Host import wrappers for guest-side guards.
//!
//! These functions provide a safe Rust interface over the raw hostcalls
//! imported from the `clawdstrike_host` namespace.

use crate::types::{Capability, GuardOutput};

#[cfg(target_arch = "wasm32")]
extern "C" {
    #[link_name = "set_output"]
    fn __host_set_output(ptr: i32, len: i32) -> i32;
    #[link_name = "request_capability"]
    fn __host_request_capability(cap_kind: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn __host_set_output(_ptr: i32, _len: i32) -> i32 {
    0
}
#[cfg(not(target_arch = "wasm32"))]
unsafe fn __host_request_capability(_cap_kind: i32) -> i32 {
    0
}

/// Serialize a [`GuardOutput`] to JSON and send it to the host via the
/// `set_output` hostcall.
///
/// Returns `Ok(())` on success or `Err(msg)` if serialization or the
/// hostcall failed.
pub fn set_output(output: &GuardOutput) -> Result<(), &'static str> {
    let json = serde_json::to_vec(output).map_err(|_| "failed to serialize guard output")?;
    let ptr = json.as_ptr() as i32;
    let len = json.len() as i32;
    // Safety: `ptr` and `len` describe a valid byte slice allocated by this
    // module.  The host reads the bytes synchronously before returning.
    let rc = unsafe { __host_set_output(ptr, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err("host set_output returned non-zero")
    }
}

/// Request a runtime capability from the host.
///
/// Returns `true` if the capability is allowed by the plugin manifest,
/// `false` if denied.
pub fn request_capability(cap: Capability) -> bool {
    // Safety: `cap as i32` is a valid capability kind integer (0..=4).
    let rc = unsafe { __host_request_capability(cap as i32) };
    rc == 0
}
