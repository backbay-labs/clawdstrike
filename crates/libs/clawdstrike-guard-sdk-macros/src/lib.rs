//! Proc macros for the clawdstrike guard SDK.
//!
//! Provides the `#[clawdstrike_guard]` attribute macro that generates the ABI
//! glue required for a WASM guard plugin.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Attribute macro that generates WASM ABI exports for a clawdstrike guard.
///
/// Apply this to a struct that implements `clawdstrike_guard_sdk::Guard`.
/// The macro generates:
/// - `clawdstrike_guard_init` — returns ABI version 1
/// - `clawdstrike_guard_handles` — reads action type from memory, delegates to `Guard::handles`
/// - `clawdstrike_guard_check` — reads input envelope from memory, delegates to `Guard::check`,
///   serializes output via `host::set_output`
/// - A global static instance of the guard (via `Default`)
///
/// # Requirements
///
/// The struct must implement both `clawdstrike_guard_sdk::Guard` and `Default`.
///
/// # Example
///
/// ```ignore
/// use clawdstrike_guard_sdk::prelude::*;
///
/// #[clawdstrike_guard]
/// #[derive(Default)]
/// struct MyGuard;
///
/// impl Guard for MyGuard {
///     fn name(&self) -> &str { "my-guard" }
///     fn handles(&self, action_type: &str) -> bool { true }
///     fn check(&self, input: GuardInput) -> GuardOutput {
///         GuardOutput::allow()
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn clawdstrike_guard(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let struct_name = &input.ident;

    let expanded = quote! {
        #input

        const _CLAWDSTRIKE_ABI_VERSION: i32 = 1;

        /// ABI init — returns the guard ABI version.
        #[unsafe(no_mangle)]
        pub extern "C" fn clawdstrike_guard_init() -> i32 {
            _CLAWDSTRIKE_ABI_VERSION
        }

        /// ABI handles — reads the action type string from the fixed memory
        /// location and delegates to `Guard::handles`.
        #[unsafe(no_mangle)]
        pub extern "C" fn clawdstrike_guard_handles(action_ptr: i32, action_len: i32) -> i32 {
            let guard = <#struct_name as Default>::default();

            let ptr = action_ptr as usize;
            let len = action_len as usize;

            // Safety: the host has written the action type bytes at `action_ptr`
            // before calling this function.  On wasm32 targets the entire linear
            // memory is a single flat byte array so this is safe as long as the
            // host wrote within bounds (which it does — validated in runtime.rs).
            let slice = unsafe {
                core::slice::from_raw_parts(ptr as *const u8, len)
            };

            let action_type = match core::str::from_utf8(slice) {
                Ok(s) => s,
                Err(_) => return 0,
            };

            if <#struct_name as clawdstrike_guard_sdk::Guard>::handles(&guard, action_type) {
                1
            } else {
                0
            }
        }

        /// ABI check — reads the input envelope JSON from the fixed memory
        /// location, delegates to `Guard::check`, and writes the output JSON
        /// via the `set_output` hostcall.
        #[unsafe(no_mangle)]
        pub extern "C" fn clawdstrike_guard_check(input_ptr: i32, input_len: i32) -> i32 {
            let guard = <#struct_name as Default>::default();

            let ptr = input_ptr as usize;
            let len = input_len as usize;

            // Safety: same rationale as `clawdstrike_guard_handles`.
            let slice = unsafe {
                core::slice::from_raw_parts(ptr as *const u8, len)
            };

            let input: clawdstrike_guard_sdk::GuardInput = match clawdstrike_guard_sdk::serde_json::from_slice(slice) {
                Ok(v) => v,
                Err(_) => {
                    // Write an explicit deny output so the host can surface the
                    // actual parse error instead of a generic sandbox fault.
                    let err_output = clawdstrike_guard_sdk::GuardOutput::deny(
                        clawdstrike_guard_sdk::Severity::Error,
                        "Failed to deserialize guard input envelope",
                    );
                    // Returning 0 is intentional when we successfully emit a deny
                    // output: the host treats non-zero as a sandbox fault and would
                    // discard this structured error signal.
                    return if clawdstrike_guard_sdk::host::set_output(&err_output).is_ok() {
                        0
                    } else {
                        1
                    };
                }
            };

            let output = <#struct_name as clawdstrike_guard_sdk::Guard>::check(&guard, input);

            match clawdstrike_guard_sdk::host::set_output(&output) {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
    };

    TokenStream::from(expanded)
}
