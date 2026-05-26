//! Signed OTA updater for managed hushd binaries.

mod manifest;
mod service;
mod types;

pub use service::HushdUpdater;
pub use types::OtaStatus;

#[cfg(test)]
mod tests;
