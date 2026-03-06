#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hunt Correlate — correlation rules, watch mode, and IOC matching for clawdstrike hunt.

pub mod detection;
pub mod engine;
pub mod error;
pub mod ioc;
pub mod report;
pub mod rules;
pub mod service;
pub mod watch;
