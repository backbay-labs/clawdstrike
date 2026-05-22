//! Pure helpers for endpoint response execution: effect extraction and target resolution.

pub(crate) mod effect;
pub(crate) mod targets;

pub(crate) use effect::*;
pub(crate) use targets::*;
