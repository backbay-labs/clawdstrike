use serde::{Deserialize, Serialize};

use crate::rules::Rules;

/// A parsed HushSpec document.
///
/// This is the top-level type representing a portable security policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HushSpec {
    /// Specification version (e.g. `"0.1.0"`).
    pub hushspec: String,
    /// Human-readable policy name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Free-form description of this policy's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parent policy to inherit from (file path, URL, or built-in name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    /// Strategy for merging with the parent policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_strategy: Option<MergeStrategy>,
    /// Core security rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
    /// Optional extension modules (posture, origins, detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<crate::extensions::Extensions>,
}

/// Strategy for merging policies when using `extends`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Child completely replaces the base policy.
    Replace,
    /// Shallow merge: child rule blocks replace base rule blocks.
    Merge,
    /// Deep merge: child fields override base fields within each rule block.
    #[default]
    DeepMerge,
}

impl HushSpec {
    /// Parse a YAML string into a `HushSpec`.
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Serialize this spec back to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}
