# Policy Inheritance (`extends`) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement policy inheritance with `extends` field so policies can build upon built-in rulesets or other YAML files, with configurable merge strategies and pattern modification.

**Architecture:** Add `extends`, `merge_strategy`, and per-guard `additional_patterns`/`remove_patterns` fields to the Policy struct. Load base policy (from built-in ruleset or file path), then merge override policy on top using the specified strategy. Support recursive extension with circular dependency detection.

**Tech Stack:** Rust, serde_yaml, std::collections::HashSet (for cycle detection), glob patterns

---

## Task 1: Add `MergeStrategy` Enum

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

Add to the `tests` module at the end of `policy.rs`:

```rust
#[test]
fn test_merge_strategy_default() {
    let yaml = r#"
version: "1.0.0"
name: Test
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.merge_strategy, MergeStrategy::DeepMerge);
}

#[test]
fn test_merge_strategy_parse() {
    let yaml = r#"
version: "1.0.0"
name: Test
merge_strategy: replace
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.merge_strategy, MergeStrategy::Replace);
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_merge_strategy`
Expected: FAIL with "cannot find value `merge_strategy`"

**Step 3: Write minimal implementation**

Add the enum and field to `policy.rs` before the `Policy` struct:

```rust
/// Strategy for merging policies when using extends
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Replace base entirely with child values
    Replace,
    /// Shallow merge: child values override base at top level
    Merge,
    /// Deep merge: recursively merge nested structures
    #[default]
    DeepMerge,
}
```

Then add the field to the `Policy` struct after `description`:

```rust
    /// Strategy for merging with base policy
    #[serde(default)]
    pub merge_strategy: MergeStrategy,
```

And update `Policy::default()`:

```rust
impl Default for Policy {
    fn default() -> Self {
        Self {
            version: default_version(),
            name: String::new(),
            description: String::new(),
            merge_strategy: MergeStrategy::default(),
            guards: GuardConfigs::default(),
            settings: PolicySettings::default(),
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_merge_strategy`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): add MergeStrategy enum for policy inheritance"
```

---

## Task 2: Add `extends` Field to Policy

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_extends_field_parse() {
    let yaml = r#"
version: "1.0.0"
name: Test
extends: strict
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.extends, Some("strict".to_string()));
}

#[test]
fn test_extends_field_none_by_default() {
    let yaml = r#"
version: "1.0.0"
name: Test
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(policy.extends.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_extends_field`
Expected: FAIL with "cannot find value `extends`"

**Step 3: Write minimal implementation**

Add the field to `Policy` struct after `description`:

```rust
    /// Base policy to extend (ruleset name or file path)
    #[serde(default)]
    pub extends: Option<String>,
```

Update `Policy::default()` to include:

```rust
            extends: None,
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_extends_field`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): add extends field for policy inheritance"
```

---

## Task 3: Add Merge Pattern Fields to Guard Configs

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/forbidden_path.rs`
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/egress_allowlist.rs`
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/mcp_tool.rs`

**Step 1: Write the failing test**

Add to `forbidden_path.rs` tests:

```rust
#[test]
fn test_additional_patterns_field() {
    let yaml = r#"
patterns:
  - "**/.ssh/**"
additional_patterns:
  - "**/custom/**"
remove_patterns:
  - "**/.ssh/**"
"#;
    let config: ForbiddenPathConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.additional_patterns, vec!["**/custom/**"]);
    assert_eq!(config.remove_patterns, vec!["**/.ssh/**"]);
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_additional_patterns`
Expected: FAIL with "missing field"

**Step 3: Write minimal implementation**

Add to `ForbiddenPathConfig` in `forbidden_path.rs`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForbiddenPathConfig {
    /// Glob patterns for forbidden paths
    #[serde(default = "default_forbidden_patterns")]
    pub patterns: Vec<String>,
    /// Additional allowed paths (exceptions)
    #[serde(default)]
    pub exceptions: Vec<String>,
    /// Additional patterns to add when merging (for extends)
    #[serde(default)]
    pub additional_patterns: Vec<String>,
    /// Patterns to remove when merging (for extends)
    #[serde(default)]
    pub remove_patterns: Vec<String>,
}
```

Similarly update `EgressAllowlistConfig` in `egress_allowlist.rs`:

```rust
    /// Additional allowed domains when merging
    #[serde(default)]
    pub additional_allow: Vec<String>,
    /// Domains to remove from allow list when merging
    #[serde(default)]
    pub remove_allow: Vec<String>,
    /// Additional blocked domains when merging
    #[serde(default)]
    pub additional_block: Vec<String>,
    /// Domains to remove from block list when merging
    #[serde(default)]
    pub remove_block: Vec<String>,
```

Similarly update `McpToolConfig` in `mcp_tool.rs`:

```rust
    /// Additional allowed tools when merging
    #[serde(default)]
    pub additional_allow: Vec<String>,
    /// Tools to remove from allow list when merging
    #[serde(default)]
    pub remove_allow: Vec<String>,
    /// Additional blocked tools when merging
    #[serde(default)]
    pub additional_block: Vec<String>,
    /// Tools to remove from block list when merging
    #[serde(default)]
    pub remove_block: Vec<String>,
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_additional_patterns`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/guards/forbidden_path.rs crates/hushclaw/src/guards/egress_allowlist.rs crates/hushclaw/src/guards/mcp_tool.rs
git commit -m "feat(guards): add additional/remove pattern fields for merge support"
```

---

## Task 4: Implement `resolve_base()` Function

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_resolve_base_builtin_strict() {
    let base = Policy::resolve_base("strict").unwrap();
    assert!(base.settings.fail_fast);
}

#[test]
fn test_resolve_base_builtin_default() {
    let base = Policy::resolve_base("default").unwrap();
    assert!(!base.settings.fail_fast);
}

#[test]
fn test_resolve_base_unknown_returns_error() {
    let result = Policy::resolve_base("nonexistent");
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_resolve_base`
Expected: FAIL with "cannot find function `resolve_base`"

**Step 3: Write minimal implementation**

Add to `impl Policy`:

```rust
    /// Resolve a base policy by name or path
    ///
    /// Tries built-in ruleset names first (default, strict, permissive),
    /// then falls back to loading from file path.
    pub fn resolve_base(name_or_path: &str) -> Result<Self> {
        // Try built-in rulesets first
        if let Some(ruleset) = RuleSet::by_name(name_or_path) {
            return Ok(ruleset.policy);
        }

        // Try loading from file
        let path = std::path::Path::new(name_or_path);
        if path.exists() {
            return Self::from_yaml_file(path);
        }

        Err(Error::ConfigError(format!(
            "Unknown ruleset or file not found: {}",
            name_or_path
        )))
    }
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_resolve_base`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): add resolve_base() for policy lookup"
```

---

## Task 5: Implement Guard Config Merging Helpers

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/forbidden_path.rs`
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/egress_allowlist.rs`
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/guards/mcp_tool.rs`

**Step 1: Write the failing test**

Add to `forbidden_path.rs` tests:

```rust
#[test]
fn test_merge_patterns() {
    let base = ForbiddenPathConfig {
        patterns: vec!["**/.ssh/**".to_string(), "**/.env".to_string()],
        exceptions: vec![],
        additional_patterns: vec![],
        remove_patterns: vec![],
    };

    let child = ForbiddenPathConfig {
        patterns: vec![],
        exceptions: vec![],
        additional_patterns: vec!["**/secrets/**".to_string()],
        remove_patterns: vec!["**/.env".to_string()],
    };

    let merged = base.merge_with(&child);

    assert!(merged.patterns.contains(&"**/.ssh/**".to_string()));
    assert!(merged.patterns.contains(&"**/secrets/**".to_string()));
    assert!(!merged.patterns.contains(&"**/.env".to_string()));
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_merge_patterns`
Expected: FAIL with "cannot find function `merge_with`"

**Step 3: Write minimal implementation**

Add to `impl ForbiddenPathConfig`:

```rust
impl ForbiddenPathConfig {
    /// Merge this config with a child config
    ///
    /// - Start with base patterns
    /// - Add child's additional_patterns
    /// - Remove child's remove_patterns
    /// - Child's patterns replace if non-empty (for Replace strategy)
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut patterns: Vec<String> = self.patterns.clone();

        // Add additional patterns
        for p in &child.additional_patterns {
            if !patterns.contains(p) {
                patterns.push(p.clone());
            }
        }

        // Remove specified patterns
        patterns.retain(|p| !child.remove_patterns.contains(p));

        // Merge exceptions
        let mut exceptions = self.exceptions.clone();
        for e in &child.exceptions {
            if !exceptions.contains(e) {
                exceptions.push(e.clone());
            }
        }

        Self {
            patterns,
            exceptions,
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }
}
```

Similarly add `merge_with` to `EgressAllowlistConfig`:

```rust
impl EgressAllowlistConfig {
    /// Merge this config with a child config
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut allow = self.allow.clone();
        let mut block = self.block.clone();

        // Add additional domains
        for d in &child.additional_allow {
            if !allow.contains(d) {
                allow.push(d.clone());
            }
        }
        for d in &child.additional_block {
            if !block.contains(d) {
                block.push(d.clone());
            }
        }

        // Remove specified domains
        allow.retain(|d| !child.remove_allow.contains(d));
        block.retain(|d| !child.remove_block.contains(d));

        // Use child's allow/block if non-empty
        if !child.allow.is_empty() {
            allow = child.allow.clone();
        }
        if !child.block.is_empty() {
            block = child.block.clone();
        }

        Self {
            allow,
            block,
            default_action: if child.default_action != default_policy() {
                child.default_action.clone()
            } else {
                self.default_action.clone()
            },
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}
```

Similarly add `merge_with` to `McpToolConfig`:

```rust
impl McpToolConfig {
    /// Merge this config with a child config
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut allow = self.allow.clone();
        let mut block = self.block.clone();
        let mut require_confirmation = self.require_confirmation.clone();

        // Add additional tools
        for t in &child.additional_allow {
            if !allow.contains(t) {
                allow.push(t.clone());
            }
        }
        for t in &child.additional_block {
            if !block.contains(t) {
                block.push(t.clone());
            }
        }

        // Remove specified tools
        allow.retain(|t| !child.remove_allow.contains(t));
        block.retain(|t| !child.remove_block.contains(t));

        // Use child's lists if non-empty
        if !child.allow.is_empty() {
            allow = child.allow.clone();
        }
        if !child.block.is_empty() {
            block = child.block.clone();
        }
        if !child.require_confirmation.is_empty() {
            require_confirmation = child.require_confirmation.clone();
        }

        Self {
            allow,
            block,
            require_confirmation,
            default_action: if child.default_action != default_action() {
                child.default_action.clone()
            } else {
                self.default_action.clone()
            },
            max_args_size: if child.max_args_size != default_max_args_size() {
                child.max_args_size
            } else {
                self.max_args_size
            },
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_merge_patterns`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/guards/forbidden_path.rs crates/hushclaw/src/guards/egress_allowlist.rs crates/hushclaw/src/guards/mcp_tool.rs
git commit -m "feat(guards): implement merge_with() for guard config merging"
```

---

## Task 6: Implement `GuardConfigs::merge_with()`

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_guard_configs_merge() {
    use crate::guards::ForbiddenPathConfig;

    let base = GuardConfigs {
        forbidden_path: Some(ForbiddenPathConfig {
            patterns: vec!["**/.ssh/**".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let child = GuardConfigs {
        forbidden_path: Some(ForbiddenPathConfig {
            additional_patterns: vec!["**/secrets/**".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let fp = merged.forbidden_path.unwrap();
    assert!(fp.patterns.contains(&"**/.ssh/**".to_string()));
    assert!(fp.patterns.contains(&"**/secrets/**".to_string()));
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_guard_configs_merge`
Expected: FAIL with "cannot find function `merge_with`"

**Step 3: Write minimal implementation**

Add to `policy.rs`:

```rust
impl GuardConfigs {
    /// Merge with another GuardConfigs (child overrides base)
    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            forbidden_path: match (&self.forbidden_path, &child.forbidden_path) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            egress_allowlist: match (&self.egress_allowlist, &child.egress_allowlist) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            secret_leak: child.secret_leak.clone().or_else(|| self.secret_leak.clone()),
            patch_integrity: child.patch_integrity.clone().or_else(|| self.patch_integrity.clone()),
            mcp_tool: match (&self.mcp_tool, &child.mcp_tool) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_guard_configs_merge`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): implement GuardConfigs::merge_with()"
```

---

## Task 7: Implement `Policy::merge()`

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_policy_merge_deep() {
    let base = Policy {
        name: "Base".to_string(),
        settings: PolicySettings {
            fail_fast: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let child = Policy {
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::DeepMerge,
        settings: PolicySettings {
            verbose_logging: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let merged = base.merge(&child);
    assert_eq!(merged.name, "Child");
    assert!(merged.settings.fail_fast); // from base
    assert!(merged.settings.verbose_logging); // from child
}

#[test]
fn test_policy_merge_replace() {
    let base = Policy {
        name: "Base".to_string(),
        settings: PolicySettings {
            fail_fast: true,
            verbose_logging: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let child = Policy {
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::Replace,
        settings: PolicySettings::default(),
        ..Default::default()
    };

    let merged = base.merge(&child);
    assert_eq!(merged.name, "Child");
    assert!(!merged.settings.fail_fast); // child replaces
    assert!(!merged.settings.verbose_logging); // child replaces
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_policy_merge`
Expected: FAIL with "cannot find function `merge`"

**Step 3: Write minimal implementation**

Add to `impl Policy`:

```rust
    /// Merge this policy with a child policy
    ///
    /// Uses child's merge_strategy to determine how to combine.
    pub fn merge(&self, child: &Policy) -> Self {
        match child.merge_strategy {
            MergeStrategy::Replace => child.clone(),
            MergeStrategy::Merge => Self {
                version: if child.version != default_version() {
                    child.version.clone()
                } else {
                    self.version.clone()
                },
                name: if !child.name.is_empty() {
                    child.name.clone()
                } else {
                    self.name.clone()
                },
                description: if !child.description.is_empty() {
                    child.description.clone()
                } else {
                    self.description.clone()
                },
                extends: None, // Don't propagate extends
                merge_strategy: MergeStrategy::default(),
                guards: if child.guards != GuardConfigs::default() {
                    child.guards.clone()
                } else {
                    self.guards.clone()
                },
                settings: if child.settings != PolicySettings::default() {
                    child.settings.clone()
                } else {
                    self.settings.clone()
                },
            },
            MergeStrategy::DeepMerge => Self {
                version: if child.version != default_version() {
                    child.version.clone()
                } else {
                    self.version.clone()
                },
                name: if !child.name.is_empty() {
                    child.name.clone()
                } else {
                    self.name.clone()
                },
                description: if !child.description.is_empty() {
                    child.description.clone()
                } else {
                    self.description.clone()
                },
                extends: None,
                merge_strategy: MergeStrategy::default(),
                guards: self.guards.merge_with(&child.guards),
                settings: PolicySettings {
                    fail_fast: if child.settings.fail_fast != PolicySettings::default().fail_fast {
                        child.settings.fail_fast
                    } else {
                        self.settings.fail_fast
                    },
                    verbose_logging: if child.settings.verbose_logging != PolicySettings::default().verbose_logging {
                        child.settings.verbose_logging
                    } else {
                        self.settings.verbose_logging
                    },
                    session_timeout_secs: if child.settings.session_timeout_secs != default_timeout() {
                        child.settings.session_timeout_secs
                    } else {
                        self.settings.session_timeout_secs
                    },
                },
            },
        }
    }
```

Note: You'll need to derive `PartialEq` on `GuardConfigs` and `PolicySettings`:

```rust
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GuardConfigs {
```

```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicySettings {
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_policy_merge`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): implement Policy::merge() with strategy support"
```

---

## Task 8: Implement `from_yaml_file_with_extends()`

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/src/policy.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_policy_extends_builtin() {
    let yaml = r#"
version: "1.0.0"
name: CustomStrict
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
"#;
    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Should have strict's fail_fast
    assert!(policy.settings.fail_fast);
    // Should have custom pattern merged in
    let fp = policy.guards.forbidden_path.unwrap();
    assert!(fp.patterns.iter().any(|p| p.contains("my-secrets")));
}

#[test]
fn test_policy_circular_extends_error() {
    // This would need file-based test, but we can test the detection logic
    use std::collections::HashSet;
    let mut visited = HashSet::new();
    visited.insert("policy-a".to_string());

    // Simulating circular detection
    assert!(visited.contains("policy-a"));
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_policy_extends`
Expected: FAIL with "cannot find function"

**Step 3: Write minimal implementation**

Add to `impl Policy`:

```rust
    /// Load from YAML string with extends resolution
    ///
    /// If the policy has an `extends` field, loads the base and merges.
    /// Detects circular dependencies.
    pub fn from_yaml_with_extends(yaml: &str, base_path: Option<&Path>) -> Result<Self> {
        Self::from_yaml_with_extends_internal(yaml, base_path, &mut std::collections::HashSet::new())
    }

    fn from_yaml_with_extends_internal(
        yaml: &str,
        base_path: Option<&Path>,
        visited: &mut std::collections::HashSet<String>,
    ) -> Result<Self> {
        let child: Policy = serde_yaml::from_str(yaml)?;

        if let Some(ref extends) = child.extends {
            // Check for circular dependency
            if visited.contains(extends) {
                return Err(Error::ConfigError(format!(
                    "Circular policy extension detected: {}",
                    extends
                )));
            }
            visited.insert(extends.clone());

            // Resolve base policy
            let base = if let Some(ruleset) = RuleSet::by_name(extends) {
                ruleset.policy
            } else {
                // Try as file path, relative to base_path if provided
                let extends_path = if let Some(bp) = base_path {
                    bp.parent().unwrap_or(bp).join(extends)
                } else {
                    std::path::PathBuf::from(extends)
                };

                if !extends_path.exists() {
                    return Err(Error::ConfigError(format!(
                        "Unknown ruleset or file not found: {}",
                        extends
                    )));
                }

                let base_yaml = std::fs::read_to_string(&extends_path)?;
                Self::from_yaml_with_extends_internal(
                    &base_yaml,
                    Some(&extends_path),
                    visited,
                )?
            };

            Ok(base.merge(&child))
        } else {
            Ok(child)
        }
    }

    /// Load from YAML file with extends resolution
    pub fn from_yaml_file_with_extends(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_with_extends(&content, Some(path))
    }
```

Add the import at the top of the file:

```rust
use std::path::Path;
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw test_policy_extends`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hushclaw/src/policy.rs
git commit -m "feat(policy): implement from_yaml_with_extends() with cycle detection"
```

---

## Task 9: Add CLI Support for `--resolve`

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hush-cli/src/main.rs`

**Step 1: Write the failing test**

Add to `tests.rs`:

```rust
#[test]
fn test_policy_validate_with_resolve_flag() {
    let cli = Cli::parse_from(["hush", "policy", "validate", "--resolve", "policy.yaml"]);

    match cli.command {
        Commands::Policy { command } => match command {
            PolicyCommands::Validate { file, resolve } => {
                assert_eq!(file, "policy.yaml");
                assert!(resolve);
            }
            _ => panic!("Expected Validate subcommand"),
        },
        _ => panic!("Expected Policy command"),
    }
}

#[test]
fn test_policy_show_with_merged_flag() {
    let cli = Cli::parse_from(["hush", "policy", "show", "--merged", "strict"]);

    match cli.command {
        Commands::Policy { command } => match command {
            PolicyCommands::Show { ruleset, merged } => {
                assert_eq!(ruleset, "strict");
                assert!(merged);
            }
            _ => panic!("Expected Show subcommand"),
        },
        _ => panic!("Expected Policy command"),
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hush-cli test_policy_validate_with`
Expected: FAIL with "missing field"

**Step 3: Write minimal implementation**

Update `PolicyCommands` in `main.rs`:

```rust
#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Show a ruleset's policy
    Show {
        /// Ruleset name or file path
        #[arg(default_value = "default")]
        ruleset: String,
        /// Show merged policy (resolve extends)
        #[arg(long)]
        merged: bool,
    },

    /// Validate a policy file
    Validate {
        /// Path to policy YAML file
        file: String,
        /// Resolve extends and show merged policy
        #[arg(long)]
        resolve: bool,
    },

    /// List available rulesets
    List,
}
```

Update the match arm for `PolicyCommands::Show`:

```rust
PolicyCommands::Show { ruleset, merged } => {
    if merged || std::path::Path::new(&ruleset).exists() {
        // Load from file with extends
        let policy = Policy::from_yaml_file_with_extends(&ruleset)?;
        let yaml = policy.to_yaml()?;
        println!("# Policy: {} (merged)", policy.name);
        println!("{}", yaml);
    } else {
        let rs = RuleSet::by_name(&ruleset)
            .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", ruleset))?;
        let yaml = rs.policy.to_yaml()?;
        println!("# Ruleset: {} ({})", rs.name, rs.id);
        println!("# {}", rs.description);
        println!("{}", yaml);
    }
}
```

Update the match arm for `PolicyCommands::Validate`:

```rust
PolicyCommands::Validate { file, resolve } => {
    let policy = if resolve {
        Policy::from_yaml_file_with_extends(&file)?
    } else {
        Policy::from_yaml_file(&file)?
    };

    println!("Policy is valid:");
    println!("  Version: {}", policy.version);
    println!("  Name: {}", policy.name);
    if resolve {
        if let Some(extends) = &policy.extends {
            println!("  Extends: {} (resolved)", extends);
        }
        println!("\nMerged policy:");
        println!("{}", policy.to_yaml()?);
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hush-cli test_policy_validate_with`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-cli/src/main.rs crates/hush-cli/src/tests.rs
git commit -m "feat(cli): add --resolve and --merged flags to policy commands"
```

---

## Task 10: Create Example Policies

**Files:**
- Create: `/Users/connor/Medica/hushclaw-ws21-policy-merge/examples/policies/extend-strict.yaml`
- Create: `/Users/connor/Medica/hushclaw-ws21-policy-merge/examples/policies/project-base.yaml`
- Create: `/Users/connor/Medica/hushclaw-ws21-policy-merge/examples/policies/project-dev.yaml`

**Step 1: Create example directory**

Run: `mkdir -p /Users/connor/Medica/hushclaw-ws21-policy-merge/examples/policies`

**Step 2: Create extend-strict.yaml**

```yaml
# Example: Extending the strict ruleset
version: "1.0.0"
name: Custom Strict
description: Strict ruleset with additional patterns for our company

extends: strict
merge_strategy: deep_merge

guards:
  forbidden_path:
    # Add company-specific sensitive paths
    additional_patterns:
      - "**/company-secrets/**"
      - "**/.vault-token"
    # Allow some paths that strict blocks
    exceptions:
      - "**/test-fixtures/.env"

  egress_allowlist:
    # Add our internal APIs
    additional_allow:
      - "api.internal.company.com"
      - "*.company-services.io"

settings:
  # Override timeout for our longer-running tasks
  session_timeout_secs: 3600
```

**Step 3: Create project-base.yaml**

```yaml
# Example: Base policy for a project
version: "1.0.0"
name: Project Base
description: Base security policy for MyProject

guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
    exceptions:
      - "**/.env.example"

  egress_allowlist:
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
      - "pypi.org"
    default_action: block

  mcp_tool:
    block:
      - shell_exec
      - raw_file_delete
    require_confirmation:
      - git_push
    default_action: allow

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
```

**Step 4: Create project-dev.yaml**

```yaml
# Example: Development policy extending project base
version: "1.0.0"
name: Project Dev
description: Development environment - more permissive for testing

extends: ./project-base.yaml
merge_strategy: deep_merge

guards:
  forbidden_path:
    # Allow .env in local dev
    remove_patterns:
      - "**/.env"
    # Keep .env.* files blocked
    additional_patterns:
      - "**/.env.production"

  egress_allowlist:
    # Allow additional services for dev
    additional_allow:
      - "localhost"
      - "127.0.0.1"
      - "*.local"

  mcp_tool:
    # Remove git_push from confirmation for faster iteration
    require_confirmation: []

settings:
  verbose_logging: true
  session_timeout_secs: 7200  # 2 hours for dev
```

**Step 5: Commit**

```bash
git add examples/policies/
git commit -m "docs: add example policies demonstrating extends feature"
```

---

## Task 11: Write Integration Tests

**Files:**
- Create: `/Users/connor/Medica/hushclaw-ws21-policy-merge/crates/hushclaw/tests/policy_extends.rs`

**Step 1: Create the test file**

```rust
//! Integration tests for policy extends feature

use hushclaw::{Policy, RuleSet};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_policy_extends_builtin_strict() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/custom-secret/**"
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Should have strict's settings
    assert!(policy.settings.fail_fast);

    // Should have custom pattern added
    let fp = policy.guards.forbidden_path.as_ref().unwrap();
    assert!(fp.patterns.iter().any(|p| p.contains("custom-secret")));
    // Should still have strict's patterns
    assert!(fp.patterns.iter().any(|p| p.contains(".vault")));
}

#[test]
fn test_policy_extends_file() {
    let temp_dir = TempDir::new().unwrap();

    // Create base policy
    let base_yaml = r#"
version: "1.0.0"
name: Base
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
settings:
  fail_fast: true
"#;
    let base_path = temp_dir.path().join("base.yaml");
    fs::write(&base_path, base_yaml).unwrap();

    // Create child policy
    let child_yaml = format!(r#"
version: "1.0.0"
name: Child
extends: {}
guards:
  forbidden_path:
    additional_patterns:
      - "**/secrets/**"
"#, base_path.display());

    let policy = Policy::from_yaml_with_extends(&child_yaml, None).unwrap();

    assert_eq!(policy.name, "Child");
    assert!(policy.settings.fail_fast); // from base
    let fp = policy.guards.forbidden_path.as_ref().unwrap();
    assert!(fp.patterns.iter().any(|p| p.contains(".ssh")));
    assert!(fp.patterns.iter().any(|p| p.contains("secrets")));
}

#[test]
fn test_policy_merge_strategy_replace() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
merge_strategy: replace
settings:
  fail_fast: false
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Replace strategy means child settings replace base entirely
    assert!(!policy.settings.fail_fast);
}

#[test]
fn test_policy_merge_strategy_deep_merge() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
merge_strategy: deep_merge
settings:
  verbose_logging: true
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Deep merge keeps base values not overridden
    assert!(policy.settings.fail_fast); // from strict
    assert!(policy.settings.verbose_logging); // from child
}

#[test]
fn test_policy_remove_patterns() {
    let yaml = r#"
version: "1.0.0"
name: DevPolicy
extends: default
guards:
  forbidden_path:
    remove_patterns:
      - "**/.env"
      - "**/.env.*"
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();
    let fp = policy.guards.forbidden_path.as_ref().unwrap();

    // .env patterns should be removed
    assert!(!fp.patterns.iter().any(|p| p == "**/.env"));
    // But other patterns should remain
    assert!(fp.patterns.iter().any(|p| p.contains(".ssh")));
}

#[test]
fn test_policy_circular_extends_detected() {
    let temp_dir = TempDir::new().unwrap();

    // Create policy A that extends B
    let policy_a = temp_dir.path().join("policy-a.yaml");
    let policy_b = temp_dir.path().join("policy-b.yaml");

    fs::write(&policy_a, format!(r#"
version: "1.0.0"
name: A
extends: {}
"#, policy_b.display())).unwrap();

    fs::write(&policy_b, format!(r#"
version: "1.0.0"
name: B
extends: {}
"#, policy_a.display())).unwrap();

    let result = Policy::from_yaml_file_with_extends(&policy_a);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Circular"));
}
```

**Step 2: Run tests to verify**

Run: `cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw --test policy_extends`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/hushclaw/tests/policy_extends.rs
git commit -m "test: add integration tests for policy extends feature"
```

---

## Task 12: Update Documentation

**Files:**
- Modify: `/Users/connor/Medica/hushclaw-ws21-policy-merge/docs/src/concepts/policies.md`
- Create: `/Users/connor/Medica/hushclaw-ws21-policy-merge/docs/src/guides/policy-inheritance.md`

**Step 1: Update policies.md**

Add under "## Policy Inheritance":

```markdown
## Policy Inheritance

Use `extends` to build on base policies:

```yaml
# Your policy
version: "1.0.0"
name: My Custom Policy
extends: strict

# Only specify overrides
guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
```

### Built-in Rulesets

| Name | Description |
|------|-------------|
| `default` | Balanced security |
| `strict` | Maximum security, blocks by default |
| `permissive` | Development-friendly, logs but allows |

### Extending Files

You can extend from local files:

```yaml
extends: ./base-policy.yaml
```

Paths are resolved relative to the current policy file.

### Merge Strategies

Control how child policy merges with base:

```yaml
merge_strategy: deep_merge  # default
```

| Strategy | Behavior |
|----------|----------|
| `replace` | Child completely replaces base |
| `merge` | Child values override base at top level |
| `deep_merge` | Recursively merge nested structures |

### Adding and Removing Patterns

Use `additional_patterns` and `remove_patterns` to modify base:

```yaml
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/company-secrets/**"
    remove_patterns:
      - "**/.env"  # Allow .env in this project
```
```

**Step 2: Create policy-inheritance.md guide**

```markdown
# Policy Inheritance Guide

This guide covers advanced policy inheritance patterns.

## Basic Inheritance

Start with a base policy and customize:

```yaml
# my-policy.yaml
version: "1.0.0"
name: My Project Policy
extends: strict

guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
```

## Multi-Level Inheritance

Policies can extend other custom policies:

```yaml
# team-base.yaml
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/team-secrets/**"

# project.yaml
extends: ./team-base.yaml
guards:
  egress_allowlist:
    additional_allow:
      - "api.project-service.com"
```

## Environment-Specific Policies

Create a hierarchy for different environments:

```yaml
# base.yaml - shared settings
version: "1.0.0"
name: Base
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"

# dev.yaml
extends: ./base.yaml
guards:
  forbidden_path:
    remove_patterns:
      - "**/.env"  # Allow .env in dev
settings:
  verbose_logging: true

# prod.yaml
extends: ./base.yaml
merge_strategy: deep_merge
guards:
  forbidden_path:
    additional_patterns:
      - "**/staging/**"
settings:
  fail_fast: true
```

## Validating Merged Policies

Use CLI to see the final merged policy:

```bash
# Validate and show merged result
hush policy validate --resolve my-policy.yaml

# Show a policy file with extends resolved
hush policy show --merged ./project.yaml
```

## Common Patterns

### Per-Repository Override

```yaml
# .hush/policy.yaml in your repo
extends: strict
guards:
  egress_allowlist:
    additional_allow:
      - "api.github.com"
      - "registry.npmjs.org"
```

### Team-Wide Base

```yaml
# company-policy.yaml (shared via package)
version: "1.0.0"
name: Company Base
guards:
  forbidden_path:
    additional_patterns:
      - "**/company-secrets/**"
      - "**/internal-keys/**"
```

Then in projects:

```yaml
extends: company-policy  # if registered as ruleset
# or
extends: /path/to/company-policy.yaml
```
```

**Step 3: Commit**

```bash
git add docs/src/concepts/policies.md docs/src/guides/policy-inheritance.md
git commit -m "docs: document policy inheritance and extends feature"
```

---

## Final Verification

After completing all tasks:

1. Run all tests:
```bash
cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo test -p hushclaw && cargo test -p hush-cli
```

2. Run clippy:
```bash
cd /Users/connor/Medica/hushclaw-ws21-policy-merge && cargo clippy -p hushclaw -p hush-cli -- -D warnings
```

3. Test example policies manually:
```bash
cd /Users/connor/Medica/hushclaw-ws21-policy-merge
cargo run -p hush-cli -- policy validate --resolve examples/policies/extend-strict.yaml
cargo run -p hush-cli -- policy validate --resolve examples/policies/project-dev.yaml
```

4. Final commit with all changes verified:
```bash
git add .
git commit -m "feat(policy): complete policy inheritance with extends support

- Add MergeStrategy enum (replace, merge, deep_merge)
- Add extends field for policy inheritance
- Add additional_patterns/remove_patterns to guard configs
- Implement recursive extends resolution with cycle detection
- Add CLI --resolve and --merged flags
- Include example policies and documentation"
```
