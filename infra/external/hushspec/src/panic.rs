//! Emergency override (panic mode) for HushSpec.
//!
//! When panic mode is active, **all** `evaluate()` calls return `Deny`
//! immediately, before any rule evaluation takes place.  This provides an
//! instant kill switch for agent runtimes that detect an active compromise.
//!
//! Activation mechanisms:
//!  - Programmatic: [`activate_panic`] / [`deactivate_panic`]
//!  - Sentinel file: [`check_panic_sentinel`]
//!
//! Thread safety is guaranteed via an [`AtomicBool`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Activate panic mode globally. All subsequent `evaluate()` calls will deny.
pub fn activate_panic() {
    PANIC_ACTIVE.store(true, Ordering::SeqCst);
}

/// Deactivate panic mode, restoring normal evaluation.
pub fn deactivate_panic() {
    PANIC_ACTIVE.store(false, Ordering::SeqCst);
}

/// Check if panic mode is currently active.
pub fn is_panic_active() -> bool {
    PANIC_ACTIVE.load(Ordering::SeqCst)
}

/// Get the built-in panic (deny-all) policy.
///
/// The panic policy is embedded at compile time from `rulesets/panic.yaml`.
/// Panics at runtime only if the embedded YAML is somehow invalid (which would
/// indicate a build-time defect).
pub fn panic_policy() -> crate::HushSpec {
    let yaml = include_str!("../rulesets/panic.yaml");
    crate::HushSpec::parse(yaml).expect("panic policy must be valid")
}

/// Check a sentinel file for panic activation.
///
/// If the file at `path` exists, panic mode is activated and `true` is
/// returned.  If the file does not exist, `false` is returned (panic mode
/// is **not** automatically deactivated -- use [`deactivate_panic`] for that).
pub fn check_panic_sentinel(path: impl AsRef<Path>) -> bool {
    let exists = path.as_ref().exists();
    if exists {
        activate_panic();
    }
    exists
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize panic tests -- they share the global `PANIC_ACTIVE`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn activate_and_deactivate() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        assert!(!is_panic_active());
        activate_panic();
        assert!(is_panic_active());
        deactivate_panic();
        assert!(!is_panic_active());
    }

    #[test]
    fn panic_policy_parses() {
        // Does not touch global state -- no lock needed.
        let spec = panic_policy();
        assert_eq!(spec.name.as_deref(), Some("__hushspec_panic__"));
    }

    #[test]
    fn sentinel_file_activates_panic() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        let dir = std::env::temp_dir().join("hushspec_panic_test");
        let sentinel = dir.join(".hushspec_panic");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(&sentinel, "").unwrap();

        assert!(check_panic_sentinel(&sentinel));
        assert!(is_panic_active());

        // cleanup
        let _ = std::fs::remove_file(&sentinel);
        deactivate_panic();
    }

    #[test]
    fn sentinel_file_missing_does_not_activate() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        let path = std::env::temp_dir().join("hushspec_nonexistent_sentinel");
        let _ = std::fs::remove_file(&path);

        assert!(!check_panic_sentinel(&path));
        assert!(!is_panic_active());
    }

    #[test]
    fn panic_mode_denies_all_action_types() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();
        activate_panic();

        let spec = panic_policy();
        let action_types = [
            "tool_call",
            "egress",
            "file_read",
            "file_write",
            "patch_apply",
            "shell_command",
            "computer_use",
            "unknown_action",
        ];

        for action_type in action_types {
            let action = crate::EvaluationAction {
                action_type: action_type.to_string(),
                target: Some("anything".to_string()),
                ..Default::default()
            };
            let result = crate::evaluate(&spec, &action);
            assert_eq!(
                result.decision,
                crate::Decision::Deny,
                "expected deny for action type '{}' during panic mode",
                action_type
            );
            assert_eq!(result.matched_rule.as_deref(), Some("__hushspec_panic__"));
            assert_eq!(
                result.reason.as_deref(),
                Some("emergency panic mode is active")
            );
        }

        deactivate_panic();
    }

    #[test]
    fn deactivate_restores_normal_evaluation() {
        let _guard = TEST_LOCK.lock().unwrap();
        deactivate_panic();

        // Create a permissive spec with no rules
        let yaml = r#"
hushspec: "0.1.0"
name: "permissive"
"#;
        let spec = crate::HushSpec::parse(yaml).unwrap();
        let action = crate::EvaluationAction {
            action_type: "tool_call".to_string(),
            target: Some("some_tool".to_string()),
            ..Default::default()
        };

        // Normal evaluation should allow
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Allow);

        // Activate panic -- should deny
        activate_panic();
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Deny);

        // Deactivate -- should allow again
        deactivate_panic();
        let result = crate::evaluate(&spec, &action);
        assert_eq!(result.decision, crate::Decision::Allow);
    }
}
