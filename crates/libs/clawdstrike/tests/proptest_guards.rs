//! Property-based tests for security guards

#![allow(clippy::expect_used, clippy::unwrap_used)]

use clawdstrike::{ForbiddenPathGuard, SecretLeakGuard};
use proptest::prelude::*;

proptest! {
    /// ForbiddenPathGuard never panics on any input
    #[test]
    fn forbidden_path_no_panic(path in ".*") {
        let guard = ForbiddenPathGuard::new();
        let _ = guard.is_forbidden(&path);
    }

    /// ForbiddenPathGuard is deterministic
    #[test]
    fn forbidden_path_deterministic(path in ".*") {
        let guard = ForbiddenPathGuard::new();
        let r1 = guard.is_forbidden(&path);
        let r2 = guard.is_forbidden(&path);
        prop_assert_eq!(r1, r2);
    }

    /// Safe paths (no dots, no sensitive keywords) should be allowed
    #[test]
    fn safe_paths_allowed(
        prefix in "[a-z]{1,10}",
        name in "[a-z0-9_]{1,20}",
        ext in "[a-z]{1,4}",
    ) {
        let path = format!("/tmp/{prefix}/{name}.{ext}");
        let guard = ForbiddenPathGuard::new();
        // Generic paths without sensitive patterns should be allowed
        prop_assert!(!guard.is_forbidden(&path));
    }

    /// SSH paths are always forbidden
    #[test]
    fn ssh_paths_forbidden(
        user in "[a-z]{1,10}",
        file in "(id_rsa|id_ed25519|authorized_keys|known_hosts)",
    ) {
        let path = format!("/home/{user}/.ssh/{file}");
        let guard = ForbiddenPathGuard::new();
        prop_assert!(guard.is_forbidden(&path));
    }

    /// AWS credential paths are always forbidden
    #[test]
    fn aws_paths_forbidden(
        user in "[a-z]{1,10}",
        file in "(credentials|config)",
    ) {
        let path = format!("/home/{user}/.aws/{file}");
        let guard = ForbiddenPathGuard::new();
        prop_assert!(guard.is_forbidden(&path));
    }

    /// SecretLeakGuard never panics on any input
    #[test]
    fn secret_leak_no_panic(content in prop::collection::vec(any::<u8>(), 0..1000)) {
        let guard = SecretLeakGuard::new();
        let _ = guard.scan(&content);
    }

    /// SecretLeakGuard is deterministic
    #[test]
    fn secret_leak_deterministic(content in prop::collection::vec(any::<u8>(), 0..500)) {
        let guard = SecretLeakGuard::new();
        let r1 = guard.scan(&content);
        let r2 = guard.scan(&content);
        prop_assert_eq!(r1.len(), r2.len());
    }

    /// AWS access keys are detected
    #[test]
    fn aws_keys_detected(
        suffix in "[A-Z0-9]{16}",
    ) {
        let content = format!("key = AKIA{suffix}");
        let guard = SecretLeakGuard::new();
        let matches = guard.scan(content.as_bytes());
        prop_assert!(!matches.is_empty());
    }

    /// GitHub tokens are detected
    #[test]
    fn github_tokens_detected(
        suffix in "[A-Za-z0-9]{36}",
    ) {
        let content = format!("token: ghp_{suffix}");
        let guard = SecretLeakGuard::new();
        let matches = guard.scan(content.as_bytes());
        prop_assert!(!matches.is_empty());
    }

    /// Normal code without secrets has no matches
    #[test]
    fn normal_code_no_secrets(
        fn_name in "[a-z_]{1,20}",
        var_name in "[a-z_]{1,10}",
        value in "[0-9]{1,5}",
    ) {
        let content = format!("fn {fn_name}() {{ let {var_name} = {value}; }}");
        let guard = SecretLeakGuard::new();
        let matches = guard.scan(content.as_bytes());
        prop_assert!(matches.is_empty());
    }
}
