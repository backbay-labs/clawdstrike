//! Parity test: EgressAllowlistGuard as a CustomGuardFactory plugin.
//!
//! Proves that the built-in EgressAllowlistGuard can be wrapped as a
//! custom guard factory and registered in CustomGuardRegistry, demonstrating
//! that the same guard works via the plugin/custom_guards policy path.

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::error::Result;
    use crate::guards::{
        custom::{CustomGuardFactory, CustomGuardRegistry},
        egress_allowlist::{EgressAllowlistConfig, EgressAllowlistGuard},
        Guard, GuardAction, GuardContext,
    };

    /// A factory that builds EgressAllowlistGuard from JSON config.
    /// This is exactly what a plugin package would provide.
    struct EgressAllowlistGuardFactory;

    impl CustomGuardFactory for EgressAllowlistGuardFactory {
        fn id(&self) -> &str {
            "egress_allowlist"
        }

        fn build(&self, config: Value) -> Result<Box<dyn Guard>> {
            let guard_config: EgressAllowlistConfig =
                if config.is_null() || config == Value::Object(Default::default()) {
                    EgressAllowlistConfig::with_defaults()
                } else {
                    serde_json::from_value(config).map_err(|e| {
                        crate::error::Error::ConfigError(format!("Invalid egress config: {}", e))
                    })?
                };
            Ok(Box::new(EgressAllowlistGuard::with_config(guard_config)))
        }
    }

    #[test]
    fn factory_registers_and_builds() {
        let mut registry = CustomGuardRegistry::new();
        registry.register(EgressAllowlistGuardFactory);

        let guard = registry.build("egress_allowlist", serde_json::json!({}));
        assert!(guard.is_ok(), "factory should build from empty config");
    }

    #[tokio::test]
    async fn custom_guard_produces_same_verdicts_as_builtin() {
        let mut registry = CustomGuardRegistry::new();
        registry.register(EgressAllowlistGuardFactory);

        let guard = registry
            .build("egress_allowlist", serde_json::json!({}))
            .expect("build should succeed");

        let ctx = GuardContext::new();

        // Allowed domain (in default allowlist)
        let result = guard
            .check(&GuardAction::NetworkEgress("api.openai.com", 443), &ctx)
            .await;
        assert!(result.allowed, "api.openai.com should be allowed");
        assert_eq!(result.guard, "egress_allowlist");

        // Denied domain (not in allowlist)
        let result = guard
            .check(&GuardAction::NetworkEgress("evil.com", 443), &ctx)
            .await;
        assert!(!result.allowed, "evil.com should be denied");
        assert_eq!(result.guard, "egress_allowlist");
    }

    #[test]
    fn custom_guard_handles_network_egress_only() {
        let mut registry = CustomGuardRegistry::new();
        registry.register(EgressAllowlistGuardFactory);

        let guard = registry
            .build("egress_allowlist", serde_json::json!({}))
            .expect("build should succeed");

        assert!(
            guard.handles(&GuardAction::NetworkEgress("example.com", 443)),
            "should handle NetworkEgress"
        );
        assert!(
            !guard.handles(&GuardAction::FileAccess("/tmp/test")),
            "should not handle FileAccess"
        );
    }

    #[test]
    fn custom_guard_name_matches_builtin() {
        let mut registry = CustomGuardRegistry::new();
        registry.register(EgressAllowlistGuardFactory);

        let guard = registry
            .build("egress_allowlist", serde_json::json!({}))
            .expect("build should succeed");

        assert_eq!(guard.name(), "egress_allowlist");
    }
}
