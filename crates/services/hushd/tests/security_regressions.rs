#![allow(clippy::expect_used, clippy::unwrap_used)]

use clawdstrike::policy::{PolicyLocation, PolicyResolver};
use hushd::config::RemoteExtendsConfig;
use hushd::remote_extends::{
    security_parse_git_remote_host, security_validate_git_commit_ref, RemoteExtendsResolverConfig,
    RemotePolicyResolver,
};

const SHA256_PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn security_regression_remote_extends_scp_remote_must_be_allowlisted() {
    let cfg = RemoteExtendsConfig {
        allowed_hosts: vec!["example.com".to_string()],
        ..RemoteExtendsConfig::default()
    };
    let resolver_cfg = RemoteExtendsResolverConfig::from_config(&cfg);
    let resolver = RemotePolicyResolver::new(resolver_cfg).expect("resolver");

    let reference = format!(
        "git+git@github.com:backbay-labs/clawdstrike.git@main:policy.yaml#sha256={}",
        SHA256_PIN
    );
    let err = resolver
        .resolve(&reference, &PolicyLocation::None)
        .expect_err("scp remote outside allowlist must be rejected");

    assert!(
        err.to_string().contains("not allowlisted"),
        "unexpected error: {err}"
    );
}

#[test]
fn security_regression_remote_extends_rejects_file_scheme_git_remote() {
    let err = security_parse_git_remote_host("file:///tmp/repo.git", true)
        .expect_err("file:// remotes must be rejected");

    assert!(
        err.to_string().contains("Unsupported git remote scheme"),
        "unexpected error: {err}"
    );
}

#[test]
fn security_regression_remote_extends_rejects_dash_prefixed_ref() {
    let err = security_validate_git_commit_ref("--upload-pack=echo")
        .expect_err("dash-prefixed commit/ref must be rejected");

    assert!(
        err.to_string().contains("must not start with '-'"),
        "unexpected error: {err}"
    );
}
