//! Integration tests for the MCP module.

use super::auth::mcp_authorized;
use super::developer_activity::developer_activities_for_policy_check;
use super::server::get_mcp_config;
use crate::agent_auth::read_local_api_token;
use crate::policy::{PolicyCheckInput, PolicyCheckOutput};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use std::collections::HashMap;

#[test]
fn policy_check_params_deserialize() {
    let json = r#"{"action_type":"file_access","target":"/etc/passwd"}"#;
    let params = match serde_json::from_str::<PolicyCheckInput>(json) {
        Ok(value) => value,
        Err(err) => panic!("failed to deserialize policy_check params: {}", err),
    };
    assert_eq!(params.action_type, "file_access");
    assert_eq!(params.target, "/etc/passwd");
}

#[test]
fn mcp_config_generation() {
    let config = get_mcp_config(9877);
    let url = config["mcpServers"]["clawdstrike"]["url"]
        .as_str()
        .unwrap_or("");
    assert!(url.contains("9877"));
}

#[test]
fn policy_check_input_accepts_args() {
    let json = serde_json::json!({
        "action_type": "mcp_tool",
        "target": "run_command",
        "args": {
            "cwd": "/tmp"
        }
    });
    let parsed = serde_json::from_value::<PolicyCheckInput>(json);
    assert!(parsed.is_ok());
    let args = parsed.ok().and_then(|p| p.args).unwrap_or_default();
    assert_eq!(
        args.get("cwd").and_then(|v| v.as_str()).unwrap_or(""),
        "/tmp"
    );
}

#[test]
fn policy_check_input_without_args_deserializes() {
    let parsed = serde_json::from_value::<PolicyCheckInput>(serde_json::json!({
        "action_type": "egress",
        "target": "example.com:443"
    }));
    assert!(parsed.is_ok());
    let p = parsed.ok();
    assert_eq!(p.as_ref().map(|v| v.action_type.as_str()), Some("egress"));
}

#[test]
fn can_use_hashmap_aliases_in_args() {
    let mut args: HashMap<String, serde_json::Value> = HashMap::new();
    args.insert("flag".to_string(), serde_json::json!(true));
    let input = PolicyCheckInput {
        action_type: "mcp_tool".to_string(),
        target: "run_command".to_string(),
        content: None,
        args: Some(args),
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    assert!(input.args.as_ref().is_some_and(|m| m.contains_key("flag")));
}

#[test]
fn mcp_policy_check_projects_tool_and_secret_developer_activity() {
    let mut args: HashMap<String, serde_json::Value> = HashMap::new();
    args.insert("path".to_string(), serde_json::json!("/repo/.env"));
    let input = PolicyCheckInput {
        action_type: "mcp_tool".to_string(),
        target: "mcp__filesystem__read_file".to_string(),
        content: None,
        args: Some(args),
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-1"), &output);

    assert_eq!(activities.len(), 2);
    assert_eq!(activities[0]["kind"], "mcp_tool");
    assert_eq!(activities[0]["toolName"], "mcp__filesystem__read_file");
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-1");
    assert_eq!(activities[1]["kind"], "repo_secret");
    assert_eq!(activities[1]["path"], "/repo/.env");
    assert_eq!(activities[1]["credentialKind"], "api_token");
}

#[test]
fn mcp_policy_check_projects_package_registry_secret_target() {
    let input = PolicyCheckInput {
        action_type: "file_access".to_string(),
        target: "/Users/alice/.npmrc".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: false,
        guard: Some("developer_secret_access".to_string()),
        severity: Some("high".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-2"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "repo_secret");
    assert_eq!(activities[0]["path"], "/Users/alice/.npmrc");
    assert_eq!(activities[0]["credentialKind"], "package_registry_token");
    assert_eq!(activities[0]["agentId"], "agent:codex");
}

#[test]
fn mcp_policy_check_projects_package_manager_shell_activity() {
    let mut args: HashMap<String, serde_json::Value> = HashMap::new();
    args.insert("cwd".to_string(), serde_json::json!("/repo"));
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "npm --prefix /repo run postinstall -- --audit=false".to_string(),
        content: None,
        args: Some(args),
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: false,
        guard: Some("supply_chain".to_string()),
        severity: Some("high".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-3"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "package_script");
    assert_eq!(activities[0]["manager"], "npm");
    assert_eq!(activities[0]["phase"], "postinstall");
    assert_eq!(
        activities[0]["script"],
        "npm --prefix /repo run postinstall -- --audit=false"
    );
    assert_eq!(activities[0]["workingDirectory"], "/repo");
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-3");
    assert_eq!(
        activities[0]["metadata"]["shellClassifier"],
        "package_script"
    );
}

#[test]
fn mcp_policy_check_projects_package_registry_token_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "npm token list --json".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-npm-token"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "repo_secret");
    assert_eq!(activities[0]["path"], "npm:token");
    assert_eq!(activities[0]["name"], "npm-token");
    assert_eq!(activities[0]["credentialKind"], "package_registry_token");
    assert_eq!(activities[0]["commandLine"], "npm token list --json");
    assert_eq!(
        activities[0]["metadata"]["shellClassifier"],
        "package_registry_token_command"
    );
}

#[test]
fn mcp_policy_check_projects_cloud_cli_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "aws --profile prod secretsmanager get-secret-value --secret-id prod/db"
            .to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-4"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "aws");
    assert_eq!(activities[0]["operation"], "secretsmanager");
    assert_eq!(activities[0]["args"][0], "get-secret-value");
    assert_eq!(activities[0]["args"][1], "--secret-id");
    assert_eq!(activities[0]["args"][2], "prod/db");
    assert_eq!(
        activities[0]["commandLine"],
        "aws --profile prod secretsmanager get-secret-value --secret-id prod/db"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-4");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_github_cli_secret_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "gh secret set PROD_DB_URL --body redacted --repo acme/service".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-gh"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "gh");
    assert_eq!(activities[0]["operation"], "secret");
    assert_eq!(activities[0]["args"][0], "set");
    assert_eq!(activities[0]["args"][1], "PROD_DB_URL");
    assert_eq!(
        activities[0]["commandLine"],
        "gh secret set PROD_DB_URL --body redacted --repo acme/service"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-gh");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_vercel_env_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "vercel env pull .env.local --environment production".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-vercel"), &output);

    let activity = activities
        .iter()
        .find(|activity| activity["kind"] == "cloud_cli")
        .unwrap_or_else(|| panic!("missing vercel cloud CLI developer activity"));
    assert_eq!(activity["provider"], "vercel");
    assert_eq!(activity["operation"], "env");
    assert_eq!(activity["args"][0], "pull");
    assert_eq!(activity["args"][1], ".env.local");
    assert_eq!(
        activity["commandLine"],
        "vercel env pull .env.local --environment production"
    );
    assert_eq!(activity["agentId"], "agent:codex");
    assert_eq!(activity["sessionId"], "mcp-session-vercel");
    assert_eq!(activity["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_netlify_env_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "netlify env:get API_KEY --context production".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-netlify"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "netlify");
    assert_eq!(activities[0]["operation"], "env:get");
    assert_eq!(activities[0]["args"][0], "API_KEY");
    assert_eq!(
        activities[0]["commandLine"],
        "netlify env:get API_KEY --context production"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-netlify");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_wrangler_secret_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "wrangler secret put API_TOKEN --env production".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-wrangler"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "wrangler");
    assert_eq!(activities[0]["operation"], "secret");
    assert_eq!(activities[0]["args"][0], "put");
    assert_eq!(activities[0]["args"][1], "API_TOKEN");
    assert_eq!(
        activities[0]["commandLine"],
        "wrangler secret put API_TOKEN --env production"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-wrangler");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_doctl_registry_secret_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "doctl registry docker-config example-registry --read-write".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-doctl"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "doctl");
    assert_eq!(activities[0]["operation"], "registry");
    assert_eq!(activities[0]["args"][0], "docker-config");
    assert_eq!(
        activities[0]["commandLine"],
        "doctl registry docker-config example-registry --read-write"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-doctl");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_fly_secret_shell_activity() {
    let input = PolicyCheckInput {
        action_type: "shell".to_string(),
        target: "fly secrets set DATABASE_URL=postgres://example --app api".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: Some("agent:codex".to_string()),
        runtime_agent_kind: Some("mcp".to_string()),
    };
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    let activities =
        developer_activities_for_policy_check(&input, Some("mcp-session-fly"), &output);

    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["kind"], "cloud_cli");
    assert_eq!(activities[0]["provider"], "fly");
    assert_eq!(activities[0]["operation"], "secrets");
    assert_eq!(activities[0]["args"][0], "set");
    assert_eq!(
        activities[0]["commandLine"],
        "fly secrets set DATABASE_URL=postgres://example --app api"
    );
    assert_eq!(activities[0]["agentId"], "agent:codex");
    assert_eq!(activities[0]["sessionId"], "mcp-session-fly");
    assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
}

#[test]
fn mcp_policy_check_projects_secret_platform_shell_activity() {
    let cases = [
        (
            "op item get prod/api-token",
            "mcp-session-op",
            "op",
            "item",
            &["get", "prod/api-token"][..],
        ),
        (
            "vault kv get secret/prod/api",
            "mcp-session-vault",
            "vault",
            "kv",
            &["get", "secret/prod/api"][..],
        ),
        (
            "doppler secrets download --no-file",
            "mcp-session-doppler",
            "doppler",
            "secrets",
            &["download", "--no-file"][..],
        ),
        (
            "heroku config:get DATABASE_URL --app prod-api",
            "mcp-session-heroku",
            "heroku",
            "config:get",
            &["DATABASE_URL", "--app", "prod-api"][..],
        ),
        (
            "supabase secrets list --project-ref prodref",
            "mcp-session-supabase",
            "supabase",
            "secrets",
            &["list", "--project-ref", "prodref"][..],
        ),
        (
            "kubectl get secret prod-token -o yaml",
            "mcp-session-kubectl",
            "kubectl",
            "get",
            &["secret", "prod-token", "-o", "yaml"][..],
        ),
        (
            "pulumi config get dbPassword --show-secrets",
            "mcp-session-pulumi",
            "pulumi",
            "config",
            &["get", "dbPassword", "--show-secrets"][..],
        ),
        (
            "circleci context store-secret github acme production DATABASE_URL",
            "mcp-session-circleci",
            "circleci",
            "context",
            &[
                "store-secret",
                "github",
                "acme",
                "production",
                "DATABASE_URL",
            ][..],
        ),
        (
            "glab variable set DATABASE_URL postgres://redacted --masked",
            "mcp-session-glab",
            "glab",
            "variable",
            &["set", "DATABASE_URL", "postgres://redacted", "--masked"][..],
        ),
        (
            "buildkite-agent secret get deploy_key",
            "mcp-session-buildkite",
            "buildkite",
            "secret",
            &["get", "deploy_key"][..],
        ),
    ];
    let output = PolicyCheckOutput {
        allowed: true,
        guard: Some("allow".to_string()),
        severity: Some("info".to_string()),
        message: None,
        details: None,
    };

    for (target, session_id, provider, operation, args) in cases {
        let input = PolicyCheckInput {
            action_type: "shell".to_string(),
            target: target.to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some("agent:codex".to_string()),
            runtime_agent_kind: Some("mcp".to_string()),
        };

        let activities =
            developer_activities_for_policy_check(&input, Some(session_id), &output);

        assert_eq!(activities.len(), 1, "missing activity for {provider}");
        assert_eq!(activities[0]["kind"], "cloud_cli");
        assert_eq!(activities[0]["provider"], provider);
        assert_eq!(activities[0]["operation"], operation);
        for (index, expected_arg) in args.iter().enumerate() {
            assert_eq!(activities[0]["args"][index], *expected_arg);
        }
        assert_eq!(activities[0]["commandLine"], target);
        assert_eq!(activities[0]["agentId"], "agent:codex");
        assert_eq!(activities[0]["sessionId"], session_id);
        assert_eq!(activities[0]["metadata"]["shellClassifier"], "cloud_cli");
    }
}

#[test]
fn mcp_requires_bearer_token() {
    let expected_token = read_local_api_token().unwrap_or_else(|_| "secret-token".to_string());
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", expected_token)
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse authorization header: {err}")),
    );
    assert!(mcp_authorized(&headers, "secret-token"));
    assert!(!mcp_authorized(&HeaderMap::new(), "secret-token"));
}
