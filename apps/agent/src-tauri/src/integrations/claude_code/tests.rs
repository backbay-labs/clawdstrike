use super::hook_script::HOOK_SCRIPT;
use super::*;

#[test]
fn test_hook_script_contains_essentials() {
    assert!(HOOK_SCRIPT.contains("jq -cn"));
    assert!(HOOK_SCRIPT.contains("/api/v1/agent/policy-check"));
    assert!(HOOK_SCRIPT.contains("/api/v1/agent/edr/developer-activity"));
    assert!(!HOOK_SCRIPT.contains("CLAWDSTRIKE_HOOK_FAIL_OPEN"));
    assert!(HOOK_SCRIPT.contains("ACTION_TYPE=\"mcp_tool\""));
}

#[test]
fn test_hook_script_escapes_json_payload() {
    assert!(HOOK_SCRIPT.contains("--arg target \"$TARGET\""));
    assert!(!HOOK_SCRIPT.contains("\\\"target\\\":\\\"${TARGET}\\\""));
}

#[test]
fn test_hook_script_handles_unknown_tools_via_mcp_tool_args() {
    assert!(HOOK_SCRIPT.contains("--argjson args \"$TOOL_INPUT\""));
    assert!(HOOK_SCRIPT.contains("Unknown tool: treat as an MCP tool"));
}

#[test]
fn test_hook_script_best_effort_publishes_developer_activity() {
    assert!(HOOK_SCRIPT.contains("publish_developer_activity || true"));
    assert!(HOOK_SCRIPT.contains("collectorKind: \"claude_code_hook\""));
    assert!(HOOK_SCRIPT.contains("secret_activity"));
    assert!(HOOK_SCRIPT.contains("*.npmrc*|*.pypirc*|*cargo/credentials*"));
    assert!(HOOK_SCRIPT.contains("activity_kind=\"package_script\""));
    assert!(HOOK_SCRIPT.contains("activity_kind=\"cloud_cli\""));
    assert!(HOOK_SCRIPT.contains(
        "aws|gcloud|az|gh|vercel|netlify|wrangler|doctl|fly|flyctl|op|vault|doppler|heroku|supabase|kubectl|pulumi|circleci"
    ));
    assert!(HOOK_SCRIPT.contains("*\"secret set\"*"));
    assert!(HOOK_SCRIPT.contains("*\"secret put\"*"));
    assert!(HOOK_SCRIPT.contains("*\"registry docker-config\"*"));
    assert!(HOOK_SCRIPT.contains("*\"secrets set\"*"));
    assert!(HOOK_SCRIPT.contains("*\"env pull\"*"));
    assert!(HOOK_SCRIPT.contains("*\"env:get\"*"));
    assert!(HOOK_SCRIPT.contains("shellClassifier: \"package_script\""));
    assert!(HOOK_SCRIPT.contains("shellClassifier: \"cloud_cli\""));
}

#[test]
fn test_hook_script_classifies_secret_platform_cloud_cli_activity() {
    assert!(HOOK_SCRIPT.contains(
        "op|vault|doppler|heroku|supabase|kubectl|pulumi|circleci|glab|buildkite-agent|bk"
    ));
    assert!(HOOK_SCRIPT.contains("*\"item get\"*"));
    assert!(HOOK_SCRIPT.contains("*\"document get\"*"));
    assert!(HOOK_SCRIPT.contains("*\"secret get\"*"));
    assert!(HOOK_SCRIPT.contains("*\"kv get\"*"));
    assert!(HOOK_SCRIPT.contains("*\"secrets download\"*"));
    assert!(HOOK_SCRIPT.contains("*\"config:get\"*"));
    assert!(HOOK_SCRIPT.contains("*\"get secret\"*"));
    assert!(HOOK_SCRIPT.contains("*\"--show-secrets\"*"));
    assert!(HOOK_SCRIPT.contains("*\"context store-secret\"*"));
    assert!(HOOK_SCRIPT.contains("*\"variable set\"*"));
}

#[test]
fn test_hook_script_classifies_package_registry_token_activity() {
    assert!(HOOK_SCRIPT.contains("secret_classifier=\"package_registry_token_command\""));
    assert!(HOOK_SCRIPT.contains("secret_target=\"${shell_base}:token\""));
    assert!(HOOK_SCRIPT.contains("secret_name=\"${shell_base}-token\""));
    assert!(HOOK_SCRIPT.contains("*\"token list\"*|*\"token create\"*|*\"token revoke\"*"));
    assert!(HOOK_SCRIPT.contains("*\"_authtoken\"*|*\"node_auth_token\"*|*\"npm_token\"*"));
    assert!(HOOK_SCRIPT.contains("shellClassifier: $secret_classifier"));
}

#[test]
fn test_hook_script_does_not_skip_grep_without_path() {
    // Grep can be invoked without a path (search full workspace); ensure we still produce a
    // non-empty TARGET by falling back to the search pattern.
    assert!(HOOK_SCRIPT.contains("Grep)"));
    assert!(HOOK_SCRIPT.contains(".file_path // .path // .pattern"));
}

#[test]
fn test_integration_paths() {
    let integration = ClaudeCodeIntegration::new();
    assert!(integration.claude_dir.to_string_lossy().contains(".claude"));
    assert!(integration.hooks_dir.to_string_lossy().contains("hooks"));
}
