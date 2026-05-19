//! Claude Code integration via hooks.
//!
//! Auto-installs pre-tool hooks to ~/.claude/hooks/ for policy checking.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Hook script for pre-tool checks.
const HOOK_SCRIPT: &str = r#"#!/bin/bash
# Clawdstrike pre-tool hook for Claude Code
# Checks actions against security policy before execution

set -euo pipefail

# Configuration
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:9878}"
CLAWDSTRIKE_TOKEN_FILE="${CLAWDSTRIKE_TOKEN_FILE:-$HOME/.config/clawdstrike/agent-local-token}"

fail() {
  local reason="$1"
  echo "🚫 Clawdstrike hook error: ${reason}" >&2
  exit 1
}

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract tool name and input from hook data
if ! TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null); then
  fail "invalid hook payload: missing/invalid .tool_name"
fi

if ! TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {} | if type == "object" then . else {"tool_input": .} end' 2>/dev/null); then
  fail "invalid hook payload: .tool_input is not JSON"
fi

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
  exit 0
fi

# Map tool names to hushd /api/v1/check action types.
CONTENT=""
case "$TOOL_NAME" in
  Read)
    ACTION_TYPE="file_access"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    ;;
  Glob)
    ACTION_TYPE="file_access"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.pattern // empty' 2>/dev/null || true)
    ;;
  Grep)
    ACTION_TYPE="file_access"
    # Grep may be invoked without an explicit path (searching the full workspace). In that case
    # fall back to `.pattern` so we don't bypass the policy check entirely.
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .pattern // empty' 2>/dev/null || true)
    ;;
  Write)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    CONTENT=$(echo "$TOOL_INPUT" | jq -er '.content // .text // empty' 2>/dev/null || true)
    ;;
  Edit)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    CONTENT=$(echo "$TOOL_INPUT" | jq -er '.new_string // .content // empty' 2>/dev/null || true)
    ;;
  Bash)
    ACTION_TYPE="shell"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.command // empty' 2>/dev/null || true)
    ;;
  WebFetch|WebSearch)
    ACTION_TYPE="egress"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.url // .query // empty' 2>/dev/null || true)
    ;;
  *)
    # Unknown tool: treat as an MCP tool and let policy decide.
    ACTION_TYPE="mcp_tool"
    TARGET="$TOOL_NAME"
    ;;
esac

# Skip if no target
if [ -z "${TARGET:-}" ]; then
  exit 0
fi

RUNTIME_AGENT_KIND="claude_code"
RUNTIME_AGENT_EXTERNAL_ID=$(echo "$TOOL_INPUT" | jq -er '.agent_id // .runtime_agent_id // .session_id // .conversation_id // empty' 2>/dev/null || true)
if [ -z "${RUNTIME_AGENT_EXTERNAL_ID:-}" ]; then
  RUNTIME_AGENT_EXTERNAL_ID="${CLAUDE_AGENT_ID:-claude-code}"
fi

if [ ! -f "$CLAWDSTRIKE_TOKEN_FILE" ]; then
  fail "agent auth token file not found at $CLAWDSTRIKE_TOKEN_FILE"
fi

if ! CLAWDSTRIKE_TOKEN=$(cat "$CLAWDSTRIKE_TOKEN_FILE"); then
  fail "failed to read agent auth token"
fi

if [ -z "$CLAWDSTRIKE_TOKEN" ]; then
  fail "agent auth token is empty"
fi

RUNTIME_AGENT_ID="$RUNTIME_AGENT_EXTERNAL_ID"
REGISTER_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/runtimes/register"
if REGISTER_PAYLOAD=$(jq -cn --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --arg runtime_agent_id "$RUNTIME_AGENT_EXTERNAL_ID" '{runtime_agent_kind:$runtime_agent_kind,runtime_agent_id:$runtime_agent_id}' 2>/dev/null); then
  if REGISTER_RESPONSE=$(curl -sS --max-time 4 -X POST "$REGISTER_URL" \
    -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$REGISTER_PAYLOAD" 2>/dev/null); then
    REGISTERED_ID=$(echo "$REGISTER_RESPONSE" | jq -er '.runtime_agent_id // empty' 2>/dev/null || true)
    if [ -n "${REGISTERED_ID:-}" ]; then
      RUNTIME_AGENT_ID="$REGISTERED_ID"
    fi
  fi
fi

# Build JSON safely.
if [ "$ACTION_TYPE" = "mcp_tool" ]; then
  if [ -n "${CONTENT:-}" ]; then
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg content "$CONTENT" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --argjson args "$TOOL_INPUT" '{action_type:$action_type,target:$target,content:$content,args:$args,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  else
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --argjson args "$TOOL_INPUT" '{action_type:$action_type,target:$target,args:$args,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  fi
else
  if [ -n "${CONTENT:-}" ]; then
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg content "$CONTENT" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" '{action_type:$action_type,target:$target,content:$content,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  else
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" '{action_type:$action_type,target:$target,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  fi
fi

CHECK_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/policy-check"

if ! RESPONSE=$(curl -sS --max-time 8 -X POST "$CHECK_URL" \
  -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$PAYLOAD" 2>/dev/null); then
  fail "policy-check request failed"
fi

if ! ALLOWED=$(echo "$RESPONSE" | jq -er '.allowed' 2>/dev/null); then
  fail "policy-check returned malformed response"
fi

publish_developer_activity() {
  local guard severity secret_target secret_lower secret_kind credential_kind secret_name secret_classifier activity_kind shell_image shell_base target_lower package_manager package_phase cloud_provider cloud_operation
  guard=$(echo "$RESPONSE" | jq -er '.guard // empty' 2>/dev/null || true)
  severity=$(echo "$RESPONSE" | jq -er '.severity // empty' 2>/dev/null || true)
  activity_kind="mcp_tool"
  shell_image=""
  package_manager=""
  package_phase=""
  cloud_provider=""
  cloud_operation=""

  if [ "$ACTION_TYPE" = "shell" ]; then
    activity_kind="shell_command"
    shell_image=$(printf '%s' "$TARGET" | awk '{print $1}')
    if [ -z "${shell_image:-}" ]; then
      shell_image="shell"
    fi
    shell_base=$(basename "$shell_image" 2>/dev/null || printf '%s' "$shell_image")
    shell_base=$(printf '%s' "$shell_base" | sed -E 's/\.(exe|cmd|bat)$//' | tr '[:upper:]' '[:lower:]')
    target_lower=$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')
    case "$shell_base" in
      npm|pnpm|yarn|pip|pip3|cargo|brew|go|gem)
        package_manager="$shell_base"
        if [ "$package_manager" = "pip3" ]; then
          package_manager="pip"
        fi
        case "$target_lower" in
          *" postinstall"*|*" run postinstall"*|*" run-script postinstall"*) package_phase="postinstall" ;;
          *" preinstall"*|*" run preinstall"*|*" run-script preinstall"*) package_phase="preinstall" ;;
          *" prepare"*|*" run prepare"*|*" run-script prepare"*) package_phase="prepare" ;;
          *" build"*|*" run build"*|*" run-script build"*) package_phase="build" ;;
          *" install"*|*" ci"*|*" add"*|*" rebuild"*|*" get"*) package_phase="install" ;;
          *" run"*|*" exec"*|*" dlx"*) package_phase="run" ;;
          *" test"*) package_phase="test" ;;
        esac
        if [ -n "${package_phase:-}" ]; then
          activity_kind="package_script"
        fi
        ;;
      aws|gcloud|az|gh|vercel|netlify|wrangler|doctl|fly|flyctl|op|vault|doppler|heroku|supabase|kubectl|pulumi|circleci|glab|buildkite-agent|bk)
        case "$target_lower" in
          *"secretsmanager get-secret-value"*|*"ssm get-parameter"*|*"ssm get-parameters"*|*"iam create-access-key"*|*"iam put-user-policy"*|*"iam attach-user-policy"*|*"ecr get-login-password"*|*"sts get-session-token"*|*"sts assume-role"*|*"auth print-access-token"*|*"secrets versions access"*|*"iam service-accounts keys create"*|*"keyvault secret show"*|*"keyvault secret download"*|*"account get-access-token"*|*"ad app credential reset"*|*"secret set"*|*"secret put"*|*"secret bulk"*|*"versions secret put"*|*"versions secret bulk"*|*"registry docker-config"*|*"registry login"*|*"kubernetes cluster kubeconfig save"*|*"secrets set"*|*"secrets import"*|*"secrets unset"*|*"secrets list"*|*"tokens create"*|*"tokens revoke"*|*"auth token"*|*"variable set"*|*"variable update"*|*"variable delete"*|*"variable get"*|*"variable list"*|*"variable export"*|*"secret get"*|*"secret create"*|*"secret update"*|*"env pull"*|*"env add"*|*"env rm"*|*"env remove"*|*"env ls"*|*"env:get"*|*"env:list"*|*"env:set"*|*"env:import"*|*"env:unset"*|*"item get"*|*"document get"*|*"op://"*|*"kv get"*|*"read secret/"*|*"token create"*|*"secrets download"*|*"configs tokens create"*|*"config:get"*|*"config:set"*|*"secrets pull"*|*"get secret"*|*"describe secret"*|*"config view --raw"*|*"--show-secrets"*|*"context store-secret"*|*"context remove-secret"*|*"runner token create"*|*"runner token list"*|*" secret"*|*" token"*|*" credential"*|*" access-key"*|*" keyvault"*)
            activity_kind="cloud_cli"
            cloud_provider="$shell_base"
            if [ "$cloud_provider" = "flyctl" ]; then
              cloud_provider="fly"
            fi
            if [ "$cloud_provider" = "buildkite-agent" ] || [ "$cloud_provider" = "bk" ]; then
              cloud_provider="buildkite"
            fi
            cloud_operation=$(printf '%s' "$TARGET" | awk '{for (i=2; i<=NF; i++) { if ($i == "--") { if (i<NF) { print $(i+1); exit } } else if ($i ~ /^--/ && $i !~ /=/) { i++ } else if ($i ~ /^-/) { next } else { print $i; exit } }}')
            if [ -z "${cloud_operation:-}" ]; then
              cloud_operation="$shell_base"
            fi
            ;;
        esac
        ;;
    esac
  fi

  secret_target=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .target // .resource // empty' 2>/dev/null || true)
  if [ -z "${secret_target:-}" ]; then
    if [ "$ACTION_TYPE" = "shell" ]; then
      secret_target=$(printf '%s' "$TARGET" | tr ' ' '\n' | grep -E '(^/|^\./|^\.\./|^~|^\.|/\.|\\)' | head -n 1 || true)
    else
      secret_target="$TARGET"
    fi
  fi
  secret_lower=$(printf '%s' "$secret_target" | tr '[:upper:]' '[:lower:]')
  secret_kind=""
  credential_kind=""
  secret_classifier=""
  case "$secret_lower" in
    *cookie*)
      secret_kind="browser_cookie"
      credential_kind="browser_cookie"
      ;;
    *ci_token*|*github_token*|*gh_token*|*actions*|*gitlab_token*)
      secret_kind="ci_token"
      credential_kind="api_token"
      ;;
    *agent-local-token*|*clawdstrike_agent_auth*)
      secret_kind="local_api_key"
      credential_kind="api_token"
      ;;
    *.aws/credentials*|*gcloud*|*azure*)
      secret_kind="repo_secret"
      credential_kind="cloud_credential"
      ;;
    *.npmrc*|*.pypirc*|*cargo/credentials*)
      secret_kind="repo_secret"
      credential_kind="package_registry_token"
      ;;
    *.ssh/*|*id_rsa*|*id_ed25519*)
      secret_kind="repo_secret"
      credential_kind="ssh_key"
      ;;
    *signing*|*codesign*)
      secret_kind="repo_secret"
      credential_kind="signing_key"
      ;;
    *.env*|*api_key*|*apikey*|*secret*|*token*)
      secret_kind="repo_secret"
      credential_kind="api_token"
      ;;
  esac

  if [ "$ACTION_TYPE" = "shell" ]; then
    case "$shell_base" in
      npm|pnpm|yarn)
        case "$target_lower" in
          *"token list"*|*"token create"*|*"token revoke"*|*"token delete"*)
            secret_kind="repo_secret"
            credential_kind="package_registry_token"
            secret_target="${shell_base}:token"
            secret_name="${shell_base}-token"
            secret_classifier="package_registry_token_command"
            ;;
          *"config get"*|*"config set"*|*"config delete"*)
            case "$target_lower" in
              *"_authtoken"*|*"node_auth_token"*|*"npm_token"*|*"npm_config_"*)
                secret_kind="repo_secret"
                credential_kind="package_registry_token"
                secret_target="${shell_base}:token"
                secret_name="${shell_base}-token"
                secret_classifier="package_registry_token_command"
                ;;
            esac
            ;;
        esac
        ;;
    esac
  fi
  if [ -z "${secret_name:-}" ]; then
    secret_name=$(basename "$secret_target" 2>/dev/null || printf '%s' "$secret_target")
  fi

  if ! DEV_PAYLOAD=$(jq -cn \
    --arg kind "$activity_kind" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg session_id "$RUNTIME_AGENT_EXTERNAL_ID" \
    --arg agent_id "$RUNTIME_AGENT_ID" \
    --arg workload_id "$RUNTIME_AGENT_KIND" \
    --arg shell_image "$shell_image" \
    --arg package_manager "$package_manager" \
    --arg package_phase "$package_phase" \
    --arg cloud_provider "$cloud_provider" \
    --arg cloud_operation "$cloud_operation" \
    --arg secret_kind "$secret_kind" \
    --arg secret_target "$secret_target" \
    --arg secret_name "$secret_name" \
    --arg secret_classifier "$secret_classifier" \
    --arg credential_kind "$credential_kind" \
    --arg guard "$guard" \
    --arg severity "$severity" \
    --argjson allowed "$ALLOWED" \
    --argjson parameters "$TOOL_INPUT" \
    '
    def metadata: {
      collectorKind: "claude_code_hook",
      policyAllowed: $allowed,
      policyGuard: $guard,
      policySeverity: $severity,
      policyActionType: $action_type
    };
    def shell_args: ($target | split(" ") | map(select(length > 0)));
    def tool_activity:
      if $kind == "package_script" then {
        kind: $kind,
        sessionId: $session_id,
        agentId: $agent_id,
        workloadId: $workload_id,
        manager: $package_manager,
        phase: $package_phase,
        script: $target,
        workingDirectory: ($parameters.cwd? // $parameters.workingDirectory? // $parameters.working_directory? // ""),
        image: $shell_image,
        commandLine: $target,
        metadata: metadata + {shellClassifier: "package_script"}
      } elif $kind == "cloud_cli" then {
        kind: $kind,
        sessionId: $session_id,
        agentId: $agent_id,
        workloadId: $workload_id,
        provider: $cloud_provider,
        operation: $cloud_operation,
        args: shell_args,
        image: $shell_image,
        commandLine: $target,
        metadata: metadata + {shellClassifier: "cloud_cli"}
      } else {
        kind: $kind,
        sessionId: $session_id,
        agentId: $agent_id,
        workloadId: $workload_id,
        toolName: $tool_name,
        action: $tool_name,
        target: $target,
        parameters: ($parameters + {target: $target}),
        image: $shell_image,
        args: (if $kind == "shell_command" then [$target] else [] end),
        metadata: metadata
      } end;
    def secret_activity: {
      kind: $secret_kind,
      sessionId: $session_id,
      agentId: $agent_id,
      workloadId: $workload_id,
      path: $secret_target,
      name: $secret_name,
      credentialKind: $credential_kind,
      metadata: metadata + (if $secret_classifier == "" then {} else {shellClassifier: $secret_classifier} end)
    };
    {activities: ([tool_activity] + (if $secret_kind == "" then [] else [secret_activity] end))}
    ' 2>/dev/null); then
    return 0
  fi

  curl -sS --max-time 2 -X POST "${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/edr/developer-activity" \
    -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$DEV_PAYLOAD" >/dev/null 2>&1 || true
}

publish_developer_activity || true

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")

  # Treat daemon infrastructure denies as hook failures to preserve fail-closed behavior.
  if [[ "$GUARD" == hushd_* ]]; then
    fail "policy daemon error (${GUARD})"
  fi

  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Action blocked by security policy"' 2>/dev/null || echo "Action blocked by security policy")

  echo "🚫 BLOCKED by Clawdstrike (${GUARD}): ${MESSAGE}" >&2
  echo "   Target: ${TARGET}" >&2
  exit 1
fi

exit 0
"#;

/// Hook configuration JSON.
const HOOK_CONFIG: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "~/.claude/hooks/clawdstrike-check.sh"
      }
    ]
  }
}
"#;

/// Claude Code integration manager.
pub struct ClaudeCodeIntegration {
    claude_dir: PathBuf,
    hooks_dir: PathBuf,
}

impl ClaudeCodeIntegration {
    /// Create a new integration manager.
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let claude_dir = home.join(".claude");
        let hooks_dir = claude_dir.join("hooks");

        Self {
            claude_dir,
            hooks_dir,
        }
    }

    /// Check if Claude Code is installed (has ~/.claude directory).
    pub fn is_installed(&self) -> bool {
        self.claude_dir.exists()
    }

    /// Install the pre-tool hook.
    pub fn install_hooks(&self) -> Result<()> {
        fs::create_dir_all(&self.hooks_dir)
            .with_context(|| format!("Failed to create hooks directory: {:?}", self.hooks_dir))?;

        let hook_path = self.hooks_dir.join("clawdstrike-check.sh");
        fs::write(&hook_path, HOOK_SCRIPT)
            .with_context(|| format!("Failed to write hook script: {:?}", hook_path))?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_path)
                .with_context(|| "Failed to get hook script metadata")?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .with_context(|| "Failed to set hook script permissions")?;
        }

        tracing::info!(path = ?hook_path, "Installed Claude Code hook");

        self.update_hooks_config()?;
        Ok(())
    }

    /// Update the hooks.json configuration file.
    fn update_hooks_config(&self) -> Result<()> {
        let hooks_json = self.claude_dir.join("hooks.json");

        if hooks_json.exists() {
            let content =
                fs::read_to_string(&hooks_json).with_context(|| "Failed to read hooks.json")?;

            if let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&content) {
                let hooks = config
                    .as_object_mut()
                    .and_then(|obj| obj.get_mut("hooks"))
                    .and_then(|h| h.as_object_mut());

                if let Some(hooks) = hooks {
                    let pre_tool = hooks
                        .entry("PreToolUse")
                        .or_insert_with(|| serde_json::json!([]));

                    if let Some(arr) = pre_tool.as_array_mut() {
                        let already_installed = arr.iter().any(|item| {
                            item.get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("clawdstrike-check.sh"))
                                .unwrap_or(false)
                        });

                        if !already_installed {
                            arr.push(serde_json::json!({
                                "type": "command",
                                "command": "~/.claude/hooks/clawdstrike-check.sh"
                            }));

                            let updated = serde_json::to_string_pretty(&config)
                                .with_context(|| "Failed to serialize hooks.json")?;
                            fs::write(&hooks_json, updated)
                                .with_context(|| "Failed to write hooks.json")?;

                            tracing::info!(path = ?hooks_json, "Updated hooks.json with Clawdstrike hook");
                        }
                    }
                }
            }
        } else {
            fs::write(&hooks_json, HOOK_CONFIG)
                .with_context(|| format!("Failed to create hooks.json: {:?}", hooks_json))?;
            tracing::info!(path = ?hooks_json, "Created hooks.json");
        }

        Ok(())
    }
}

impl Default for ClaudeCodeIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
