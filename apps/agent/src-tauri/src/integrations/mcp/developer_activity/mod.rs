//! Developer-activity classification for MCP `policy_check` calls.
//!
//! Projects [`PolicyCheckInput`]/[`PolicyCheckOutput`] pairs into the
//! developer-activity telemetry shapes consumed by the agent EDR ingest
//! endpoint (`/api/v1/agent/edr/developer-activity`).

use crate::policy::{PolicyCheckInput, PolicyCheckOutput};

mod cloud_command;
mod metadata;
mod package_command;
mod secret_targets;
mod shell_tokens;

use cloud_command::{cloud_cli_args_are_sensitive, cloud_command, CloudCommand};
use metadata::{local_mcp_activity_id, mcp_shell_activity_metadata};
use package_command::{
    package_command, package_registry_manager, package_registry_token_command_is_sensitive,
    package_script_phase_and_package, PackageCommand,
};
use secret_targets::{secret_name_from_target, secret_target_from_policy_check};
use shell_tokens::{
    first_non_option_arg_index, normalized_shell_commands, shell_command_image, shell_command_line,
    shell_tokens_for_policy_check, shell_working_directory,
};

/// Project a policy-check input/output pair into developer-activity records.
pub(crate) fn developer_activities_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    result: &PolicyCheckOutput,
) -> Vec<serde_json::Value> {
    let mut activities = Vec::new();
    let action_type = input.action_type.trim().to_ascii_lowercase();
    let agent_id = input
        .runtime_agent_id
        .as_deref()
        .or(input.agent_id.as_deref())
        .or(input.endpoint_agent_id.as_deref())
        .unwrap_or("mcp-local");
    let workload_id = input.runtime_agent_kind.as_deref().unwrap_or("mcp");
    let base_metadata = serde_json::json!({
        "policyAllowed": result.allowed,
        "policyGuard": result.guard,
        "policySeverity": result.severity,
        "policyActionType": input.action_type,
    });

    match action_type.as_str() {
        "mcp_tool" => {
            let mut parameters = input
                .args
                .as_ref()
                .map(|args| serde_json::to_value(args).unwrap_or_else(|_| serde_json::json!({})))
                .unwrap_or_else(|| serde_json::json!({}));
            if let serde_json::Value::Object(object) = &mut parameters {
                object
                    .entry("target".to_string())
                    .or_insert_with(|| serde_json::Value::String(input.target.clone()));
            }
            activities.push(serde_json::json!({
                "kind": "mcp_tool",
                "id": local_mcp_activity_id("mcp-tool", session_id, agent_id, &input.target),
                "sessionId": session_id,
                "agentId": agent_id,
                "workloadId": workload_id,
                "toolName": input.target,
                "parameters": parameters,
                "metadata": base_metadata,
            }));
        }
        "shell" => {
            activities.push(shell_developer_activity_for_policy_check(
                input,
                session_id,
                agent_id,
                workload_id,
                &base_metadata,
            ));
        }
        _ => {}
    }

    if let Some(secret_activity) =
        secret_developer_activity_for_policy_check(input, session_id, agent_id, workload_id)
    {
        activities.push(secret_activity);
    }

    activities
}

fn shell_developer_activity_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    agent_id: &str,
    workload_id: &str,
    base_metadata: &serde_json::Value,
) -> serde_json::Value {
    let command_line = shell_command_line(input);
    let tokens = shell_tokens_for_policy_check(input, &command_line);
    let working_directory = shell_working_directory(input);
    let context = McpShellActivityContext {
        input,
        session_id,
        agent_id,
        workload_id,
        base_metadata,
        command_line: &command_line,
        working_directory: working_directory.as_deref(),
    };

    for command in normalized_shell_commands(&tokens) {
        if let Some(activity) = package_script_activity_for_shell(&context, &command) {
            return activity;
        }
        if let Some(activity) = package_registry_token_activity_for_shell(&context, &command) {
            return activity;
        }
        if let Some(activity) = cloud_cli_activity_for_shell(&context, &command) {
            return activity;
        }
    }

    serde_json::json!({
        "kind": "shell_command",
        "id": local_mcp_activity_id("mcp-shell", session_id, agent_id, &command_line),
        "sessionId": session_id,
        "agentId": agent_id,
        "workloadId": workload_id,
        "image": shell_command_image(&command_line),
        "args": [command_line],
        "metadata": base_metadata,
    })
}

struct McpShellActivityContext<'a> {
    input: &'a PolicyCheckInput,
    session_id: Option<&'a str>,
    agent_id: &'a str,
    workload_id: &'a str,
    base_metadata: &'a serde_json::Value,
    command_line: &'a str,
    working_directory: Option<&'a str>,
}

fn package_script_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let PackageCommand {
        manager,
        image,
        args,
    } = package_command(command)?;
    let (phase, package) = package_script_phase_and_package(manager, &args)?;
    Some(serde_json::json!({
        "kind": "package_script",
        "id": local_mcp_activity_id("mcp-package-script", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "manager": manager,
        "package": package,
        "phase": phase,
        "script": context.command_line,
        "workingDirectory": context.working_directory,
        "image": image,
        "commandLine": context.command_line,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "package_script"),
    }))
}

fn package_registry_token_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let manager = package_registry_manager(command)?;
    let args = command.iter().skip(1).cloned().collect::<Vec<_>>();
    let command_index = first_non_option_arg_index(&args)?;
    let command_name = args.get(command_index)?.to_ascii_lowercase();
    let command_args = args
        .iter()
        .skip(command_index + 1)
        .cloned()
        .collect::<Vec<_>>();
    if !package_registry_token_command_is_sensitive(&command_name, &command_args) {
        return None;
    }

    Some(serde_json::json!({
        "kind": "repo_secret",
        "id": local_mcp_activity_id("mcp-package-registry-token", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "path": format!("{manager}:token"),
        "name": format!("{manager}-token"),
        "credentialKind": "package_registry_token",
        "image": command.first().cloned(),
        "commandLine": context.command_line,
        "args": args,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "package_registry_token_command"),
    }))
}

fn cloud_cli_activity_for_shell(
    context: &McpShellActivityContext<'_>,
    command: &[String],
) -> Option<serde_json::Value> {
    let CloudCommand {
        provider,
        image,
        args,
    } = cloud_command(command)?;
    let operation_index = first_non_option_arg_index(&args)?;
    let operation = args.get(operation_index)?.clone();
    let operation_args = args
        .iter()
        .skip(operation_index + 1)
        .cloned()
        .collect::<Vec<_>>();
    let mut sensitive_args = Vec::with_capacity(operation_args.len() + 1);
    sensitive_args.push(operation.clone());
    sensitive_args.extend(operation_args.iter().cloned());
    if !cloud_cli_args_are_sensitive(&sensitive_args) {
        return None;
    }

    Some(serde_json::json!({
        "kind": "cloud_cli",
        "id": local_mcp_activity_id("mcp-cloud-cli", context.session_id, context.agent_id, context.command_line),
        "sessionId": context.session_id,
        "agentId": context.agent_id,
        "workloadId": context.workload_id,
        "provider": provider,
        "operation": operation,
        "args": operation_args,
        "image": image,
        "commandLine": context.command_line,
        "metadata": mcp_shell_activity_metadata(context.base_metadata, context.input, "cloud_cli"),
    }))
}

fn secret_developer_activity_for_policy_check(
    input: &PolicyCheckInput,
    session_id: Option<&str>,
    agent_id: &str,
    workload_id: &str,
) -> Option<serde_json::Value> {
    let target = secret_target_from_policy_check(input)?;
    let lower = target.to_ascii_lowercase();
    let (kind, credential_kind) = if lower.contains("cookie") {
        ("browser_cookie", "browser_cookie")
    } else if lower.contains("ci_token")
        || lower.contains("github_token")
        || lower.contains("gh_token")
        || lower.contains("actions")
    {
        ("ci_token", "api_token")
    } else if lower.contains("agent-local-token") || lower.contains("clawdstrike_agent_auth") {
        ("local_api_key", "api_token")
    } else if lower.contains(".aws/credentials")
        || lower.contains("gcloud")
        || lower.contains("azure")
    {
        ("repo_secret", "cloud_credential")
    } else if lower.contains(".npmrc")
        || lower.contains(".pypirc")
        || lower.contains("cargo/credentials")
    {
        ("repo_secret", "package_registry_token")
    } else if lower.contains(".ssh/") || lower.contains("id_rsa") || lower.contains("id_ed25519") {
        ("repo_secret", "ssh_key")
    } else if lower.contains("signing") || lower.contains("codesign") {
        ("repo_secret", "signing_key")
    } else {
        ("repo_secret", "api_token")
    };
    Some(serde_json::json!({
        "kind": kind,
        "id": local_mcp_activity_id("mcp-secret", session_id, agent_id, &target),
        "sessionId": session_id,
        "agentId": agent_id,
        "workloadId": workload_id,
        "path": target,
        "name": secret_name_from_target(&target),
        "credentialKind": credential_kind,
        "metadata": {
            "collectorKind": "mcp_policy_check",
            "policyActionType": input.action_type,
        },
    }))
}
