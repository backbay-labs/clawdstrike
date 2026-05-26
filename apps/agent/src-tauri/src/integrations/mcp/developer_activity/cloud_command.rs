//! Cloud-CLI command classification (aws/gcloud/az/gh/vercel/etc).

use super::shell_tokens::executable_name;

pub(super) struct CloudCommand {
    pub(super) provider: &'static str,
    pub(super) image: String,
    pub(super) args: Vec<String>,
}

pub(super) fn cloud_command(command: &[String]) -> Option<CloudCommand> {
    let image = command.first()?.clone();
    let executable = executable_name(&image);
    let provider = match executable.as_str() {
        "aws" => "aws",
        "gcloud" => "gcloud",
        "az" => "az",
        "gh" => "gh",
        "vercel" => "vercel",
        "netlify" => "netlify",
        "wrangler" => "wrangler",
        "doctl" => "doctl",
        "fly" | "flyctl" => "fly",
        "op" => "op",
        "vault" => "vault",
        "doppler" => "doppler",
        "heroku" => "heroku",
        "supabase" => "supabase",
        "kubectl" => "kubectl",
        "pulumi" => "pulumi",
        "circleci" => "circleci",
        "glab" => "glab",
        "buildkite-agent" | "bk" => "buildkite",
        _ => return None,
    };
    Some(CloudCommand {
        provider,
        image,
        args: command.iter().skip(1).cloned().collect(),
    })
}

pub(super) fn cloud_cli_args_are_sensitive(args: &[String]) -> bool {
    let joined = args.join(" ").to_ascii_lowercase();
    [
        "secretsmanager get-secret-value",
        "ssm get-parameter",
        "ssm get-parameters",
        "iam create-access-key",
        "iam put-user-policy",
        "iam attach-user-policy",
        "ecr get-login-password",
        "sts get-session-token",
        "sts assume-role",
        "auth print-access-token",
        "secrets versions access",
        "iam service-accounts keys create",
        "keyvault secret show",
        "keyvault secret download",
        "account get-access-token",
        "ad app credential reset",
        "secret set",
        "secret put",
        "secret bulk",
        "secret list",
        "secret delete",
        "versions secret put",
        "versions secret bulk",
        "registry docker-config",
        "registry login",
        "kubernetes cluster kubeconfig save",
        "secrets set",
        "secrets import",
        "secrets unset",
        "secrets list",
        "tokens create",
        "tokens revoke",
        "auth token",
        "variable set",
        "variable update",
        "variable delete",
        "variable get",
        "variable list",
        "variable export",
        "secret get",
        "secret create",
        "secret update",
        "env pull",
        "env add",
        "env rm",
        "env remove",
        "env ls",
        "env:get",
        "env:list",
        "env:set",
        "env:import",
        "env:unset",
        "item get",
        "document get",
        "op://",
        "kv get",
        "read secret/",
        "token create",
        "secrets download",
        "configs tokens create",
        "config:get",
        "config:set",
        "secrets pull",
        "get secret",
        "describe secret",
        "config view --raw",
        "--show-secrets",
        "context store-secret",
        "context remove-secret",
        "runner token create",
        "runner token list",
    ]
    .iter()
    .any(|needle| joined.contains(needle))
        || args.iter().any(|arg| {
            let arg = arg.to_ascii_lowercase();
            arg.contains("secret")
                || arg.contains("token")
                || arg.contains("credential")
                || arg.contains("access-key")
                || arg == "iam"
                || arg == "sts"
                || arg == "keyvault"
        })
}
