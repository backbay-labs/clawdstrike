//! Supply-chain CLI classification: package-manager and cloud CLI detection.
//!
//! Pure string/argument heuristics that name the package registry or cloud
//! provider a command targets and flag credential-touching invocations.

#![allow(dead_code)]

use std::collections::BTreeMap;

pub(crate) fn command_looks_like_package_manager(image: &str, args: &[String]) -> bool {
    let image = image.to_ascii_lowercase();
    let args = args.join(" ").to_ascii_lowercase();
    [
        "npm", "pnpm", "yarn", "pip", "pip3", "cargo", "brew", "go", "gem", "bundle",
    ]
    .iter()
    .any(|name| image.ends_with(name) || image.contains(&format!("/{name}")))
        || args.contains(" npm ")
        || args.contains(" pip ")
        || args.contains(" cargo ")
}

pub(crate) fn package_registry_cli_name<'a>(
    image: &'a str,
    args: &'a [String],
) -> Option<&'static str> {
    let image = image.to_ascii_lowercase();
    let first_arg = args
        .first()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    [("npm", "npm"), ("pnpm", "pnpm"), ("yarn", "yarn")]
        .into_iter()
        .find_map(|(binary, manager)| {
            let image_matches = image == binary
                || image.ends_with(&format!("/{binary}"))
                || image.contains(&format!("/{binary}-"));
            let arg_matches = first_arg == binary || first_arg.ends_with(&format!("/{binary}"));
            (image_matches || arg_matches).then_some(manager)
        })
}

pub(crate) fn suspicious_package_registry_cli_reason(args: &[String]) -> Option<&'static str> {
    let args = args.join(" ").to_ascii_lowercase();
    [
        ("token list", "lists npm authentication tokens"),
        ("token create", "creates an npm authentication token"),
        ("token revoke", "revokes an npm authentication token"),
        ("token delete", "deletes an npm authentication token"),
        (
            "config get",
            "reads package manager registry authentication configuration",
        ),
        (
            "config set",
            "writes package manager registry authentication configuration",
        ),
        (
            "config delete",
            "deletes package manager registry authentication configuration",
        ),
    ]
    .into_iter()
    .find_map(|(needle, reason)| {
        if args.contains(needle)
            && (needle.starts_with("token ") || package_registry_auth_config_reference(&args))
        {
            Some(reason)
        } else {
            None
        }
    })
}

fn package_registry_auth_config_reference(args: &str) -> bool {
    args.contains("_authtoken")
        || args.contains("node_auth_token")
        || args.contains("npm_token")
        || args.contains("npm_config_")
}

pub(crate) fn package_registry_credential_env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .filter(|key| {
            matches!(
                key.to_ascii_uppercase().as_str(),
                "NODE_AUTH_TOKEN"
                    | "NPM_TOKEN"
                    | "NPM_CONFIG_TOKEN"
                    | "NPM_CONFIG__AUTH"
                    | "NPM_CONFIG__AUTHTOKEN"
                    | "YARN_NPM_AUTH_TOKEN"
            )
        })
        .cloned()
        .collect()
}

pub(crate) fn cloud_cli_name<'a>(image: &'a str, args: &'a [String]) -> Option<&'static str> {
    let image = image.to_ascii_lowercase();
    let first_arg = args
        .first()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    [
        ("aws", "aws"),
        ("gcloud", "gcloud"),
        ("az", "az"),
        ("doctl", "doctl"),
        ("fly", "fly"),
        ("flyctl", "fly"),
        ("gh", "gh"),
        ("vercel", "vercel"),
        ("netlify", "netlify"),
        ("wrangler", "wrangler"),
        ("op", "op"),
        ("vault", "vault"),
        ("doppler", "doppler"),
        ("heroku", "heroku"),
        ("supabase", "supabase"),
        ("firebase", "firebase"),
        ("railway", "railway"),
        ("stripe", "stripe"),
        ("sentry-cli", "sentry"),
        ("snyk", "snyk"),
        ("bw", "bitwarden"),
        ("kubectl", "kubectl"),
        ("pulumi", "pulumi"),
        ("circleci", "circleci"),
        ("glab", "glab"),
        ("buildkite-agent", "buildkite"),
        ("bk", "buildkite"),
        ("drone", "drone"),
        ("sem", "semaphore"),
        ("semaphore", "semaphore"),
        ("appveyor", "appveyor"),
        ("woodpecker", "woodpecker"),
        ("codefresh", "codefresh"),
        ("terraform", "terraform"),
        ("terragrunt", "terragrunt"),
        ("tofu", "opentofu"),
    ]
    .into_iter()
    .find_map(|(binary, cli_name)| {
        let image_matches = image == binary
            || image.ends_with(&format!("/{binary}"))
            || image.contains(&format!("/{binary}-"));
        let arg_matches = first_arg == binary || first_arg.ends_with(&format!("/{binary}"));
        (image_matches || arg_matches).then_some(cli_name)
    })
}

pub(crate) fn suspicious_cloud_cli_reason(args: &[String]) -> Option<&'static str> {
    let args = args.join(" ").to_ascii_lowercase();
    [
        (
            "secretsmanager get-secret-value",
            "reads an AWS Secrets Manager secret value",
        ),
        ("ssm get-parameter", "reads an AWS SSM parameter value"),
        ("ssm get-parameters", "reads AWS SSM parameter values"),
        ("iam create-access-key", "creates a new AWS IAM access key"),
        (
            "iam put-user-policy",
            "modifies an AWS IAM inline user policy",
        ),
        (
            "iam attach-user-policy",
            "attaches an AWS IAM policy to a user",
        ),
        (
            "ecr get-login-password",
            "exports an AWS ECR registry login password",
        ),
        (
            "auth print-access-token",
            "prints a cloud OAuth access token",
        ),
        (
            "secrets versions access",
            "reads a GCP Secret Manager secret version",
        ),
        (
            "iam service-accounts keys create",
            "creates a GCP service account key",
        ),
        ("keyvault secret show", "reads an Azure Key Vault secret"),
        (
            "keyvault secret download",
            "downloads an Azure Key Vault secret",
        ),
        (
            "account get-access-token",
            "prints an Azure account access token",
        ),
        (
            "ad app credential reset",
            "resets Azure application credentials",
        ),
        (
            "secret set",
            "writes a GitHub repository or organization secret",
        ),
        (
            "versions secret put",
            "writes a Cloudflare Worker version secret",
        ),
        (
            "versions secret bulk",
            "bulk imports Cloudflare Worker version secrets",
        ),
        ("secret put", "writes a Cloudflare Worker or Pages secret"),
        ("secret bulk", "bulk imports Cloudflare Worker secrets"),
        (
            "registry docker-config",
            "prints DigitalOcean registry Docker credentials",
        ),
        (
            "registry login",
            "writes DigitalOcean registry credentials locally",
        ),
        (
            "kubernetes cluster kubeconfig save",
            "writes DigitalOcean Kubernetes access credentials locally",
        ),
        ("secrets set", "writes a Fly.io app secret"),
        ("secrets import", "imports Fly.io app secrets"),
        ("secrets unset", "removes a Fly.io app secret"),
        ("secrets list", "lists Fly.io app secrets"),
        ("tokens create", "creates a Fly.io API token"),
        ("tokens revoke", "revokes a Fly.io API token"),
        ("secret get", "reads a cloud or CI platform secret"),
        ("secret list", "lists cloud CLI secrets"),
        ("secret create", "creates a cloud or CI platform secret"),
        ("secret update", "updates a cloud or CI platform secret"),
        ("secret delete", "deletes a cloud CLI secret"),
        ("auth token", "prints a GitHub CLI authentication token"),
        (
            "variable set",
            "writes a CI/CD or developer-platform variable",
        ),
        (
            "variable update",
            "updates a CI/CD or developer-platform variable",
        ),
        (
            "variable delete",
            "deletes a CI/CD or developer-platform variable",
        ),
        (
            "variable get",
            "reads a CI/CD or developer-platform variable",
        ),
        (
            "variable list",
            "lists CI/CD or developer-platform variables",
        ),
        (
            "variable export",
            "exports CI/CD or developer-platform variables",
        ),
        ("env pull", "pulls Vercel environment variables locally"),
        ("env add", "writes a Vercel project environment variable"),
        ("env rm", "removes a Vercel project environment variable"),
        (
            "env remove",
            "removes a Vercel project environment variable",
        ),
        ("env ls", "lists Vercel project environment variables"),
        ("env:get", "retrieves a Netlify environment variable"),
        ("env:list", "lists Netlify environment variables"),
        ("env:set", "writes a Netlify environment variable"),
        ("env:import", "imports Netlify environment variables"),
        ("env:unset", "deletes a Netlify environment variable"),
        ("item get", "reads a 1Password item"),
        ("get item", "reads a password-manager item"),
        ("document get", "reads a 1Password document"),
        ("op://", "reads a 1Password secret reference"),
        ("kv get", "reads a Vault KV secret"),
        ("read secret/", "reads a Vault secret path"),
        ("token create", "creates an access token"),
        ("secrets download", "downloads application secrets"),
        ("configs tokens create", "creates a Doppler config token"),
        ("config:get", "reads a platform environment variable"),
        ("config:set", "writes a platform environment variable"),
        ("secrets pull", "downloads project secrets"),
        (
            "functions:secrets:access",
            "reads a Firebase Functions secret",
        ),
        (
            "functions:secrets:set",
            "writes a Firebase Functions secret",
        ),
        ("variables", "reads or writes Railway service variables"),
        (
            "login --auth-token",
            "logs into a developer platform with an auth token",
        ),
        (
            "auth --auth-token",
            "authenticates a developer security tool with an auth token",
        ),
        ("get secret", "reads a Kubernetes Secret object"),
        ("describe secret", "describes a Kubernetes Secret object"),
        (
            "config view --raw",
            "prints raw Kubernetes credential configuration",
        ),
        (
            "--show-secrets",
            "prints secret values from developer platform configuration",
        ),
        ("context store-secret", "writes a CircleCI context secret"),
        ("context remove-secret", "removes a CircleCI context secret"),
        ("runner token create", "creates a CircleCI runner token"),
        ("runner token list", "lists CircleCI runner tokens"),
        ("secret add", "writes a CI platform secret"),
        ("secret rm", "removes a CI platform secret"),
        ("secret remove", "removes a CI platform secret"),
        ("auth create-token", "creates a CI platform API token"),
        ("encrypt --secret", "encrypts CI platform secret material"),
        (
            "context create",
            "creates CI platform context or credential material",
        ),
        (
            "login --api-key",
            "authenticates Stripe CLI with an inline API key",
        ),
        (
            "listen --print-secret",
            "prints a Stripe webhook signing secret",
        ),
        ("output -json", "prints Terraform output values"),
        ("output -raw", "prints a Terraform output value"),
        ("state pull", "exports Terraform state"),
        ("state show", "prints Terraform state for a resource"),
        ("show -json", "prints Terraform plan or state values"),
    ]
    .into_iter()
    .find_map(|(needle, reason)| args.contains(needle).then_some(reason))
}

pub(crate) fn cloud_credential_env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .filter(|key| {
            let upper = key.to_ascii_uppercase();
            upper.starts_with("TF_TOKEN_")
                || upper.starts_with("TERRAFORM_TOKEN")
                || matches!(
                    upper.as_str(),
                    "AWS_ACCESS_KEY_ID"
                        | "AWS_SECRET_ACCESS_KEY"
                        | "AWS_SESSION_TOKEN"
                        | "AWS_PROFILE"
                        | "GOOGLE_APPLICATION_CREDENTIALS"
                        | "CLOUDSDK_AUTH_ACCESS_TOKEN"
                        | "AZURE_CLIENT_ID"
                        | "AZURE_CLIENT_SECRET"
                        | "AZURE_TENANT_ID"
                        | "ARM_CLIENT_ID"
                        | "ARM_CLIENT_SECRET"
                        | "ARM_TENANT_ID"
                        | "GITHUB_TOKEN"
                        | "GH_TOKEN"
                        | "VERCEL_TOKEN"
                        | "NETLIFY_AUTH_TOKEN"
                        | "CLOUDFLARE_API_TOKEN"
                        | "CLOUDFLARE_API_KEY"
                        | "CLOUDFLARE_ACCESS_CLIENT_ID"
                        | "CLOUDFLARE_ACCESS_CLIENT_SECRET"
                        | "WRANGLER_R2_SQL_AUTH_TOKEN"
                        | "CF_API_TOKEN"
                        | "CF_API_KEY"
                        | "DIGITALOCEAN_ACCESS_TOKEN"
                        | "DO_API_TOKEN"
                        | "FLY_API_TOKEN"
                        | "FLY_ACCESS_TOKEN"
                        | "OP_SERVICE_ACCOUNT_TOKEN"
                        | "OP_CONNECT_TOKEN"
                        | "VAULT_TOKEN"
                        | "DOPPLER_TOKEN"
                        | "DOPPLER_SERVICE_TOKEN"
                        | "HEROKU_API_KEY"
                        | "SUPABASE_ACCESS_TOKEN"
                        | "SUPABASE_SERVICE_ROLE_KEY"
                        | "FIREBASE_TOKEN"
                        | "RAILWAY_TOKEN"
                        | "STRIPE_API_KEY"
                        | "STRIPE_WEBHOOK_SECRET"
                        | "SENTRY_AUTH_TOKEN"
                        | "SNYK_TOKEN"
                        | "BW_SESSION"
                        | "KUBECONFIG"
                        | "PULUMI_ACCESS_TOKEN"
                        | "PULUMI_CONFIG_PASSPHRASE"
                        | "CIRCLECI_CLI_TOKEN"
                        | "CIRCLE_TOKEN"
                        | "GITLAB_TOKEN"
                        | "GITLAB_ACCESS_TOKEN"
                        | "CI_JOB_TOKEN"
                        | "BUILDKITE_AGENT_ACCESS_TOKEN"
                        | "BUILDKITE_API_TOKEN"
                        | "DRONE_TOKEN"
                        | "DRONE_NETRC_PASSWORD"
                        | "SEMAPHORE_API_TOKEN"
                        | "SEMAPHORE_OIDC_TOKEN"
                        | "APPVEYOR_API_TOKEN"
                        | "APPVEYOR_TOKEN"
                        | "WOODPECKER_TOKEN"
                        | "CODEFRESH_API_KEY"
                        | "TFE_TOKEN"
                )
        })
        .cloned()
        .collect()
}
