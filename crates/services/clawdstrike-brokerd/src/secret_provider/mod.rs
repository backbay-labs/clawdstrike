use std::collections::BTreeMap;
use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn resolve(&self, secret_ref: &str) -> Option<String>;
}

#[derive(Clone, Debug, Default)]
pub struct FileSecretProvider {
    secrets: BTreeMap<String, String>,
}

impl FileSecretProvider {
    pub fn new(secrets: BTreeMap<String, String>) -> Self {
        Self { secrets }
    }

    pub fn from_json_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let secrets = serde_json::from_str::<BTreeMap<String, String>>(&raw)?;
        Ok(Self { secrets })
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    async fn resolve(&self, secret_ref: &str) -> Option<String> {
        self.secrets.get(secret_ref).cloned()
    }
}

#[derive(Clone, Debug)]
pub struct EnvSecretProvider {
    prefix: String,
}

impl EnvSecretProvider {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub fn env_var_name(&self, secret_ref: &str) -> String {
        format!("{}{}", self.prefix, normalize_secret_ref(secret_ref))
    }
}

#[async_trait]
impl SecretProvider for EnvSecretProvider {
    async fn resolve(&self, secret_ref: &str) -> Option<String> {
        std::env::var(self.env_var_name(secret_ref))
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Clone, Debug)]
pub struct HttpSecretProvider {
    base_url: String,
    bearer_token: Option<String>,
    path_prefix: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct SecretValueResponse {
    value: String,
}

impl HttpSecretProvider {
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: Option<String>,
        path_prefix: impl Into<String>,
        timeout_secs: u64,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()?;

        Ok(Self {
            base_url: base_url.into(),
            bearer_token,
            path_prefix: path_prefix.into(),
            client,
        })
    }

    fn build_secret_url(&self, secret_ref: &str) -> anyhow::Result<Url> {
        let mut url = Url::parse(self.base_url.trim_end_matches('/'))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("secret base url cannot be a cannot-be-a-base url"))?;
            segments.pop_if_empty();
            for segment in self
                .path_prefix
                .trim_matches('/')
                .split('/')
                .filter(|segment| !segment.is_empty())
            {
                segments.push(segment);
            }
            segments.push(secret_ref);
        }
        Ok(url)
    }
}

#[async_trait]
impl SecretProvider for HttpSecretProvider {
    async fn resolve(&self, secret_ref: &str) -> Option<String> {
        let url = match self.build_secret_url(secret_ref) {
            Ok(url) => url,
            Err(error) => {
                tracing::warn!(error = %error, secret_ref, "failed to build managed secret url");
                return None;
            }
        };

        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(error = %error, secret_ref, "managed secret lookup failed");
                return None;
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                secret_ref,
                "managed secret backend returned non-success status"
            );
            return None;
        }

        match response.json::<SecretValueResponse>().await {
            Ok(payload) if !payload.value.trim().is_empty() => Some(payload.value),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(error = %error, secret_ref, "managed secret lookup payload invalid");
                None
            }
        }
    }
}

fn normalize_secret_ref(secret_ref: &str) -> String {
    secret_ref
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{EnvSecretProvider, HttpSecretProvider};

    #[test]
    fn env_secret_provider_normalizes_secret_refs() {
        let provider = EnvSecretProvider::new("CLAWDSTRIKE_SECRET_");
        assert_eq!(
            provider.env_var_name("openai/prod.primary"),
            "CLAWDSTRIKE_SECRET_OPENAI_PROD_PRIMARY"
        );
    }

    #[test]
    fn http_secret_provider_builds_expected_paths() {
        let provider = HttpSecretProvider::new(
            "https://secrets.example.internal",
            Some("token".to_string()),
            "/v1/managed/secrets",
            5,
        )
        .expect("provider");
        assert_eq!(
            provider
                .build_secret_url("openai/prod.primary")
                .expect("url")
                .as_str(),
            "https://secrets.example.internal/v1/managed/secrets/openai%2Fprod.primary"
        );
    }
}
