use std::sync::Arc;

use reqwest::redirect::Policy;

use crate::config::{Config, SecretBackendConfig};
use crate::operator::OperatorState;
use crate::secret_provider::{
    EnvSecretProvider, FileSecretProvider, HttpSecretProvider, SecretProvider,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub secret_provider: Arc<dyn SecretProvider>,
    pub operator_state: OperatorState,
    pub hushd_client: reqwest::Client,
    pub upstream_client: reqwest::Client,
}

impl AppState {
    pub fn from_config(config: Config) -> anyhow::Result<Self> {
        let secret_provider: Arc<dyn SecretProvider> = match &config.secret_backend {
            SecretBackendConfig::File { path } => {
                Arc::new(FileSecretProvider::from_json_file(path)?)
            }
            SecretBackendConfig::Env { prefix } => Arc::new(EnvSecretProvider::new(prefix.clone())),
            SecretBackendConfig::Http {
                base_url,
                bearer_token,
                path_prefix,
            } => Arc::new(HttpSecretProvider::new(
                base_url.clone(),
                bearer_token.clone(),
                path_prefix.clone(),
                config.request_timeout_secs,
            )?),
        };
        let hushd_client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(config.request_timeout_secs))
            .build()?;
        let upstream_client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(config.request_timeout_secs))
            .danger_accept_invalid_certs(config.allow_invalid_upstream_tls)
            .build()?;

        Ok(Self {
            config: Arc::new(config),
            secret_provider,
            operator_state: OperatorState::default(),
            hushd_client,
            upstream_client,
        })
    }

    pub fn with_secret_provider(mut self, provider: Arc<dyn SecretProvider>) -> Self {
        self.secret_provider = provider;
        self
    }
}
