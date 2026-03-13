pub mod generic_https;
pub mod github;
pub mod openai;
pub mod slack;

use std::collections::BTreeMap;

use clawdstrike_broker_protocol::{BrokerCapability, BrokerProvider, BrokerRequest};
use reqwest::header::CONTENT_TYPE;

use crate::api::ApiError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct ProviderExecutionResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub response_body_sha256: Option<String>,
    pub bytes_received: usize,
    pub provider_metadata: BTreeMap<String, String>,
}

pub struct ProviderStreamResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub content_type: Option<String>,
    pub response: reqwest::Response,
    pub provider_metadata: BTreeMap<String, String>,
}

pub async fn execute_provider(
    state: &AppState,
    capability: &BrokerCapability,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderExecutionResponse, ApiError> {
    match capability.secret_ref.provider {
        BrokerProvider::Openai => openai::execute_openai(state, request, secret).await,
        BrokerProvider::Github => github::execute_github(state, request, secret).await,
        BrokerProvider::Slack => slack::execute_slack(state, request, secret).await,
        BrokerProvider::GenericHttps => {
            generic_https::execute_generic_https(state, request, secret).await
        }
    }
}

pub async fn execute_provider_stream(
    state: &AppState,
    capability: &BrokerCapability,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderStreamResponse, ApiError> {
    match capability.secret_ref.provider {
        BrokerProvider::Openai => openai::execute_openai_stream(state, request, secret).await,
        BrokerProvider::Github => github::execute_github_stream(state, request, secret).await,
        BrokerProvider::Slack => slack::execute_slack_stream(state, request, secret).await,
        BrokerProvider::GenericHttps => {
            generic_https::execute_generic_https_stream(state, request, secret).await
        }
    }
}

pub(crate) fn extract_response_headers(
    response: &reqwest::Response,
) -> (BTreeMap<String, String>, Option<String>) {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let mut headers = BTreeMap::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.insert(name.to_string(), value.to_string());
        }
    }
    (headers, content_type)
}

pub(crate) fn map_method(method: &clawdstrike_broker_protocol::HttpMethod) -> reqwest::Method {
    match method {
        clawdstrike_broker_protocol::HttpMethod::GET => reqwest::Method::GET,
        clawdstrike_broker_protocol::HttpMethod::POST => reqwest::Method::POST,
        clawdstrike_broker_protocol::HttpMethod::PUT => reqwest::Method::PUT,
        clawdstrike_broker_protocol::HttpMethod::PATCH => reqwest::Method::PATCH,
        clawdstrike_broker_protocol::HttpMethod::DELETE => reqwest::Method::DELETE,
    }
}
