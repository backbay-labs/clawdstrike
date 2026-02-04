//! Shared types for the public `/v1/*` API surface.

use axum::http::HeaderName;
use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V1Meta {
    pub request_id: String,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct V1Links {
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct V1Response<T: Serialize> {
    pub data: T,
    pub meta: V1Meta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<V1Links>,
}

pub fn new_request_id() -> String {
    format!("req_{}", uuid::Uuid::new_v4())
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn v1_ok<T: Serialize>(data: T) -> Json<V1Response<T>> {
    Json(V1Response {
        data,
        meta: V1Meta {
            request_id: new_request_id(),
            timestamp: now_rfc3339(),
            total_count: None,
        },
        links: None,
    })
}

pub fn v1_ok_with_links<T: Serialize>(data: T, links: V1Links) -> Json<V1Response<T>> {
    Json(V1Response {
        data,
        meta: V1Meta {
            request_id: new_request_id(),
            timestamp: now_rfc3339(),
            total_count: None,
        },
        links: Some(links),
    })
}

pub fn v1_ok_with_meta<T: Serialize>(
    data: T,
    meta: V1Meta,
    links: Option<V1Links>,
) -> Json<V1Response<T>> {
    Json(V1Response { data, meta, links })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V1ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct V1ErrorEnvelope {
    pub error: V1ErrorBody,
}

#[derive(Clone, Debug)]
pub struct V1Error {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub retry_after: Option<u64>,
}

impl V1Error {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
            retry_after: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_retry_after(mut self, retry_after: u64) -> Self {
        self.retry_after = Some(retry_after);
        self
    }
}

impl IntoResponse for V1Error {
    fn into_response(self) -> Response {
        let request_id = new_request_id();
        let envelope = V1ErrorEnvelope {
            error: V1ErrorBody {
                code: self.code,
                message: self.message,
                details: self.details,
                request_id: request_id.clone(),
                retry_after: self.retry_after,
            },
        };

        let mut resp = (self.status, Json(envelope)).into_response();
        resp.headers_mut().insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(&request_id)
                .unwrap_or_else(|_| HeaderValue::from_static("req_invalid")),
        );
        resp
    }
}
