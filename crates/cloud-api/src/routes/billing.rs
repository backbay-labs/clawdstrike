use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ApiError;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Tolerance window for Stripe webhook timestamp verification (5 minutes).
const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

pub fn router() -> Router<AppState> {
    Router::new().route("/webhooks/stripe", post(stripe_webhook))
}

/// Verify a Stripe webhook signature (v1 scheme) using HMAC-SHA256.
///
/// The `Stripe-Signature` header has the format:
///   t=<timestamp>,v1=<signature>[,v1=<signature>...]
fn verify_stripe_signature(payload: &str, sig_header: &str, secret: &str) -> Result<(), ApiError> {
    let mut timestamp: Option<&str> = None;
    let mut signatures: Vec<&str> = Vec::new();

    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = Some(ts);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            signatures.push(sig);
        }
    }

    let ts = timestamp.ok_or(ApiError::InvalidSignature)?;
    if signatures.is_empty() {
        return Err(ApiError::InvalidSignature);
    }

    // Verify timestamp is within tolerance
    let ts_val: i64 = ts.parse().map_err(|_| ApiError::InvalidSignature)?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts_val).abs() > TIMESTAMP_TOLERANCE_SECS {
        return Err(ApiError::InvalidSignature);
    }

    // Compute expected signature: HMAC-SHA256(secret, "{timestamp}.{payload}")
    let signed_payload = format!("{ts}.{payload}");
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ApiError::InvalidSignature)?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Check if any v1 signature matches
    for sig in &signatures {
        if *sig == expected {
            return Ok(());
        }
    }

    Err(ApiError::InvalidSignature)
}

async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let sig = headers
        .get("stripe-signature")
        .ok_or(ApiError::InvalidSignature)?
        .to_str()
        .map_err(|_| ApiError::InvalidSignature)?;

    let payload = String::from_utf8(body.to_vec()).map_err(|_| ApiError::InvalidSignature)?;

    verify_stripe_signature(&payload, sig, &state.config.stripe_webhook_secret)?;

    // Parse the event type from raw JSON
    let event: serde_json::Value =
        serde_json::from_str(&payload).map_err(|_| ApiError::InvalidSignature)?;

    let event_type = event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match event_type {
        "invoice.payment_succeeded" => {
            tracing::info!("Invoice payment succeeded");
        }
        "invoice.payment_failed" => {
            tracing::warn!("Invoice payment failed");
        }
        "customer.subscription.deleted" => {
            if let Some(customer_id) = event
                .pointer("/data/object/customer")
                .and_then(|v| v.as_str())
            {
                tracing::info!(customer_id = %customer_id, "Subscription cancelled, suspending tenant");
                let _ = sqlx::query::query(
                    "UPDATE tenants SET status = 'suspended', updated_at = now() WHERE stripe_customer_id = $1",
                )
                .bind(customer_id)
                .execute(&state.db)
                .await;
            }
        }
        _ => {
            tracing::debug!(event_type = %event_type, "Unhandled Stripe event");
        }
    }

    Ok(StatusCode::OK)
}
