use std::time::Duration;

use sha2::{Digest as _, Sha256};

use crate::state::AppState;

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC-SHA256 as defined in RFC 2104.
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn signature_header(secret: &str, body: &[u8]) -> String {
    let mac = hmac_sha256(secret.as_bytes(), body);
    format!("sha256={}", hex::encode(mac))
}

pub fn emit_webhook_event(state: AppState, event: &'static str, data: serde_json::Value) {
    let Ok(targets) = state.webhook_store.list_enabled_for_event(event) else {
        return;
    };
    if targets.is_empty() {
        return;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload = serde_json::json!({
        "event": event,
        "timestamp": timestamp,
        "data": data,
    });

    let Ok(body) = serde_json::to_vec(&payload) else {
        return;
    };

    for t in targets {
        let client = reqwest::Client::new();
        let url = t.url.clone();
        let sig = signature_header(&t.secret, &body);
        let body = body.clone();
        let webhook_id = t.webhook_id.clone();

        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            for attempt in 0..=3 {
                let req = client
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("x-clawdstrike-event", event)
                    .header("x-clawdstrike-signature", &sig)
                    .body(body.clone());

                match req.send().await {
                    Ok(resp) if resp.status().is_success() => return,
                    Ok(resp) => {
                        tracing::warn!(
                            webhook_id = %webhook_id,
                            status = %resp.status(),
                            attempt,
                            "Webhook delivery failed"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            webhook_id = %webhook_id,
                            error = %err,
                            attempt,
                            "Webhook delivery error"
                        );
                    }
                }

                if attempt == 3 {
                    break;
                }
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
        });
    }
}

