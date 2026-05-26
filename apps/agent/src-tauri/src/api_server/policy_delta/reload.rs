use super::*;

pub(crate) async fn request_daemon_policy_reload(
    state: &AgentApiState,
    settings: &Settings,
    requested: bool,
) -> EdrDaemonPolicyReloadResult {
    if !requested {
        return EdrDaemonPolicyReloadResult {
            requested: false,
            reloaded: false,
            status_code: None,
            policy_hash: None,
            message: None,
            error: None,
        };
    }

    let url = format!(
        "{}/api/v1/policy/reload",
        settings.daemon_url().trim_end_matches('/')
    );
    let mut request = state.http_client.post(url);
    if let Some(api_key) = settings
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }

    let response = match tokio::time::timeout(POLICY_VERSION_FETCH_TIMEOUT, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => {
            return EdrDaemonPolicyReloadResult {
                requested: true,
                reloaded: false,
                status_code: None,
                policy_hash: None,
                message: None,
                error: Some(err.to_string()),
            };
        }
        Err(_) => {
            return EdrDaemonPolicyReloadResult {
                requested: true,
                reloaded: false,
                status_code: None,
                policy_hash: None,
                message: None,
                error: Some("daemon policy reload timed out".to_string()),
            };
        }
    };

    let status = response.status();
    let status_code = Some(status.as_u16());
    let body = response.text().await.unwrap_or_default();
    let payload = serde_json::from_str::<Value>(&body).ok();
    let policy_hash = payload
        .as_ref()
        .and_then(|value| value.get("policy_hash"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let message = payload
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let success = status.is_success()
        && payload
            .as_ref()
            .and_then(|value| value.get("success"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
    let error = if success {
        None
    } else {
        message
            .clone()
            .or_else(|| (!body.trim().is_empty()).then(|| body.trim().to_string()))
            .or_else(|| Some(format!("daemon policy reload returned HTTP {status}")))
    };

    EdrDaemonPolicyReloadResult {
        requested: true,
        reloaded: success,
        status_code,
        policy_hash,
        message,
        error,
    }
}
