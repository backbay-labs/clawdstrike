//! Failure recording and message sanitization for response actions.
//!
//! Records failed response executions in the ledger with a signed receipt,
//! produces operator-facing error tuples (status + message) that include the
//! failure record reference, and sanitizes provider/error text to redact
//! shell-quoted secrets and secret-like token fragments before they are
//! surfaced through receipts.

use super::*;

pub(crate) async fn record_failed_edr_response_execution(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    failure: &str,
) -> Result<(String, Option<String>), String> {
    let execution = EndpointResponseExecutionReport::failed(plan, graph, failure)
        .map_err(|err| format!("build failed response execution report: {err}"))?;
    let (execution, _stored_bundle, receipt, _bundle_receipt) =
        persist_edr_response_execution(state, execution, graph, actor)
            .await
            .map_err(|(_status, err)| err)?;
    Ok((execution.execution_id, receipt.receipt.receipt_id.clone()))
}

pub(crate) fn response_action_failure_error(
    status: StatusCode,
    message: String,
    failure_record: Result<(String, Option<String>), String>,
) -> (StatusCode, String) {
    match failure_record {
        Ok((execution_id, receipt_id)) => {
            let receipt = receipt_id.unwrap_or_else(|| "unknown".to_string());
            (
                status,
                format!(
                    "{message}; failed response execution recorded as {execution_id} with receipt {receipt}"
                ),
            )
        }
        Err(err) => (
            status,
            format!("{message}; failed to record response failure receipt: {err}"),
        ),
    }
}

pub(crate) fn sanitize_response_execution_failure(message: &str) -> String {
    let redacted = redact_developer_activity_command_line(message.trim());
    truncate_delivery_error(&redact_response_failure_secret_like_fragments(&redacted))
}

pub(crate) fn sanitize_provider_status_reason(reason: &str) -> String {
    sanitize_response_execution_failure(reason)
}

fn redact_response_failure_secret_like_fragments(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut redacted = String::with_capacity(message.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some((start, end)) = response_failure_secret_like_range(message, index) {
            debug_assert_eq!(start, index);
            redacted.push_str("[REDACTED]");
            index = end;
            continue;
        }
        let Some(ch) = message[index..].chars().next() else {
            break;
        };
        redacted.push(ch);
        index += ch.len_utf8();
    }
    redacted
}

fn response_failure_secret_like_range(message: &str, index: usize) -> Option<(usize, usize)> {
    for prefix in [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ] {
        if !message[index..].starts_with(prefix) {
            continue;
        }
        let mut end = index + prefix.len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| response_failure_token_byte(*byte))
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    if message[index..].starts_with("AKIA") {
        let mut end = index + "AKIA".len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    None
}

fn response_failure_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

pub(super) fn sanitize_brokerd_error_body(body: &str) -> String {
    sanitize_response_execution_failure(body)
}
