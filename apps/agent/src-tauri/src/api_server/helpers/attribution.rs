//! Response-execution record attribution hydration.

use super::super::*;
use axum::http::StatusCode;

pub(crate) async fn response_execution_record_with_attribution(
    state: &AgentApiState,
    execution: clawdstrike_policy_event::edr::EndpointResponseExecutionReport,
) -> Result<EdrResponseExecutionRecord, (StatusCode, String)> {
    let mut records = response_execution_records_with_attribution(state, vec![execution]).await?;
    records
        .pop()
        .ok_or_else(|| internal_error(anyhow::anyhow!("missing response execution record")))
}

pub(crate) async fn response_execution_records_with_attribution(
    state: &AgentApiState,
    executions: Vec<clawdstrike_policy_event::edr::EndpointResponseExecutionReport>,
) -> Result<Vec<EdrResponseExecutionRecord>, (StatusCode, String)> {
    let mut records = executions
        .into_iter()
        .map(EdrResponseExecutionRecord::from_execution)
        .collect::<Vec<_>>();
    hydrate_response_execution_record_attribution(state, &mut records).await?;
    Ok(records)
}

async fn hydrate_response_execution_record_attribution(
    state: &AgentApiState,
    records: &mut [EdrResponseExecutionRecord],
) -> Result<(), (StatusCode, String)> {
    let mut store = state.edr_evidence_bundle_store.lock().await;
    for record in records {
        let bundle_id = record.execution.evidence_bundle.bundle_id.as_str();
        match store.load(bundle_id) {
            Ok(Some(stored)) => {
                crate::edr::dto::hydrate_response_execution_record_attribution(
                    record,
                    &stored.graph,
                );
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    bundle_id,
                    execution_id = %record.execution.execution_id,
                    "failed to load response execution attribution bundle"
                );
            }
        }
    }
    Ok(())
}
