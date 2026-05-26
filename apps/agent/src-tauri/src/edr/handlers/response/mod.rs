//! Response action and execution handlers.

mod acknowledge;
mod action;
mod cancel;
mod executions;
mod expire;
mod rollback;

#[allow(unused_imports)]
pub(crate) use acknowledge::{
    agent_edr_response_acknowledgements, agent_edr_response_execution_acknowledge,
};
#[allow(unused_imports)]
pub(crate) use action::agent_edr_response_action;
#[allow(unused_imports)]
pub(crate) use cancel::agent_edr_response_execution_cancel;
#[allow(unused_imports)]
pub(crate) use executions::{
    agent_edr_response_execution, agent_edr_response_execution_proof, agent_edr_response_executions,
};
#[allow(unused_imports)]
pub(crate) use expire::{agent_edr_response_execution_expire, expire_edr_response_executions};
#[allow(unused_imports)]
pub(crate) use rollback::agent_edr_response_execution_rollback;

#[cfg(test)]
mod response_proof_ttl_tests {
    use super::executions::ensure_response_execution_proof_ttl_state;
    use axum::http::StatusCode;

    fn utc(seconds: u64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
        )
    }

    #[test]
    fn response_execution_proof_rejects_expired_execution_without_terminal_transition() {
        let err = match ensure_response_execution_proof_ttl_state(
            "exec-expired",
            utc(100),
            false,
            utc(101),
        ) {
            Ok(()) => panic!("expired unswept execution proof unexpectedly succeeded"),
            Err(err) => err,
        };

        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(err
            .1
            .contains("TTL expired without terminal expiry or rollback receipt"));
    }

    #[test]
    fn response_execution_proof_allows_unexpired_or_terminal_executions() {
        ensure_response_execution_proof_ttl_state("exec-active", utc(100), false, utc(100))
            .unwrap_or_else(|err| panic!("unexpired proof should be accepted: {err:?}"));
        ensure_response_execution_proof_ttl_state("exec-terminal", utc(100), true, utc(101))
            .unwrap_or_else(|err| panic!("terminal proof should be accepted: {err:?}"));
    }
}
