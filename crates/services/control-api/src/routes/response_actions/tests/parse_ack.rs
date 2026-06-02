//! Ack-submission parsing tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn parse_ack_submission_rejects_untrusted_observed_at() {
    let future_observed_at = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: Some(Utc::now() + Duration::minutes(6)),
        message: None,
        resulting_state: None,
        raw_payload: None,
    }) {
        Ok(_) => panic!("future acknowledgement observed_at was accepted"),
        Err(err) => err,
    };
    assert!(matches!(future_observed_at, ApiError::BadRequest(_)));

    let stale_observed_at = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: Some(Utc::now() - Duration::hours(2)),
        message: None,
        resulting_state: None,
        raw_payload: None,
    }) {
        Ok(_) => panic!("stale acknowledgement observed_at was accepted"),
        Err(err) => err,
    };
    assert!(matches!(stale_observed_at, ApiError::BadRequest(_)));
}

#[test]
fn normalize_ack_status_accepts_rollback_acknowledgement() {
    assert_eq!(normalize_ack_status("rolled_back").unwrap(), "rolled_back");
}

#[test]
fn parse_ack_submission_rejects_oversized_ack_fields() {
    let oversized_target = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "e".repeat(257),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: None,
    }) {
        Ok(_) => panic!("oversized acknowledgement target id was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_target, ApiError::BadRequest(_)));

    let oversized_token = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "t".repeat(1025),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: None,
    }) {
        Ok(_) => panic!("oversized acknowledgement token was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_token, ApiError::BadRequest(_)));

    let oversized_message = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: Some("m".repeat(2049)),
        resulting_state: None,
        raw_payload: None,
    }) {
        Ok(_) => panic!("oversized acknowledgement message was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_message, ApiError::BadRequest(_)));

    let oversized_resulting_state = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: Some("s".repeat(257)),
        raw_payload: None,
    }) {
        Ok(_) => panic!("oversized acknowledgement resulting state was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_resulting_state, ApiError::BadRequest(_)));

    let oversized_raw_payload = match parse_ack_submission(RecordResponseAckRequest {
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token: "ack-token".to_string(),
        status: "acknowledged".to_string(),
        observed_at: None,
        message: None,
        resulting_state: None,
        raw_payload: Some(json!({
            "blob": "r".repeat(65_536)
        })),
    }) {
        Ok(_) => panic!("oversized acknowledgement raw payload was accepted"),
        Err(err) => err,
    };
    assert!(matches!(oversized_raw_payload, ApiError::BadRequest(_)));
}
