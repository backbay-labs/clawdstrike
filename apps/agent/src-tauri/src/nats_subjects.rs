//! Canonical NATS subject and stream name helpers.
//!
//! The cloud enrollment response provides a tenant-scoped `subject_prefix`.
//! All adaptive-SDR NATS channels must derive from that prefix to stay aligned
//! with server-side ACLs and provisioning.

/// Build the heartbeat telemetry subject.
pub fn heartbeat_subject(subject_prefix: &str, agent_id: &str) -> String {
    format!("{subject_prefix}.agent.heartbeat.{agent_id}")
}

/// Build the posture command subscription subject.
pub fn posture_command_subject(subject_prefix: &str, agent_id: &str) -> String {
    format!("{subject_prefix}.posture.command.{agent_id}")
}

/// Build the approval request publish subject.
pub fn approval_request_subject(subject_prefix: &str, agent_id: &str) -> String {
    format!("{subject_prefix}.approval.request.{agent_id}")
}

/// Build the approval response subscription subject.
pub fn approval_response_subject(subject_prefix: &str, agent_id: &str) -> String {
    format!("{subject_prefix}.approval.response.{agent_id}")
}

/// Build a KV bucket name for policy sync.
///
/// JetStream KV bucket names map to stream names and allow only
/// `[A-Za-z0-9_-]`, so we normalize all other bytes to `-`.
pub fn policy_sync_bucket(subject_prefix: &str, agent_id: &str) -> String {
    let prefix = sanitize(subject_prefix);
    let agent = sanitize(agent_id);
    format!("{prefix}-policy-sync-{agent}")
}

/// Build the JetStream stream name for telemetry.
pub fn telemetry_stream_name(subject_prefix: &str, agent_id: &str) -> String {
    let prefix = sanitize(subject_prefix);
    let agent = sanitize(agent_id);
    format!("{prefix}-telemetry-{agent}")
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_subjects_use_prefix() {
        let prefix = "tenant-acme.clawdstrike";
        assert_eq!(
            heartbeat_subject(prefix, "agent-1"),
            "tenant-acme.clawdstrike.agent.heartbeat.agent-1"
        );
        assert_eq!(
            posture_command_subject(prefix, "agent-1"),
            "tenant-acme.clawdstrike.posture.command.agent-1"
        );
        assert_eq!(
            approval_request_subject(prefix, "agent-1"),
            "tenant-acme.clawdstrike.approval.request.agent-1"
        );
        assert_eq!(
            approval_response_subject(prefix, "agent-1"),
            "tenant-acme.clawdstrike.approval.response.agent-1"
        );
    }

    #[test]
    fn bucket_and_stream_names_are_sanitized() {
        let prefix = "tenant-acme.clawdstrike";
        assert_eq!(
            policy_sync_bucket(prefix, "agent-1"),
            "tenant-acme-clawdstrike-policy-sync-agent-1"
        );
        assert_eq!(
            telemetry_stream_name(prefix, "agent-1"),
            "tenant-acme-clawdstrike-telemetry-agent-1"
        );
    }
}
