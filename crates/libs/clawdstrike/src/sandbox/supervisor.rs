//! Guard-based supervisor backend for nono.
//!
//! Routes nono [`CapabilityRequest`]s through ClawdStrike's [`HushEngine`]
//! for real-time guard-based allow/deny decisions. The supervisor runs on a
//! dedicated OS thread and uses a captured Tokio handle to evaluate async
//! guards from that thread.

use std::sync::Arc;

use nono::supervisor::{ApprovalBackend, ApprovalDecision, CapabilityRequest};
use nono::Result as NonoResult;

use crate::engine::HushEngine;
use crate::guards::{GuardAction, GuardContext};

/// Supervisor backend that routes capability requests through ClawdStrike guards.
///
/// Each [`CapabilityRequest`] from the sandboxed child is translated into the
/// closest matching filesystem guard action and evaluated by the [`HushEngine`].
/// Read requests stay as [`GuardAction::FileAccess`], while write/read+write
/// requests use [`GuardAction::FileWrite`] so allowlist and forbidden-path
/// policies preserve their read-vs-write semantics.
///
/// The `runtime_handle` is captured from the caller's Tokio context before the
/// supervisor thread is spawned, because `std::thread::spawn` threads do NOT
/// inherit the Tokio runtime thread-local.
pub struct GuardSupervisorBackend {
    engine: Arc<HushEngine>,
    context: GuardContext,
    runtime_handle: tokio::runtime::Handle,
}

impl GuardSupervisorBackend {
    pub fn new(
        engine: Arc<HushEngine>,
        context: GuardContext,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            engine,
            context,
            runtime_handle,
        }
    }
}

impl ApprovalBackend for GuardSupervisorBackend {
    fn request_capability(&self, request: &CapabilityRequest) -> NonoResult<ApprovalDecision> {
        let path = request.path.to_string_lossy();
        static EMPTY_WRITE: &[u8] = &[];

        let result = self.runtime_handle.block_on(async {
            let action = match request.access {
                nono::AccessMode::Read => GuardAction::FileAccess(&path),
                nono::AccessMode::Write | nono::AccessMode::ReadWrite => {
                    GuardAction::FileWrite(&path, EMPTY_WRITE)
                }
            };
            self.engine.check_action(&action, &self.context).await
        });

        match result {
            Ok(guard_result) => {
                if guard_result.allowed {
                    Ok(ApprovalDecision::Granted)
                } else {
                    Ok(ApprovalDecision::Denied {
                        reason: guard_result.message,
                    })
                }
            }
            Err(e) => Ok(ApprovalDecision::Denied {
                reason: format!("Guard evaluation error: {e}"),
            }),
        }
    }

    fn backend_name(&self) -> &str {
        "clawdstrike-guard-supervisor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nono::supervisor::{ApprovalDecision, CapabilityRequest};
    use nono::AccessMode;

    use crate::Policy;

    fn request(path: &str, access: AccessMode) -> CapabilityRequest {
        CapabilityRequest {
            request_id: "req-1".to_string(),
            path: path.into(),
            access,
            reason: Some("test".to_string()),
            child_pid: std::process::id(),
            session_id: "session-1".to_string(),
        }
    }

    #[test]
    fn request_capability_grants_read_access_for_allowlisted_path() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: supervisor-read
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/read/**"
"#,
        )
        .expect("policy");
        let engine = Arc::new(HushEngine::builder(policy).build().expect("engine"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let backend =
            GuardSupervisorBackend::new(engine, GuardContext::new(), runtime.handle().clone());

        let decision = backend
            .request_capability(&request("/tmp/repo/read/file.txt", AccessMode::Read))
            .expect("decision");

        assert!(matches!(decision, ApprovalDecision::Granted));
    }

    #[test]
    fn request_capability_uses_write_semantics_for_read_write_requests() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: supervisor-write
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/read/**"
    file_write_allow:
      - "**/repo/write/**"
"#,
        )
        .expect("policy");
        let engine = Arc::new(HushEngine::builder(policy).build().expect("engine"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let backend =
            GuardSupervisorBackend::new(engine, GuardContext::new(), runtime.handle().clone());

        let allowed = backend
            .request_capability(&request("/tmp/repo/write/file.txt", AccessMode::ReadWrite))
            .expect("decision");
        assert!(matches!(allowed, ApprovalDecision::Granted));

        let denied = backend
            .request_capability(&request("/tmp/repo/read/file.txt", AccessMode::Write))
            .expect("decision");
        assert!(matches!(denied, ApprovalDecision::Denied { .. }));
        assert_eq!(backend.backend_name(), "clawdstrike-guard-supervisor");
    }
}
