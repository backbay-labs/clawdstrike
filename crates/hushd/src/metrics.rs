//! Minimal Prometheus-style metrics (no external deps).

use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide daemon metrics.
#[derive(Default)]
pub struct Metrics {
    checks_total: AtomicU64,
    checks_allowed_total: AtomicU64,
    checks_blocked_total: AtomicU64,
    audit_events_total: AtomicU64,
}

impl Metrics {
    pub fn inc_check(&self, allowed: bool) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        if allowed {
            self.checks_allowed_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.checks_blocked_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn inc_audit_event(&self) {
        self.audit_events_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, uptime_secs: i64, audit_forward_dropped: Option<u64>) -> String {
        let checks_total = self.checks_total.load(Ordering::Relaxed);
        let checks_allowed_total = self.checks_allowed_total.load(Ordering::Relaxed);
        let checks_blocked_total = self.checks_blocked_total.load(Ordering::Relaxed);
        let audit_events_total = self.audit_events_total.load(Ordering::Relaxed);

        let mut out = String::new();

        out.push_str("# HELP hushd_uptime_seconds Daemon uptime in seconds.\n");
        out.push_str("# TYPE hushd_uptime_seconds gauge\n");
        out.push_str(&format!("hushd_uptime_seconds {}\n", uptime_secs.max(0)));

        out.push_str("# HELP hushd_check_requests_total Total /api/v1/check requests processed.\n");
        out.push_str("# TYPE hushd_check_requests_total counter\n");
        out.push_str(&format!("hushd_check_requests_total {}\n", checks_total));

        out.push_str(
            "# HELP hushd_check_allowed_total Total allowed decisions from /api/v1/check.\n",
        );
        out.push_str("# TYPE hushd_check_allowed_total counter\n");
        out.push_str(&format!(
            "hushd_check_allowed_total {}\n",
            checks_allowed_total
        ));

        out.push_str(
            "# HELP hushd_check_blocked_total Total blocked decisions from /api/v1/check.\n",
        );
        out.push_str("# TYPE hushd_check_blocked_total counter\n");
        out.push_str(&format!(
            "hushd_check_blocked_total {}\n",
            checks_blocked_total
        ));

        out.push_str("# HELP hushd_audit_events_total Total audit events recorded.\n");
        out.push_str("# TYPE hushd_audit_events_total counter\n");
        out.push_str(&format!(
            "hushd_audit_events_total {}\n",
            audit_events_total
        ));

        if let Some(dropped) = audit_forward_dropped {
            out.push_str("# HELP hushd_audit_forward_dropped_total Total audit events dropped from the forward queue.\n");
            out.push_str("# TYPE hushd_audit_forward_dropped_total counter\n");
            out.push_str(&format!("hushd_audit_forward_dropped_total {}\n", dropped));
        }

        out
    }
}
