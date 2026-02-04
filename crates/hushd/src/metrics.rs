//! Minimal Prometheus-style metrics for hushd (no external metrics crate).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct HttpKey {
    method: String,
    path: String,
    status: u16,
}

const LATENCY_BUCKETS_SECS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug)]
struct LatencyHist {
    // per-bucket counts (non-cumulative)
    buckets: Vec<u64>,
    sum_nanos: u128,
    count: u64,
}

impl LatencyHist {
    fn new() -> Self {
        Self {
            buckets: vec![0; LATENCY_BUCKETS_SECS.len() + 1], // +Inf bucket
            sum_nanos: 0,
            count: 0,
        }
    }

    fn observe(&mut self, duration: Duration) {
        self.count = self.count.saturating_add(1);
        self.sum_nanos = self.sum_nanos.saturating_add(duration.as_nanos());

        let secs = duration.as_secs_f64();
        let idx = LATENCY_BUCKETS_SECS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(LATENCY_BUCKETS_SECS.len());
        self.buckets[idx] = self.buckets[idx].saturating_add(1);
    }
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    http_requests_total: AtomicU64,
    http_requests_by_key: Mutex<BTreeMap<HttpKey, u64>>,
    http_latency: Mutex<LatencyHist>,

    check_allowed_total: AtomicU64,
    check_warn_total: AtomicU64,
    check_blocked_total: AtomicU64,

    eval_allowed_total: AtomicU64,
    eval_warn_total: AtomicU64,
    eval_blocked_total: AtomicU64,

    audit_write_failures_total: AtomicU64,
    rate_limit_dropped_total: AtomicU64,
}

impl Metrics {
    pub fn observe_http_request(&self, method: &str, path: &str, status: u16, duration: Duration) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);

        let mut map = self
            .http_requests_by_key
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let key = HttpKey {
            method: method.to_string(),
            path: path.to_string(),
            status,
        };
        *map.entry(key).or_insert(0) += 1;

        let mut hist = self
            .http_latency
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        hist.observe(duration);
    }

    pub fn observe_check_outcome(&self, allowed: bool, warn: bool) {
        if !allowed {
            self.check_blocked_total.fetch_add(1, Ordering::Relaxed);
        } else if warn {
            self.check_warn_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.check_allowed_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn observe_eval_outcome(&self, allowed: bool, warn: bool) {
        if !allowed {
            self.eval_blocked_total.fetch_add(1, Ordering::Relaxed);
        } else if warn {
            self.eval_warn_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.eval_allowed_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn inc_audit_write_failure(&self) {
        self.audit_write_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_dropped(&self) {
        self.rate_limit_dropped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        // HTTP requests
        out.push_str("# HELP hushd_http_requests_total Total HTTP requests handled.\n");
        out.push_str("# TYPE hushd_http_requests_total counter\n");
        out.push_str(&format!(
            "hushd_http_requests_total {}\n",
            self.http_requests_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP hushd_http_requests_by_route_status_total Requests by method/path/status.\n",
        );
        out.push_str("# TYPE hushd_http_requests_by_route_status_total counter\n");
        let map = self
            .http_requests_by_key
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        for (key, count) in map.iter() {
            out.push_str(&format!(
                "hushd_http_requests_by_route_status_total{{method=\"{}\",path=\"{}\",status=\"{}\"}} {}\n",
                escape_label_value(&key.method),
                escape_label_value(&key.path),
                key.status,
                count
            ));
        }
        drop(map);

        // Latency histogram (global)
        out.push_str(
            "# HELP hushd_http_request_duration_seconds HTTP request latency (seconds).\n",
        );
        out.push_str("# TYPE hushd_http_request_duration_seconds histogram\n");
        let hist = self
            .http_latency
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let mut cumulative: u64 = 0;
        for (idx, upper) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            cumulative = cumulative.saturating_add(hist.buckets[idx]);
            out.push_str(&format!(
                "hushd_http_request_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                upper, cumulative
            ));
        }
        // +Inf bucket
        cumulative =
            cumulative.saturating_add(*hist.buckets.get(LATENCY_BUCKETS_SECS.len()).unwrap_or(&0));
        out.push_str(&format!(
            "hushd_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            cumulative
        ));
        out.push_str(&format!(
            "hushd_http_request_duration_seconds_sum {}\n",
            (hist.sum_nanos as f64) / 1_000_000_000.0
        ));
        out.push_str(&format!(
            "hushd_http_request_duration_seconds_count {}\n",
            hist.count
        ));
        drop(hist);

        // Check/Eval outcomes
        out.push_str("# HELP hushd_check_decisions_total Outcomes of /api/v1/check.\n");
        out.push_str("# TYPE hushd_check_decisions_total counter\n");
        out.push_str(&format!(
            "hushd_check_decisions_total{{outcome=\"allowed\"}} {}\n",
            self.check_allowed_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "hushd_check_decisions_total{{outcome=\"warn\"}} {}\n",
            self.check_warn_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "hushd_check_decisions_total{{outcome=\"blocked\"}} {}\n",
            self.check_blocked_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP hushd_eval_decisions_total Outcomes of /api/v1/eval.\n");
        out.push_str("# TYPE hushd_eval_decisions_total counter\n");
        out.push_str(&format!(
            "hushd_eval_decisions_total{{outcome=\"allowed\"}} {}\n",
            self.eval_allowed_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "hushd_eval_decisions_total{{outcome=\"warn\"}} {}\n",
            self.eval_warn_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "hushd_eval_decisions_total{{outcome=\"blocked\"}} {}\n",
            self.eval_blocked_total.load(Ordering::Relaxed)
        ));

        // Operational counters
        out.push_str("# HELP hushd_audit_write_failures_total Failed audit writes.\n");
        out.push_str("# TYPE hushd_audit_write_failures_total counter\n");
        out.push_str(&format!(
            "hushd_audit_write_failures_total {}\n",
            self.audit_write_failures_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP hushd_rate_limit_dropped_total Requests dropped due to rate limiting.\n",
        );
        out.push_str("# TYPE hushd_rate_limit_dropped_total counter\n");
        out.push_str(&format!(
            "hushd_rate_limit_dropped_total {}\n",
            self.rate_limit_dropped_total.load(Ordering::Relaxed)
        ));

        out
    }
}

fn escape_label_value(value: &str) -> String {
    // Prometheus label escaping: backslash, double-quote, and newlines.
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_expected_metric_names() {
        let metrics = Metrics::default();
        metrics.observe_http_request("GET", "/health", 200, Duration::from_millis(5));
        metrics.observe_check_outcome(true, false);
        metrics.observe_eval_outcome(false, false);
        metrics.inc_audit_write_failure();
        metrics.inc_rate_limit_dropped();

        let rendered = metrics.render_prometheus();
        for name in [
            "hushd_http_requests_total",
            "hushd_http_requests_by_route_status_total",
            "hushd_http_request_duration_seconds_bucket",
            "hushd_check_decisions_total",
            "hushd_eval_decisions_total",
            "hushd_audit_write_failures_total",
            "hushd_rate_limit_dropped_total",
        ] {
            assert!(
                rendered.contains(name),
                "expected metrics output to contain {name}"
            );
        }
    }
}
