//! Prometheus metrics on a private registry. See docs/ARCHITECTURE.md.

use std::sync::Arc;
use std::time::Duration;

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
    exponential_buckets,
};

pub struct Metrics {
    registry: Registry,
    tool_calls: CounterVec,
    tool_duration: HistogramVec,
    tool_response_bytes: HistogramVec,
    auth_failures: CounterVec,
    auth_blocked_ips: Gauge,
    workers_busy: Gauge,
    queue_rejections: Counter,
    subprocess_timeouts: CounterVec,
    repo_last_success: GaugeVec,
    repo_pull_failures: CounterVec,
    repo_stale: GaugeVec,
    repo_findings: GaugeVec,
    scan_held: GaugeVec,
    credential_expiry: GaugeVec,
}

impl Metrics {
    pub fn new() -> Arc<Metrics> {
        match Metrics::try_new() {
            Ok(m) => Arc::new(m),
            Err(e) => panic!("static metric definitions are invalid: {e}"),
        }
    }

    fn try_new() -> prometheus::Result<Metrics> {
        let registry = Registry::new();

        let tool_calls = CounterVec::new(
            Opts::new(
                "explorer_tool_calls_total",
                "Tool calls by tool, result and key.",
            ),
            &["tool", "result", "key"],
        )?;
        let tool_duration = HistogramVec::new(
            HistogramOpts::new("explorer_tool_duration_seconds", "Tool call duration.")
                .buckets(exponential_buckets(0.005, 2.0, 12)?),
            &["tool"],
        )?;
        let tool_response_bytes = HistogramVec::new(
            HistogramOpts::new(
                "explorer_tool_response_bytes",
                "Tool response size in bytes.",
            )
            .buckets(exponential_buckets(256.0, 2.0, 11)?),
            &["tool"],
        )?;
        let auth_failures = CounterVec::new(
            Opts::new(
                "explorer_auth_failures_total",
                "Failed authentications by reason.",
            ),
            &["reason"],
        )?;
        let auth_blocked_ips = Gauge::new(
            "explorer_auth_blocked_ips",
            "Client IPs currently blocked by the auth throttle.",
        )?;
        let workers_busy = Gauge::new("explorer_workers_busy", "Subprocess workers in use.")?;
        let queue_rejections = Counter::new(
            "explorer_worker_queue_rejections_total",
            "Requests rejected because the worker queue was full.",
        )?;
        let subprocess_timeouts = CounterVec::new(
            Opts::new(
                "explorer_subprocess_timeouts_total",
                "Subprocess timeouts by kind.",
            ),
            &["kind"],
        )?;
        let repo_last_success = GaugeVec::new(
            Opts::new(
                "explorer_repo_last_success_timestamp_seconds",
                "Unix time of the last successful pull.",
            ),
            &["repo"],
        )?;
        let repo_pull_failures = CounterVec::new(
            Opts::new(
                "explorer_repo_pull_failures_total",
                "Failed pulls by repo and class.",
            ),
            &["repo", "class"],
        )?;
        let repo_stale = GaugeVec::new(
            Opts::new("explorer_repo_stale", "1 when the repo snapshot is stale."),
            &["repo"],
        )?;
        let repo_findings = GaugeVec::new(
            Opts::new(
                "explorer_repo_secret_findings",
                "Secret scan findings per repo.",
            ),
            &["repo"],
        )?;
        let scan_held = GaugeVec::new(
            Opts::new(
                "explorer_scan_held",
                "1 when a pull is held by the secret scan.",
            ),
            &["repo"],
        )?;
        let credential_expiry = GaugeVec::new(
            Opts::new(
                "explorer_credential_expiry_days",
                "Days until a credential expires.",
            ),
            &["credential"],
        )?;
        let build_info = GaugeVec::new(
            Opts::new("explorer_build_info", "Build information, always 1."),
            &["version"],
        )?;
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1.0);

        registry.register(Box::new(tool_calls.clone()))?;
        registry.register(Box::new(tool_duration.clone()))?;
        registry.register(Box::new(tool_response_bytes.clone()))?;
        registry.register(Box::new(auth_failures.clone()))?;
        registry.register(Box::new(auth_blocked_ips.clone()))?;
        registry.register(Box::new(workers_busy.clone()))?;
        registry.register(Box::new(queue_rejections.clone()))?;
        registry.register(Box::new(subprocess_timeouts.clone()))?;
        registry.register(Box::new(repo_last_success.clone()))?;
        registry.register(Box::new(repo_pull_failures.clone()))?;
        registry.register(Box::new(repo_stale.clone()))?;
        registry.register(Box::new(repo_findings.clone()))?;
        registry.register(Box::new(scan_held.clone()))?;
        registry.register(Box::new(credential_expiry.clone()))?;
        registry.register(Box::new(build_info))?;

        Ok(Metrics {
            registry,
            tool_calls,
            tool_duration,
            tool_response_bytes,
            auth_failures,
            auth_blocked_ips,
            workers_busy,
            queue_rejections,
            subprocess_timeouts,
            repo_last_success,
            repo_pull_failures,
            repo_stale,
            repo_findings,
            scan_held,
            credential_expiry,
        })
    }

    pub fn tool_call(&self, tool: &str, result: &str, key: &str, duration: Duration, bytes: u64) {
        self.tool_calls
            .with_label_values(&[tool, result, key])
            .inc();
        self.tool_duration
            .with_label_values(&[tool])
            .observe(duration.as_secs_f64());
        self.tool_response_bytes
            .with_label_values(&[tool])
            .observe(bytes as f64);
    }

    pub fn auth_failure(&self, reason: &str) {
        self.auth_failures.with_label_values(&[reason]).inc();
    }

    pub fn set_blocked_ips(&self, n: usize) {
        self.auth_blocked_ips.set(n as f64);
    }

    pub fn set_workers_busy(&self, n: usize) {
        self.workers_busy.set(n as f64);
    }

    pub fn queue_rejection(&self) {
        self.queue_rejections.inc();
    }

    pub fn subprocess_timeout(&self, kind: &str) {
        self.subprocess_timeouts.with_label_values(&[kind]).inc();
    }

    pub fn repo_success(&self, repo: &str, unix_ts: i64) {
        self.repo_last_success
            .with_label_values(&[repo])
            .set(unix_ts as f64);
    }

    pub fn repo_pull_failure(&self, repo: &str, class: &str) {
        self.repo_pull_failures
            .with_label_values(&[repo, class])
            .inc();
    }

    pub fn set_repo_stale(&self, repo: &str, stale: bool) {
        self.repo_stale
            .with_label_values(&[repo])
            .set(if stale { 1.0 } else { 0.0 });
    }

    pub fn set_repo_findings(&self, repo: &str, n: usize) {
        self.repo_findings.with_label_values(&[repo]).set(n as f64);
    }

    pub fn set_scan_held(&self, repo: &str, held: bool) {
        self.scan_held
            .with_label_values(&[repo])
            .set(if held { 1.0 } else { 0.0 });
    }

    pub fn set_credential_expiry(&self, name: &str, days: f64) {
        self.credential_expiry.with_label_values(&[name]).set(days);
    }

    pub fn render(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_every_metric_name() {
        let m = Metrics::new();
        m.tool_call("grep", "ok", "alice", Duration::from_millis(12), 900);
        m.auth_failure("bad_key");
        m.set_blocked_ips(2);
        m.set_workers_busy(1);
        m.queue_rejection();
        m.subprocess_timeout("grep");
        m.repo_success("demo", 1_700_000_000);
        m.repo_pull_failure("demo", "network");
        m.set_repo_stale("demo", true);
        m.set_repo_findings("demo", 3);
        m.set_scan_held("demo", true);
        m.set_credential_expiry("demo-token", 12.0);
        let out = m.render();
        for name in [
            "explorer_tool_calls_total",
            "explorer_tool_duration_seconds",
            "explorer_tool_response_bytes",
            "explorer_auth_failures_total",
            "explorer_auth_blocked_ips",
            "explorer_workers_busy",
            "explorer_worker_queue_rejections_total",
            "explorer_subprocess_timeouts_total",
            "explorer_repo_last_success_timestamp_seconds",
            "explorer_repo_pull_failures_total",
            "explorer_repo_stale",
            "explorer_repo_secret_findings",
            "explorer_scan_held",
            "explorer_credential_expiry_days",
            "explorer_build_info",
        ] {
            assert!(out.contains(name), "missing {name} in:\n{out}");
        }
        assert!(out.contains(&format!(
            "explorer_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn tool_call_increments_labelled_series() {
        let m = Metrics::new();
        m.tool_call("read", "ok", "alice", Duration::from_millis(5), 300);
        m.tool_call("read", "ok", "alice", Duration::from_millis(5), 300);
        m.tool_call("read", "error", "bob", Duration::from_millis(5), 10);
        let out = m.render();
        assert!(
            out.contains("explorer_tool_calls_total{key=\"alice\",result=\"ok\",tool=\"read\"} 2")
        );
        assert!(
            out.contains("explorer_tool_calls_total{key=\"bob\",result=\"error\",tool=\"read\"} 1")
        );
        assert!(out.contains("explorer_tool_duration_seconds_count{tool=\"read\"} 3"));
        assert!(out.contains("explorer_tool_response_bytes_count{tool=\"read\"} 3"));
    }

    #[test]
    fn bool_gauges_flip() {
        let m = Metrics::new();
        m.set_repo_stale("r", true);
        assert!(m.render().contains("explorer_repo_stale{repo=\"r\"} 1"));
        m.set_repo_stale("r", false);
        assert!(m.render().contains("explorer_repo_stale{repo=\"r\"} 0"));
    }
}
