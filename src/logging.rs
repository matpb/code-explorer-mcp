//! Tracing setup and the per-call tool log line. See docs/ARCHITECTURE.md.

use std::collections::BTreeMap;
use std::fmt as stdfmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

use crate::config::{LogArguments, LogFormat};

const DEFAULT_FILTER: &str = "code_explorer_mcp=info";

// The tracing-subscriber `time` and `chrono` features are not enabled, so format with chrono directly.
struct Rfc3339Utc;

impl FormatTime for Rfc3339Utc {
    fn format_time(&self, w: &mut Writer<'_>) -> stdfmt::Result {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        w.write_str(&now)
    }
}

/// Installs the global subscriber on stderr; later calls are no-ops.
pub fn init(format: LogFormat, filter: Option<&str>) {
    let parsed = match filter {
        Some(f) => EnvFilter::try_new(f).ok(),
        None => EnvFilter::try_from_default_env().ok(),
    };
    let env_filter = parsed.unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER));

    let builder = fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_timer(Rfc3339Utc);
    let _ = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_target(false)
            .try_init(),
        LogFormat::Pretty => builder.pretty().try_init(),
    };
}

#[derive(Debug, Clone, Default)]
pub struct ToolCallLog {
    pub request_id: String,
    pub key: String,
    pub client_ip: String,
    pub tool: String,
    pub repos: Vec<String>,
    pub args: Value,
    pub duration_ms: u64,
    pub bytes_out: u64,
    pub result: &'static str,
    pub matches: Option<u64>,
    pub truncated: bool,
    pub notices: Vec<String>,
    pub commits: BTreeMap<String, String>,
    pub error_code: Option<String>,
}

fn json_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

pub fn tool_call(log: &ToolCallLog) {
    tracing::info!(
        event = "tool_call",
        request_id = %log.request_id,
        key = %log.key,
        client_ip = %log.client_ip,
        tool = %log.tool,
        repos = %json_string(&log.repos),
        args = %json_string(&log.args),
        duration_ms = log.duration_ms,
        bytes_out = log.bytes_out,
        result = log.result,
        matches = log.matches,
        truncated = log.truncated,
        notices = %json_string(&log.notices),
        commits = %json_string(&log.commits),
        error_code = log.error_code.as_deref(),
    );
}

const KEPT_ARGS: &[&str] = &[
    "repo",
    "repos",
    "path",
    "glob",
    "type",
    "offset",
    "limit",
    "depth",
    "max_results",
    "output",
    "case",
    "fixed_strings",
    "word",
    "max_count",
    "since",
];

/// Shape mode hashes `pattern` and keeps only an allow-list of argument keys.
pub fn shape_args(_tool: &str, args: &Value, mode: LogArguments) -> Value {
    if mode == LogArguments::Full {
        return args.clone();
    }
    let mut out = Map::new();
    if let Value::Object(map) = args {
        for (k, v) in map {
            if k == "pattern" {
                if let Value::String(p) = v {
                    out.insert(
                        "pattern_sha256".to_string(),
                        Value::String(
                            data_encoding::HEXLOWER.encode(&Sha256::digest(p.as_bytes())),
                        ),
                    );
                    out.insert("pattern_len".to_string(), Value::from(p.len()));
                }
            } else if KEPT_ARGS.contains(&k.as_str()) {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shape_hashes_pattern_and_drops_unknown_keys() {
        let args = json!({
            "repo": "demo", "pattern": "abc", "path": "src", "limit": 5,
            "secret_thing": "x", "context": 3
        });
        let out = shape_args("grep", &args, LogArguments::Shape);
        assert_eq!(
            out["pattern_sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(out["pattern_len"], 3);
        assert!(out.get("pattern").is_none());
        assert!(out.get("secret_thing").is_none());
        assert!(out.get("context").is_none());
        assert_eq!(out["repo"], "demo");
        assert_eq!(out["path"], "src");
        assert_eq!(out["limit"], 5);
    }

    #[test]
    fn shape_of_non_object_is_empty_object() {
        let out = shape_args("grep", &json!("x"), LogArguments::Shape);
        assert_eq!(out, json!({}));
    }

    #[test]
    fn full_is_identity() {
        let args = json!({"pattern": "abc", "anything": [1, 2]});
        assert_eq!(shape_args("grep", &args, LogArguments::Full), args);
    }

    #[test]
    fn init_twice_does_not_panic() {
        init(LogFormat::Json, Some("off"));
        init(LogFormat::Pretty, None);
        tool_call(&ToolCallLog {
            args: json!({"a": 1}),
            result: "ok",
            ..Default::default()
        });
    }
}
