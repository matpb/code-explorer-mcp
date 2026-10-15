//! Source stamps, notices and the success result shared by every tool.

use std::borrow::Cow;
use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};

use super::caps::human_age;
use crate::config::Config;
use crate::redact::Redactor;
use crate::snapshot::{RepoState, RepoStatus, Snapshot};

pub fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

pub fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The repo@commit stamp every result carries.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Source {
    pub repo: String,
    pub host: String,
    pub path: String,
    pub branch: String,
    pub commit: String,
    pub commit_time: String,
    pub pulled_at: String,
    pub stale: bool,
}

impl Source {
    pub fn new(cfg: &Config, state: &RepoState, snap: &Snapshot) -> Source {
        let stale = state.status_word(cfg.pull.stale_after, Utc::now()) == RepoStatus::Stale;
        Source {
            repo: state.cfg.id.clone(),
            host: state.cfg.host.as_str().to_owned(),
            path: state.cfg.path.clone(),
            branch: state.cfg.branch.clone(),
            commit: snap.commit.to_string(),
            commit_time: rfc3339(snap.commit_time),
            pulled_at: rfc3339(state.status().last_success.unwrap_or(snap.pulled_at)),
            stale,
        }
    }

    /// Re-stamps the envelope for a specific commit of the same repo.
    pub fn at_commit(mut self, commit: &str, commit_time: DateTime<Utc>) -> Source {
        self.commit = commit.to_owned();
        self.commit_time = rfc3339(commit_time);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Notice {
    pub code: String,
    pub message: String,
}

impl Notice {
    fn new(code: &str, message: String) -> Notice {
        Notice {
            code: code.to_owned(),
            message,
        }
    }

    pub fn output_truncated(cap_name: &str, how_to_narrow: &str) -> Notice {
        Notice::new(
            "output_truncated",
            format!("Output was cut by {cap_name}. {how_to_narrow}"),
        )
    }

    pub fn stale_snapshot(age_secs: u64, last_error_class: Option<&str>) -> Notice {
        let mut message = format!(
            "No successful pull for {}; results may be out of date.",
            human_age(age_secs)
        );
        if let Some(class) = last_error_class {
            message.push_str(&format!(" Last pull error class: {class}."));
        }
        Notice::new("stale_snapshot", message)
    }

    pub fn secrets_redacted(count: usize) -> Notice {
        Notice::new(
            "secrets_redacted",
            format!(
                "Secret values in this result were masked as [REDACTED:rule-id] ({count} place(s))."
            ),
        )
    }

    pub fn history_truncated() -> Notice {
        Notice::new(
            "history_truncated",
            "The walk reached the shallow-clone boundary; older history is not kept.".into(),
        )
    }

    /// Prefixes the message with the repo id, for results that span several repos.
    pub fn for_repo(mut self, repo: &str) -> Notice {
        self.message = format!("{repo}: {}", self.message);
        self
    }
}

/// A `stale_snapshot` notice when the repo has had no successful pull for `stale_after`.
pub fn stale_notice(cfg: &Config, state: &RepoState) -> Option<Notice> {
    let now = Utc::now();
    if state.status_word(cfg.pull.stale_after, now) != RepoStatus::Stale {
        return None;
    }
    let age = state.stale_seconds(cfg.pull.stale_after, now);
    let status = state.status();
    let class = status.last_error.as_ref().map(|e| e.class.as_str());
    Some(Notice::stale_snapshot(age, class))
}

/// Notices of one result, without duplicates.
#[derive(Debug, Default)]
pub struct Notices(Vec<Notice>);

impl Notices {
    pub fn push(&mut self, notice: Notice) {
        if !self.0.contains(&notice) {
            self.0.push(notice);
        }
    }

    pub fn push_opt(&mut self, notice: Option<Notice>) {
        if let Some(n) = notice {
            self.push(n);
        }
    }

    pub fn into_vec(self) -> Vec<Notice> {
        self.0
    }
}

/// Applies a snapshot's redactor and counts the strings it changed.
pub struct Redaction<'a> {
    redactor: &'a Redactor,
    pub hits: usize,
}

impl<'a> Redaction<'a> {
    pub fn new(redactor: &'a Redactor) -> Self {
        Redaction { redactor, hits: 0 }
    }

    pub fn apply<'s>(&mut self, s: &'s str) -> Cow<'s, str> {
        let (out, changed) = self.redactor.redact(s);
        if changed {
            self.hits += 1;
        }
        out
    }

    pub fn notice(&self) -> Option<Notice> {
        self.notice_plus(0)
    }

    /// The `secrets_redacted` notice for these hits plus `extra` places masked on disk.
    pub fn notice_plus(&self, extra: usize) -> Option<Notice> {
        let n = self.hits + extra;
        (n > 0).then(|| Notice::secrets_redacted(n))
    }
}

/// Facts the call log needs besides the rendered result.
#[derive(Debug, Default, Clone)]
pub struct LogInfo {
    pub repos: Vec<String>,
    pub commits: BTreeMap<String, String>,
    pub matches: Option<u64>,
}

impl LogInfo {
    pub fn repo(&mut self, source: &Source) {
        if !self.repos.contains(&source.repo) {
            self.repos.push(source.repo.clone());
        }
        self.commits
            .insert(source.repo.clone(), source.commit.chars().take(7).collect());
    }
}

#[derive(Debug)]
pub struct ToolOutput {
    pub structured: Value,
    pub text: String,
    pub notices: Vec<Notice>,
    pub log: LogInfo,
}

impl ToolOutput {
    pub fn new(structured: Value, text: String) -> ToolOutput {
        ToolOutput {
            structured,
            text,
            notices: Vec::new(),
            log: LogInfo::default(),
        }
    }

    pub fn with_notices(mut self, notices: Notices) -> ToolOutput {
        self.notices = notices.into_vec();
        self
    }

    pub fn with_log(mut self, log: LogInfo) -> ToolOutput {
        self.log = log;
        self
    }

    /// Appends `notices` to the structured object and renders them at the end of the text.
    pub fn into_result(self) -> CallToolResult {
        let mut structured = self.structured;
        let notices = json!(self.notices);
        if let Value::Object(map) = &mut structured {
            map.insert("notices".into(), notices);
        }
        let mut text = self.text;
        for n in &self.notices {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!("[notice {}] {}\n", n.code, n.message));
        }
        let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
        result.structured_content = Some(structured);
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn notices_render_and_attach() {
        let out = ToolOutput::new(json!({"a": 1}), "body".into()).with_notices({
            let mut n = Notices::default();
            n.push(Notice::history_truncated());
            n.push(Notice::history_truncated());
            n
        });
        let res = out.into_result();
        let structured = res.structured_content.expect("structured");
        assert_eq!(structured["notices"].as_array().map(Vec::len), Some(1));
        assert_eq!(structured["notices"][0]["code"], "history_truncated");
        let text = res.content[0]
            .as_text()
            .map(|t| t.text.clone())
            .unwrap_or_default();
        assert!(text.starts_with("body\n[notice history_truncated] "));
    }
}
