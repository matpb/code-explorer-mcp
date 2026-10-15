//! `list_repos`: the repos this key can explore and how fresh each one is.

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::envelope::{LogInfo, Notice, Notices, Redaction, ToolOutput, rfc3339, to_value};
use super::errors::ToolError;
use crate::auth::AuthContext;
use crate::snapshot::RepoStatus;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct RepoInfo {
    pub id: String,
    pub host: String,
    pub path: String,
    pub description: String,
    pub branch: String,
    pub commit: Option<String>,
    pub commit_time: Option<String>,
    pub commit_subject: Option<String>,
    pub pulled_at: Option<String>,
    pub status: String,
    pub stale_seconds: u64,
    pub history_depth: u32,
    pub secrets_redacted: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub repos: Vec<RepoInfo>,
}

pub async fn run(
    ex: &Explorer,
    auth: &AuthContext,
    _params: Params,
) -> Result<ToolOutput, ToolError> {
    let now = Utc::now();
    let mut repos = Vec::new();
    let mut lines = Vec::new();
    let mut stale_ids = Vec::new();
    let mut redacted = 0usize;
    let mut log = LogInfo::default();
    for state in ex.registry.visible_to(auth.repos.as_deref()) {
        let status = state.status_word(ex.cfg.pull.stale_after, now);
        let stale_seconds = state.stale_seconds(ex.cfg.pull.stale_after, now);
        if status == RepoStatus::Stale {
            stale_ids.push(state.cfg.id.clone());
        }
        let snap = state.snapshot();
        let pulled = state
            .status()
            .last_success
            .or(snap.as_ref().map(|s| s.pulled_at));
        let (commit, commit_time, subject, findings) = match &snap {
            Some(s) => {
                let mut red = Redaction::new(&s.redactor);
                let subject = red.apply(&s.commit_subject).into_owned();
                redacted += red.hits;
                (
                    Some(s.commit.to_string()),
                    Some(rfc3339(s.commit_time)),
                    Some(subject),
                    s.findings,
                )
            }
            None => (None, None, None, 0),
        };
        if let Some(c) = &commit {
            log.repos.push(state.cfg.id.clone());
            log.commits
                .insert(state.cfg.id.clone(), c.chars().take(7).collect());
        }
        let short = commit.as_deref().map_or("-", |c| &c[..c.len().min(7)]);
        lines.push(format!(
            "{} ({} {} @ {}) {}, {}, {}",
            state.cfg.id,
            state.cfg.host.as_str(),
            state.cfg.path,
            state.cfg.branch,
            short,
            status.as_str(),
            state.cfg.description
        ));
        repos.push(RepoInfo {
            id: state.cfg.id.clone(),
            host: state.cfg.host.as_str().to_owned(),
            path: state.cfg.path.clone(),
            description: state.cfg.description.clone(),
            branch: state.cfg.branch.clone(),
            commit,
            commit_time,
            commit_subject: subject,
            pulled_at: pulled.map(rfc3339),
            status: status.as_str().to_owned(),
            stale_seconds,
            history_depth: ex.cfg.pull.depth,
            secrets_redacted: findings,
        });
    }
    let mut notices = Notices::default();
    if !stale_ids.is_empty() {
        let mut n = Notice::stale_snapshot(
            repos
                .iter()
                .filter(|r| r.status == "stale")
                .map(|r| r.stale_seconds)
                .max()
                .unwrap_or(0),
            None,
        );
        n.message = format!("Stale repos: {}. {}", stale_ids.join(", "), n.message);
        notices.push(n);
    }
    if redacted > 0 {
        notices.push(Notice::secrets_redacted(redacted));
    }
    let text = if lines.is_empty() {
        "No repos are available to this key.".to_owned()
    } else {
        lines.join("\n")
    };
    Ok(ToolOutput::new(to_value(&Output { repos }), text)
        .with_notices(notices)
        .with_log(log))
}
