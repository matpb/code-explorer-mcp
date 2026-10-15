//! `/readyz` body: per-repo pull state, key store state and credential expiry.

use axum::http::StatusCode;
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde::Serialize;

use super::AdminState;
use crate::config::ScanPolicy;
use crate::snapshot::{RepoState, RepoStatus};

#[derive(Debug, Serialize)]
pub struct KeysBody {
    pub count: usize,
    pub reload_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LastErrorBody {
    pub class: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ScanBody {
    pub policy: &'static str,
    pub findings: usize,
    pub held: bool,
}

#[derive(Debug, Serialize)]
pub struct RepoBody {
    pub id: String,
    pub status: &'static str,
    pub commit: Option<String>,
    pub commit_time: Option<String>,
    pub last_success: Option<String>,
    pub last_attempt: Option<String>,
    pub last_error: Option<LastErrorBody>,
    pub consecutive_failures: u32,
    pub stale_seconds: u64,
    pub scan: ScanBody,
    pub credential_expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ReadyzBody {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub keys: KeysBody,
    pub repos: Vec<RepoBody>,
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn policy_word(p: ScanPolicy) -> &'static str {
    match p {
        ScanPolicy::Redact => "redact",
        ScanPolicy::Warn => "warn",
        ScanPolicy::Block => "block",
    }
}

/// Days from `today` until `expires`; negative once past.
pub fn expiry_days(expires: NaiveDate, today: NaiveDate) -> i64 {
    (expires - today).num_days()
}

pub(super) fn credential_days(st: &AdminState, repo: &RepoState, today: NaiveDate) -> Option<i64> {
    let expires = st.cfg.credentials.get(&repo.cfg.credential)?.expires()?;
    Some(expiry_days(expires, today))
}

fn repo_body(st: &AdminState, repo: &RepoState, now: DateTime<Utc>) -> (RepoBody, RepoStatus) {
    let stale_after = st.cfg.pull.stale_after;
    let status = repo.status_word(stale_after, now);
    let pull = repo.status();
    let snap = repo.snapshot();
    let body = RepoBody {
        id: repo.cfg.id.clone(),
        status: status.as_str(),
        commit: snap.as_ref().map(|s| s.commit.short().to_owned()),
        commit_time: snap.as_ref().map(|s| ts(s.commit_time)),
        last_success: pull.last_success.map(ts),
        last_attempt: pull.last_attempt.map(ts),
        last_error: pull.last_error.as_ref().map(|e| LastErrorBody {
            class: e.class.as_str(),
            message: e.message.clone(),
        }),
        consecutive_failures: pull.consecutive_failures,
        stale_seconds: repo.stale_seconds(stale_after, now),
        scan: ScanBody {
            policy: policy_word(repo.cfg.scan_policy_or(st.cfg.scan.policy)),
            findings: pull.scan_findings,
            held: pull.scan_held,
        },
        credential_expires_in_days: credential_days(st, repo, now.date_naive()),
    };
    (body, status)
}

/// 503 `initializing` while any repo awaits its first attempt, else 200 `ok` or `degraded`.
pub fn readyz(st: &AdminState) -> (StatusCode, ReadyzBody) {
    let now = Utc::now();
    let mut initializing = false;
    let mut degraded = false;
    let mut repos = Vec::with_capacity(st.registry.repos.len());
    for repo in st.registry.iter() {
        let (body, status) = repo_body(st, repo, now);
        initializing |= status == RepoStatus::Initializing;
        degraded |= matches!(status, RepoStatus::Stale | RepoStatus::Unavailable) || body.scan.held;
        repos.push(body);
    }
    let (code, word) = if initializing {
        (StatusCode::SERVICE_UNAVAILABLE, "initializing")
    } else if degraded {
        (StatusCode::OK, "degraded")
    } else {
        (StatusCode::OK, "ok")
    };
    let body = ReadyzBody {
        status: word,
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: (now - st.started_at).num_seconds().max(0) as u64,
        keys: KeysBody {
            count: st.keys.count(),
            reload_error: st.keys.reload_error(),
        },
        repos,
    };
    (code, body)
}
