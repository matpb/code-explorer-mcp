//! `log`: commit history of the repo or of one path, within the kept shallow history.

use chrono::{DateTime, NaiveDate, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::caps::{cut_line, fit_response};
use super::envelope::{
    LogInfo, Notice, Notices, Redaction, Source, ToolOutput, rfc3339, stale_notice, to_value,
};
use super::errors::ToolError;
use crate::auth::AuthContext;
use crate::git::LogQuery;
use crate::paths::RepoPath;

const BODY_MAX_CHARS: usize = 2000;
const FILES_MAX: usize = 50;

fn default_max_count() -> u32 {
    20
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Repo id.
    pub repo: String,
    /// File or directory whose history to show; default is the whole repo.
    #[serde(default)]
    pub path: Option<String>,
    /// Maximum commits, 1 to 100.
    #[serde(default = "default_max_count")]
    #[schemars(range(min = 1, max = 100))]
    pub max_count: u32,
    /// Only commits after this RFC 3339 date or datetime.
    #[serde(default)]
    pub since: Option<String>,
    /// Include the message body, cut at 2000 characters.
    #[serde(default)]
    pub include_body: bool,
    /// Include changed paths with status, up to 50 per commit.
    #[serde(default)]
    pub include_files: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct FileChangeOut {
    pub status: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CommitOut {
    pub commit: String,
    pub parents: Vec<String>,
    pub author_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_email: Option<String>,
    pub author_time: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileChangeOut>>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub source: Source,
    pub commits: Vec<CommitOut>,
    pub history_truncated: bool,
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>, ToolError> {
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Ok(t.with_timezone(&Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        && let Some(midnight) = d.and_hms_opt(0, 0, 0)
    {
        return Ok(midnight.and_utc());
    }
    Err(ToolError::invalid_argument(format!(
        "since must be an RFC 3339 date or datetime such as 2026-01-31 or 2026-01-31T12:00:00Z; you passed {raw:?}."
    )))
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    if !(1..=100).contains(&p.max_count) {
        return Err(ToolError::invalid_argument(format!(
            "max_count must be between 1 and 100; you passed {}.",
            p.max_count
        )));
    }
    let since = p.since.as_deref().map(parse_since).transpose()?;
    let (state, snap) = ex.resolve_repo(auth, &p.repo)?;
    let path: Option<RepoPath> = match p.path.as_deref() {
        Some(raw) => Some(ex.parse_path(raw)?).filter(|rp| !rp.is_root()),
        None => None,
    };
    if let Some(rp) = &path {
        ex.check_allowed(rp)?;
    }
    let known = path
        .as_ref()
        .is_none_or(|rp| snap.index.get(rp).is_some() || snap.index.is_dir(rp));

    let query = LogQuery {
        path: path.as_ref().map(|rp| format!(":(literal){}", rp.as_str())),
        max_count: p.max_count as usize,
        since,
        include_body: p.include_body,
        include_files: p.include_files,
    };
    let in_future = since.is_some_and(|t| t > chrono::Utc::now());
    let (commits, history_truncated) = if in_future {
        (Vec::new(), false)
    } else {
        let _permit = ex.acquire_worker().await?;
        ex.git
            .log(&ex.repo_dir(&p.repo), &snap.commit, &query)
            .await
            .map_err(|e| ex.map_git(e, "git log"))?
    };

    if commits.is_empty()
        && !known
        && let Some(rp) = &path
    {
        return Err(ToolError::path_not_found(
            rp.as_str(),
            &p.repo,
            snap.commit.short(),
            &[],
        ));
    }

    let mut red = Redaction::new(&snap.redactor);
    let mut notices = Notices::default();
    let mut body_cut = false;
    let mut files_cut = false;
    let mut out: Vec<CommitOut> = commits
        .iter()
        .map(|c| {
            let body = p.include_body.then(|| {
                let masked = red.apply(c.body.trim_end());
                let (cut, was) = cut_line(&masked, BODY_MAX_CHARS);
                body_cut |= was;
                cut.into_owned()
            });
            let files = p.include_files.then(|| {
                let allowed: Vec<FileChangeOut> = c
                    .files
                    .iter()
                    .filter(|f| {
                        RepoPath::parse(&f.path)
                            .map(|rp| !ex.deny.is_denied(&rp))
                            .unwrap_or(false)
                    })
                    .map(|f| FileChangeOut {
                        status: f.status.clone(),
                        path: f.path.clone(),
                    })
                    .collect();
                files_cut |= allowed.len() > FILES_MAX;
                allowed.into_iter().take(FILES_MAX).collect()
            });
            CommitOut {
                commit: c.oid.to_string(),
                parents: c.parents.iter().map(ToString::to_string).collect(),
                author_name: c.author_name.clone(),
                author_email: ex.cfg.logging.author_emails.then(|| c.author_email.clone()),
                author_time: rfc3339(c.author_time),
                subject: red.apply(&c.subject).into_owned(),
                body,
                files,
            }
        })
        .collect();

    let source = ex.source(&state, &snap);
    let (structured, fitted) = fit_response(
        &mut out,
        |items| {
            to_value(&Output {
                source: source.clone(),
                commits: items.to_vec(),
                history_truncated,
            })
        },
        ex.cfg.limits.max_response_bytes / 2,
    );
    if body_cut {
        notices.push(Notice::output_truncated(
            "body length (2000 chars)",
            "Read the full message from the repository host.",
        ));
    }
    if files_cut {
        notices.push(Notice::output_truncated(
            "files per commit (50)",
            "Use path to narrow the history.",
        ));
    }
    if fitted {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "Lower max_count or leave out include_body and include_files.",
        ));
    }
    if history_truncated {
        notices.push(Notice::history_truncated());
    }
    notices.push_opt(stale_notice(&ex.cfg, &state));
    notices.push_opt(red.notice());

    let mut text = format!(
        "{}@{} log{} ({} commits)\n",
        source.repo,
        &source.commit[..source.commit.len().min(7)],
        path.as_ref()
            .map(|p| format!(" {}", p.as_str()))
            .unwrap_or_default(),
        out.len()
    );
    for c in &out {
        text.push_str(&format!(
            "{} {} {} {}\n",
            &c.commit[..c.commit.len().min(7)],
            c.author_time,
            c.author_name,
            c.subject
        ));
        if let Some(body) = &c.body
            && !body.is_empty()
        {
            for line in body.lines() {
                text.push_str(&format!("    {line}\n"));
            }
        }
        for f in c.files.iter().flatten() {
            text.push_str(&format!("    {} {}\n", f.status, f.path));
        }
    }
    let mut log = LogInfo::default();
    log.repo(&source);
    log.matches = Some(out.len() as u64);
    Ok(ToolOutput::new(structured, text)
        .with_notices(notices)
        .with_log(log))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::parse_since;

    #[test]
    fn since_accepts_dates_and_datetimes() {
        assert!(parse_since("2026-01-31").is_ok());
        assert!(parse_since("2026-01-31T12:00:00Z").is_ok());
        assert!(parse_since("2026-01-31T12:00:00+02:00").is_ok());
        assert!(parse_since("yesterday").is_err());
    }
}
