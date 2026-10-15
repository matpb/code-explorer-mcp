//! `blame`: per-line attribution within the kept history (optional feature).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::caps::{cut_line, fit_response};
use super::envelope::{
    LogInfo, Notice, Notices, Redaction, Source, ToolOutput, rfc3339, stale_notice, to_value,
};
use super::errors::ToolError;
use crate::auth::AuthContext;
use crate::git::GitError;
use crate::snapshot::EntryKind;

const MAX_LINES: u32 = 400;

fn default_start() -> u32 {
    1
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Repo id.
    pub repo: String,
    /// File path relative to the repo root.
    pub path: String,
    /// First line, 1-based.
    #[serde(default = "default_start")]
    #[schemars(range(min = 1))]
    pub start_line: u32,
    /// Last line, inclusive; default is start_line + 399. At most 400 lines per call.
    #[serde(default)]
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct LineOut {
    pub line: u32,
    pub commit: String,
    pub author_name: String,
    pub author_time: String,
    /// True when the line is older than the shallow boundary.
    pub boundary: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub source: Source,
    pub path: String,
    pub lines: Vec<LineOut>,
}

/// Commit ids listed in the clone's `shallow` file, i.e. the cut-off points of the kept history.
fn shallow_oids(repo_dir: &std::path::Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(repo_dir.join("shallow"))
        .map(|s| s.lines().map(|l| l.trim().to_owned()).collect())
        .unwrap_or_default()
}

/// Total line count out of git's "file X has only N lines" message.
fn lines_in_error(stderr: &str) -> Option<usize> {
    let rest = stderr.split("has only ").nth(1)?;
    rest.split_whitespace().next()?.parse().ok()
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    if !ex.cfg.features.blame {
        return Err(ToolError::invalid_argument(
            "blame is not enabled on this server.",
        ));
    }
    let start = p.start_line;
    if start < 1 {
        return Err(ToolError::invalid_argument(
            "start_line must be at least 1.",
        ));
    }
    let end = p.end_line.unwrap_or(start.saturating_add(MAX_LINES - 1));
    if end < start {
        return Err(ToolError::invalid_argument(format!(
            "end_line {end} is before start_line {start}."
        )));
    }
    if end - start + 1 > MAX_LINES {
        return Err(ToolError::invalid_argument(format!(
            "blame returns at most {MAX_LINES} lines per call; you asked for {}.",
            end - start + 1
        )));
    }
    let (state, snap) = ex.resolve_repo(auth, &p.repo)?;
    let path = ex.parse_path(&p.path)?;
    ex.check_allowed(&path)?;
    match snap.index.get(&path) {
        Some(e) if e.kind == EntryKind::File => {}
        Some(_) => return Err(ToolError::not_a_file(path.as_str())),
        None if snap.index.is_dir(&path) => return Err(ToolError::not_a_file(path.as_str())),
        None => {
            let suggestions: Vec<String> = snap
                .index
                .close_matches(&path, 5)
                .into_iter()
                .filter(|m| !ex.deny.is_denied(m))
                .map(|m| m.as_str().to_owned())
                .collect();
            return Err(ToolError::path_not_found(
                path.as_str(),
                &p.repo,
                snap.commit.short(),
                &suggestions,
            ));
        }
    }
    let _permit = ex.workers.acquire().await.map_err(|_| ToolError::busy())?;
    let blamed = match ex.git.blame(&snap.root, path.as_str(), start, end).await {
        Ok(lines) => lines,
        Err(GitError::Failed {
            stderr_scrubbed, ..
        }) => {
            return Err(match lines_in_error(&stderr_scrubbed) {
                Some(total) => ToolError::new(
                    super::errors::ErrorCode::OffsetOutOfRange,
                    format!("File has {total} lines; start_line {start} is past the end."),
                ),
                None => ToolError::internal(format!("git blame failed: {stderr_scrubbed}")),
            });
        }
        Err(e) => return Err(ex.map_git(e, "git blame")),
    };
    drop(_permit);

    let shallow = shallow_oids(&ex.repo_dir(&p.repo));
    let mut red = Redaction::new(&snap.redactor);
    let mut cut_any = false;
    let mut any_boundary = false;
    let mut lines: Vec<LineOut> = blamed
        .iter()
        .map(|b| {
            any_boundary |= b.boundary && shallow.contains(b.oid.as_str());
            let masked = red.apply(b.text.trim_end_matches(['\r', '\n']));
            let (cut, was) = cut_line(&masked, ex.cfg.limits.max_line_chars);
            cut_any |= was;
            LineOut {
                line: b.line,
                commit: b.oid.to_string(),
                author_name: b.author_name.clone(),
                author_time: rfc3339(b.author_time),
                boundary: b.boundary,
                text: cut.into_owned(),
            }
        })
        .collect();

    let source = ex.source(&state, &snap);
    let (structured, fitted) = fit_response(
        &mut lines,
        |items| {
            to_value(&Output {
                source: source.clone(),
                path: path.as_str().to_owned(),
                lines: items.to_vec(),
            })
        },
        ex.cfg.limits.max_response_bytes / 2,
    );
    let mut notices = Notices::default();
    if any_boundary {
        notices.push(Notice::history_truncated());
    }
    if cut_any {
        notices.push(Notice::output_truncated(
            "max_line_chars",
            "Some lines were cut; read_file shows the full text.",
        ));
    }
    if fitted {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "Request a smaller line range.",
        ));
    }
    notices.push_opt(stale_notice(&ex.cfg, &state));
    notices.push_opt(red.notice());

    let mut text = format!(
        "{}@{} blame {} lines {}-{}\n",
        source.repo,
        &source.commit[..source.commit.len().min(7)],
        path.as_str(),
        start,
        end
    );
    for l in &lines {
        text.push_str(&format!(
            "{}\t{}{} {}\t{}\n",
            l.line,
            &l.commit[..l.commit.len().min(7)],
            if l.boundary { "^" } else { "" },
            l.author_name,
            l.text
        ));
    }
    let mut log = LogInfo::default();
    log.repo(&source);
    Ok(ToolOutput::new(structured, text)
        .with_notices(notices)
        .with_log(log))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::lines_in_error;

    #[test]
    fn parses_total_from_git_error() {
        assert_eq!(
            lines_in_error("fatal: file README.md has only 3 lines"),
            Some(3)
        );
        assert_eq!(lines_in_error("fatal: no such path"), None);
    }
}
