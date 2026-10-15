//! `read_file`: a line range of one text file, from the worktree or from a kept commit.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::caps::{cut_line, fit_response};
use super::envelope::{
    LogInfo, Notice, Notices, Redaction, Source, ToolOutput, stale_notice, to_value,
};
use super::errors::ToolError;
use super::{permalink, read_worktree};
use crate::auth::AuthContext;
use crate::snapshot::EntryKind;

const BINARY_SNIFF_BYTES: usize = 8 * 1024;

fn default_offset() -> u32 {
    1
}

fn default_limit() -> u32 {
    400
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Repo id.
    pub repo: String,
    /// File path relative to the repo root.
    pub path: String,
    /// First line to return, 1-based.
    #[serde(default = "default_offset")]
    #[schemars(range(min = 1))]
    pub offset: u32,
    /// Number of lines to return, 1 to 2000.
    #[serde(default = "default_limit")]
    #[schemars(range(min = 1, max = 2000))]
    pub limit: u32,
    /// Read the file as of this commit (any commit within the kept history).
    #[serde(default)]
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub source: Source,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub total_lines: usize,
    pub size: u64,
    pub content: String,
    pub permalink: String,
}

/// Lines split on `\n` with `\r` kept; a trailing newline does not add an empty line.
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

fn valid_commit_arg(c: &str) -> bool {
    (4..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit())
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    if p.offset < 1 {
        return Err(ToolError::invalid_argument("offset must be at least 1."));
    }
    if !(1..=2000).contains(&p.limit) {
        return Err(ToolError::invalid_argument(format!(
            "limit must be between 1 and 2000; you passed {}.",
            p.limit
        )));
    }
    if p.commit.is_some() && !ex.cfg.features.file_at_commit {
        return Err(ToolError::invalid_argument(
            "commit is not enabled on this server; omit it to read the current snapshot.",
        ));
    }
    let (state, snap) = ex.resolve_repo(auth, &p.repo)?;
    let path = ex.parse_path(&p.path)?;
    ex.check_allowed(&path)?;
    if path.is_root() {
        return Err(ToolError::not_a_file(""));
    }
    let max_bytes = ex.cfg.limits.max_file_bytes;
    let mut source = ex.source(&state, &snap);
    let commit_full: String;

    let bytes = if let Some(rev) = &p.commit {
        if !valid_commit_arg(rev) {
            return Err(ToolError::invalid_argument(
                "commit must be a hex commit id of 4 to 64 characters.",
            ));
        }
        let repo_dir = ex.repo_dir(&p.repo);
        let short = &rev[..rev.len().min(7)];
        let history_err = || ToolError::history_unavailable(ex.cfg.pull.depth, short);
        let _permit = ex.workers.acquire().await.map_err(|_| ToolError::busy())?;
        let oid = match ex.git.rev_parse(&repo_dir, rev).await {
            Ok(oid) => oid,
            Err(crate::git::GitError::Failed { .. }) => return Err(history_err()),
            Err(e) => return Err(ex.map_git(e, "git")),
        };
        let in_history = ex
            .git
            .commit_in_history(&repo_dir, &oid, &state.cfg.branch)
            .await
            .map_err(|e| ex.map_git(e, "git"))?;
        if !in_history {
            return Err(history_err());
        }
        let data = match ex.git.show_file(&repo_dir, &oid, path.as_str()).await {
            Ok(d) => d,
            Err(crate::git::GitError::Failed { .. }) => {
                return Err(ToolError::path_not_found(
                    path.as_str(),
                    &p.repo,
                    oid.short(),
                    &[],
                ));
            }
            Err(e) => return Err(ex.map_git(e, "git")),
        };
        if data.len() as u64 > max_bytes {
            return Err(ToolError::file_too_large(
                path.as_str(),
                data.len() as u64,
                max_bytes,
            ));
        }
        let meta = ex
            .git
            .commit_meta(&repo_dir, &oid)
            .await
            .map_err(|e| ex.map_git(e, "git"))?;
        commit_full = oid.to_string();
        source = source.at_commit(&commit_full, meta.time);
        data
    } else {
        commit_full = snap.commit.to_string();
        match snap.index.get(&path) {
            None => {
                if snap.index.is_dir(&path) {
                    return Err(ToolError::not_a_file(path.as_str()));
                }
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
            Some(entry) => {
                if entry.kind == EntryKind::Submodule {
                    return Err(ToolError::new(
                        super::errors::ErrorCode::NotAFile,
                        format!(
                            "{} is a submodule; submodules are not followed.",
                            path.as_str()
                        ),
                    ));
                }
                if entry.kind == EntryKind::File && entry.size > max_bytes {
                    return Err(ToolError::file_too_large(
                        path.as_str(),
                        entry.size,
                        max_bytes,
                    ));
                }
            }
        }
        let data = read_worktree(&snap, &path, max_bytes).await?;
        if data.len() as u64 > max_bytes {
            return Err(ToolError::file_too_large(
                path.as_str(),
                data.len() as u64,
                max_bytes,
            ));
        }
        data
    };

    let size = bytes.len() as u64;
    if bytes[..bytes.len().min(BINARY_SNIFF_BYTES)].contains(&0) {
        return Err(ToolError::binary_file(path.as_str(), size));
    }
    let text = String::from_utf8_lossy(&bytes);
    let all_lines = split_lines(&text);
    let total = all_lines.len();
    let offset = p.offset as usize;
    if offset > total && !(total == 0 && offset == 1) {
        return Err(ToolError::offset_out_of_range(total, offset));
    }
    let from = offset - 1;
    let to = (from + p.limit as usize).min(total);

    let mut red = Redaction::new(&snap.redactor);
    let mut cut_any = false;
    let mut lines: Vec<String> = all_lines[from..to]
        .iter()
        .map(|l| {
            let masked = red.apply(l);
            let (cut, was_cut) = cut_line(&masked, ex.cfg.limits.max_line_chars);
            cut_any |= was_cut;
            cut.into_owned()
        })
        .collect();

    let host = state.cfg.host;
    let repo_path = state.cfg.path.clone();
    let build = |items: &[String]| {
        let end_line = offset + items.len() - 1;
        to_value(&Output {
            source: source.clone(),
            path: path.as_str().to_owned(),
            start_line: offset,
            end_line,
            total_lines: total,
            size,
            content: items.join("\n"),
            permalink: permalink(
                host,
                &repo_path,
                &commit_full,
                path.as_str(),
                offset,
                end_line,
            ),
        })
    };
    let (structured, fitted) =
        fit_response(&mut lines, build, ex.cfg.limits.max_response_bytes / 2);

    let mut notices = Notices::default();
    if cut_any {
        notices.push(Notice::output_truncated(
            "max_line_chars",
            "Some lines were cut; use grep with a narrow pattern to see the rest of a long line.",
        ));
    }
    if fitted {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "Fewer lines were returned than asked; continue with a higher offset.",
        ));
    }
    notices.push_opt(stale_notice(&ex.cfg, &state));
    notices.push_opt(red.notice());

    let end_line = if lines.is_empty() {
        offset - 1
    } else {
        offset + lines.len() - 1
    };
    let mut out = format!(
        "{}@{} {} lines {}-{} of {total}\n",
        source.repo,
        &source.commit[..source.commit.len().min(7)],
        path.as_str(),
        offset,
        end_line
    );
    for (i, line) in lines.iter().enumerate() {
        out.push_str(&format!("{}\t{line}\n", offset + i));
    }
    let mut log = LogInfo::default();
    log.repo(&source);
    Ok(ToolOutput::new(structured, out)
        .with_notices(notices)
        .with_log(log))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lines_keep_cr_and_ignore_trailing_newline() {
        assert_eq!(split_lines("a\r\nb\n"), vec!["a\r", "b"]);
        assert_eq!(split_lines("a\nb"), vec!["a", "b"]);
        assert_eq!(split_lines("a\n\n"), vec!["a", ""]);
        assert!(split_lines("").is_empty());
    }
}
