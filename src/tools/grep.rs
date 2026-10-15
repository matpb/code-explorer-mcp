//! `grep`: ripgrep over the worktrees of one or several repos, run in parallel under the worker cap.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::future::join_all;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Explorer;
use super::caps::{cut_line, fit_response};
use super::envelope::{
    LogInfo, Notice, Notices, Redaction, Source, ToolOutput, stale_notice, to_value,
};
use super::errors::ToolError;
use super::permalink;
use crate::auth::AuthContext;
use crate::paths::RepoPath;
use crate::proc::{self, ProcError};
use crate::snapshot::{RepoState, Snapshot};

fn default_max_results() -> u32 {
    100
}

fn default_max_per_file() -> u32 {
    20
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
pub enum Case {
    /// Case-insensitive unless the pattern has an uppercase letter.
    #[default]
    Smart,
    /// Exact case.
    Sensitive,
    /// Ignore case.
    Insensitive,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
pub enum Mode {
    /// Matching lines with context.
    #[default]
    Content,
    /// Only the paths of files that match.
    Files,
    /// Match counts per file.
    Count,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Regex (Rust syntax), up to 1000 characters.
    #[schemars(length(max = 1000))]
    pub pattern: String,
    /// Repo ids to search; default is every repo of the key. Up to 50.
    #[serde(default)]
    #[schemars(length(max = 50))]
    pub repos: Option<Vec<String>>,
    /// Restrict to this path; only valid when searching exactly one repo.
    #[serde(default)]
    pub path: String,
    /// Include globs; a leading ! excludes. Up to 20.
    #[serde(default)]
    #[schemars(length(max = 20))]
    pub glob: Vec<String>,
    /// ripgrep file types such as ts, rust, php. Up to 10.
    #[serde(default, rename = "type")]
    #[schemars(length(max = 10))]
    pub types: Vec<String>,
    /// Treat the pattern as a literal string.
    #[serde(default)]
    pub fixed_strings: bool,
    #[serde(default)]
    pub case: Case,
    /// Match whole words only.
    #[serde(default)]
    pub word: bool,
    /// Context lines before each match, 0 to 10.
    #[serde(default)]
    #[schemars(range(min = 0, max = 10))]
    pub context_before: u32,
    /// Context lines after each match, 0 to 10.
    #[serde(default)]
    #[schemars(range(min = 0, max = 10))]
    pub context_after: u32,
    #[serde(default)]
    pub output: Mode,
    /// Maximum matches (or files) returned overall, 1 to 1000.
    #[serde(default = "default_max_results")]
    #[schemars(range(min = 1, max = 1000))]
    pub max_results: u32,
    /// Maximum matches per file, 1 to 200.
    #[serde(default = "default_max_per_file")]
    #[schemars(range(min = 1, max = 200))]
    pub max_per_file: u32,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MatchOut {
    pub repo: String,
    pub path: String,
    pub line: u64,
    pub text: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub permalink: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct FileOut {
    pub repo: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Skipped {
    pub repo: String,
    /// repo_not_ready or timeout.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub sources: Vec<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<MatchOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileOut>>,
    pub total_matches_seen: u64,
    pub repos_skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawMatch {
    pub path: String,
    pub line: u64,
    pub text: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Debug, Default)]
struct RepoHits {
    matches: Vec<RawMatch>,
    files: Vec<(String, Option<u64>)>,
    seen: u64,
    stdout_truncated: bool,
}

enum RepoFail {
    Timeout,
    Busy,
    Error(ToolError),
}

fn decode_text(v: &Value) -> Option<String> {
    if let Some(t) = v.get("text").and_then(Value::as_str) {
        return Some(t.to_owned());
    }
    let bytes = BASE64.decode(v.get("bytes")?.as_str()?).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn trim_eol(s: &str) -> String {
    let s = s.strip_suffix('\n').unwrap_or(s);
    s.strip_suffix('\r').unwrap_or(s).to_owned()
}

fn clean_path(p: &str) -> &str {
    p.strip_prefix("./").unwrap_or(p)
}

struct FileBlock {
    path: String,
    matches: Vec<(u64, String)>,
    context: BTreeMap<u64, String>,
}

impl FileBlock {
    fn finish(self, before: u32, after: u32, out: &mut Vec<RawMatch>) {
        for (line, text) in self.matches {
            let lo = line.saturating_sub(u64::from(before));
            let b = (lo..line)
                .filter_map(|n| self.context.get(&n).cloned())
                .collect();
            let a = (line + 1..=line + u64::from(after))
                .filter_map(|n| self.context.get(&n).cloned())
                .collect();
            out.push(RawMatch {
                path: self.path.clone(),
                line,
                text,
                before: b,
                after: a,
            });
        }
    }
}

/// Parses `rg --json` output; a trailing partial line (output cap) is ignored.
pub(crate) fn parse_json(stdout: &[u8], before: u32, after: u32) -> Vec<RawMatch> {
    let mut out = Vec::new();
    let mut current: Option<FileBlock> = None;
    for raw in stdout.split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(raw) else {
            continue;
        };
        let data = &msg["data"];
        match msg["type"].as_str() {
            Some("begin") => {
                if let Some(done) = current.take() {
                    done.finish(before, after, &mut out);
                }
                if let Some(path) = data.get("path").and_then(decode_text) {
                    current = Some(FileBlock {
                        path: clean_path(&path).to_owned(),
                        matches: Vec::new(),
                        context: BTreeMap::new(),
                    });
                }
            }
            Some(kind @ ("match" | "context")) => {
                let (Some(block), Some(line), Some(text)) = (
                    current.as_mut(),
                    data["line_number"].as_u64(),
                    data.get("lines").and_then(decode_text),
                ) else {
                    continue;
                };
                if kind == "match" {
                    block.matches.push((line, trim_eol(&text)));
                } else {
                    block.context.insert(line, trim_eol(&text));
                }
            }
            Some("end") => {
                if let Some(done) = current.take() {
                    done.finish(before, after, &mut out);
                }
            }
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        done.finish(before, after, &mut out);
    }
    out
}

/// Parses `--null` output: `path\0` records for files mode, `path\0count\n` for count mode.
pub(crate) fn parse_plain(stdout: &[u8], counts: bool) -> Vec<(String, Option<u64>)> {
    let text = String::from_utf8_lossy(stdout);
    if counts {
        text.lines()
            .filter_map(|l| {
                let (path, n) = l.rsplit_once('\0')?;
                Some((clean_path(path).to_owned(), n.trim().parse().ok()))
            })
            .collect()
    } else {
        text.split('\0')
            .filter(|p| !p.is_empty())
            .map(|p| (clean_path(p.trim_matches('\n')).to_owned(), None))
            .collect()
    }
}

fn clean_rg_message(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(|l| l.strip_prefix("rg: ").unwrap_or(l))
        .filter(|l| !l.trim().is_empty())
        .collect();
    let joined = lines.join("\n");
    joined.chars().take(800).collect()
}

/// Maps a failed rg run to `Ok(())` for "no matches" or to the typed error.
pub(crate) fn classify_rg_failure(status: i32, stderr: &str) -> Result<(), ToolError> {
    if status == 1 {
        return Ok(());
    }
    let lower = stderr.to_ascii_lowercase();
    let message = clean_rg_message(stderr);
    if lower.contains("regex parse error") || lower.contains("error parsing regex") {
        return Err(ToolError::invalid_pattern(format!(
            "{}. For a literal search set fixed_strings: true.",
            message.trim_end_matches('.')
        )));
    }
    if lower.contains("exceeds size limit")
        || lower.contains("too large")
        || lower.contains("compiled regex exceeds")
    {
        return Err(ToolError::pattern_too_complex(format!(
            "{}. For a literal search set fixed_strings: true, or narrow the pattern.",
            message.trim_end_matches('.')
        )));
    }
    if lower.contains("unrecognized file type") || lower.contains("error parsing glob") {
        return Err(ToolError::invalid_argument(format!(
            "{}.",
            message.trim_end_matches('.')
        )));
    }
    Err(ToolError::internal(format!(
        "rg exited with status {status}: {message}"
    )))
}

fn rg_command(
    ex: &Explorer,
    snap: &Snapshot,
    p: &Params,
    search_path: &str,
) -> tokio::process::Command {
    let mut cmd = proc::scrubbed_command(ex.cfg.rg_bin());
    cmd.current_dir(&snap.root);
    cmd.args(["--no-config", "--hidden", "--no-ignore", "--no-follow"]);
    cmd.arg("--max-filesize")
        .arg(ex.cfg.limits.max_file_bytes.to_string());
    cmd.args(["--max-columns", "500", "--max-columns-preview"]);
    cmd.args(["--regex-size-limit", "1M", "--dfa-size-limit", "10M"]);
    match p.output {
        Mode::Content => {
            cmd.arg("--json")
                .arg("--max-count")
                .arg(p.max_per_file.to_string());
            if p.context_before > 0 {
                cmd.arg("-B").arg(p.context_before.to_string());
            }
            if p.context_after > 0 {
                cmd.arg("-A").arg(p.context_after.to_string());
            }
        }
        Mode::Files => {
            cmd.args(["--files-with-matches", "--null", "--with-filename"]);
        }
        Mode::Count => {
            cmd.args(["--count", "--null", "--with-filename"]);
        }
    }
    if p.fixed_strings {
        cmd.arg("-F");
    }
    if p.word {
        cmd.arg("-w");
    }
    cmd.arg(match p.case {
        Case::Smart => "-S",
        Case::Sensitive => "-s",
        Case::Insensitive => "-i",
    });
    for g in &p.glob {
        cmd.arg("-g").arg(g);
    }
    for g in ex.deny.rg_globs() {
        cmd.arg("-g").arg(g);
    }
    cmd.args(["-g", "!.git", "-g", "!**/.git"]);
    for t in &p.types {
        cmd.arg("-t").arg(t);
    }
    cmd.arg("-e").arg(&p.pattern).arg("--").arg(search_path);
    cmd
}

async fn search_repo(
    ex: &Explorer,
    snap: Arc<Snapshot>,
    p: &Params,
    search_path: &str,
) -> Result<RepoHits, RepoFail> {
    let _permit = ex.workers.acquire().await.map_err(|_| RepoFail::Busy)?;
    let cmd = rg_command(ex, &snap, p, search_path);
    let output = match proc::run(cmd, ex.cfg.limits.rg_timeout, "rg").await {
        Ok(out) => out,
        Err(ProcError::Timeout { .. }) => {
            ex.metrics.subprocess_timeout("rg");
            return Err(RepoFail::Timeout);
        }
        Err(ProcError::Busy) => return Err(RepoFail::Busy),
        Err(ProcError::Failed { status, stderr, .. }) => {
            classify_rg_failure(status, &stderr).map_err(RepoFail::Error)?;
            return Ok(RepoHits::default());
        }
        Err(e @ ProcError::Spawn(_)) => return Err(RepoFail::Error(ToolError::internal(e))),
    };
    let mut hits = RepoHits {
        stdout_truncated: output.stdout_truncated,
        ..Default::default()
    };
    match p.output {
        Mode::Content => {
            hits.matches = parse_json(&output.stdout, p.context_before, p.context_after);
            hits.seen = hits.matches.len() as u64;
        }
        Mode::Files => {
            hits.files = parse_plain(&output.stdout, false);
            hits.seen = hits.files.len() as u64;
        }
        Mode::Count => {
            hits.files = parse_plain(&output.stdout, true);
            hits.seen = hits.files.iter().filter_map(|(_, n)| *n).sum();
        }
    }
    Ok(hits)
}

fn validate(p: &Params) -> Result<(), ToolError> {
    let bad = |m: String| Err(ToolError::invalid_argument(m));
    if p.pattern.is_empty() {
        return bad("pattern must not be empty.".into());
    }
    if p.pattern.chars().count() > 1000 {
        return bad("pattern is longer than 1000 characters.".into());
    }
    if p.repos.as_ref().is_some_and(|r| r.len() > 50) {
        return bad("repos has more than 50 entries.".into());
    }
    if p.glob.len() > 20 {
        return bad("glob has more than 20 entries.".into());
    }
    if p.glob.iter().any(|g| g.is_empty() || g.len() > 512) {
        return bad("each glob must be 1 to 512 characters.".into());
    }
    if p.types.len() > 10 {
        return bad("type has more than 10 entries.".into());
    }
    if p.types.iter().any(|t| {
        t.is_empty()
            || !t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
    }) {
        return bad("type values must be ripgrep file type names such as ts or rust.".into());
    }
    if p.context_before > 10 || p.context_after > 10 {
        return bad("context_before and context_after must be at most 10.".into());
    }
    if !(1..=1000).contains(&p.max_results) {
        return bad(format!(
            "max_results must be between 1 and 1000; you passed {}.",
            p.max_results
        ));
    }
    if !(1..=200).contains(&p.max_per_file) {
        return bad(format!(
            "max_per_file must be between 1 and 200; you passed {}.",
            p.max_per_file
        ));
    }
    Ok(())
}

struct Target {
    state: Arc<RepoState>,
    snap: Option<Arc<Snapshot>>,
}

fn select_targets(
    ex: &Explorer,
    auth: &AuthContext,
    p: &Params,
) -> Result<Vec<Arc<RepoState>>, ToolError> {
    match p.repos.as_deref() {
        None | Some([]) => Ok(ex.registry.visible_to(auth.repos.as_deref())),
        Some(ids) => {
            let mut chosen = Vec::new();
            for id in ids {
                chosen.push(ex.resolve_state(auth, id)?);
            }
            Ok(ex
                .registry
                .iter()
                .filter(|s| chosen.iter().any(|c| c.cfg.id == s.cfg.id))
                .cloned()
                .collect())
        }
    }
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    validate(&p)?;
    let states = select_targets(ex, auth, &p)?;
    if states.is_empty() {
        return Err(ToolError::invalid_argument(
            "No repos are available to this key.",
        ));
    }
    let path = ex.parse_path(&p.path)?;
    if !path.is_root() && states.len() != 1 {
        return Err(ToolError::invalid_argument(format!(
            "path needs exactly one repo; you passed {}.",
            states.len()
        )));
    }
    ex.check_allowed(&path)?;

    let targets: Vec<Target> = states
        .into_iter()
        .map(|state| {
            let snap = state.snapshot();
            Target { state, snap }
        })
        .collect();
    let (ready, not_ready): (Vec<&Target>, Vec<&Target>) =
        targets.iter().partition(|t| t.snap.is_some());
    if ready.is_empty() {
        return Err(ex.not_ready(&not_ready[0].state));
    }
    if !path.is_root()
        && let Some(snap) = &ready[0].snap
        && snap.index.get(&path).is_none()
        && !snap.index.is_dir(&path)
    {
        return Err(ToolError::path_not_found(
            path.as_str(),
            &ready[0].state.cfg.id,
            snap.commit.short(),
            &[],
        ));
    }
    let search_path = if path.is_root() {
        ".".to_owned()
    } else {
        path.as_str().to_owned()
    };

    let runs = ready.iter().filter_map(|t| t.snap.as_ref()).map(|snap| {
        let snap = snap.clone();
        let search_path = search_path.clone();
        let params = &p;
        async move { search_repo(ex, snap, params, &search_path).await }
    });
    let results = join_all(runs).await;

    let mut skipped: Vec<Skipped> = not_ready
        .iter()
        .map(|t| Skipped {
            repo: t.state.cfg.id.clone(),
            reason: "repo_not_ready".into(),
        })
        .collect();
    let mut notices = Notices::default();
    let mut sources = Vec::new();
    let mut all_matches: Vec<MatchOut> = Vec::new();
    let mut all_files: Vec<FileOut> = Vec::new();
    let mut seen_total = 0u64;
    let mut timed_out = 0usize;
    let mut cut_any = false;
    let mut per_file_capped = false;
    let mut log = LogInfo::default();
    let mut redacted = 0usize;
    let max_chars = ex.cfg.limits.max_line_chars;

    for (t, result) in ready.iter().zip(results) {
        let (Some(snap), state) = (t.snap.as_ref(), &t.state) else {
            continue;
        };
        let hits = match result {
            Ok(h) => h,
            Err(RepoFail::Timeout) => {
                timed_out += 1;
                skipped.push(Skipped {
                    repo: state.cfg.id.clone(),
                    reason: "timeout".into(),
                });
                continue;
            }
            Err(RepoFail::Busy) => return Err(ToolError::busy()),
            Err(RepoFail::Error(e)) => return Err(e),
        };
        let source = ex.source(state, snap);
        log.repo(&source);
        sources.push(source);
        notices.push_opt(stale_notice(&ex.cfg, state).map(|n| n.for_repo(&state.cfg.id)));
        if hits.stdout_truncated {
            notices.push(Notice::output_truncated(
                "search output cap",
                "Narrow with path, glob or type.",
            ));
        }
        seen_total += hits.seen;
        let mut red = Redaction::new(&snap.redactor);
        let mut kept = hits.matches;
        if p.output == Mode::Content {
            let mut per_file: BTreeMap<&str, u32> = BTreeMap::new();
            for m in &kept {
                *per_file.entry(m.path.as_str()).or_default() += 1;
            }
            per_file_capped |= per_file.values().any(|n| *n >= p.max_per_file);
        }
        kept.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
        for m in kept {
            let Ok(rp) = RepoPath::parse(&m.path) else {
                continue;
            };
            if ex.deny.is_denied(&rp) {
                continue;
            }
            let mut shape = |s: &str| {
                let masked = red.apply(s);
                let (cut, was) = cut_line(&masked, max_chars);
                cut_any |= was;
                cut.into_owned()
            };
            all_matches.push(MatchOut {
                repo: state.cfg.id.clone(),
                permalink: permalink(
                    state.cfg.host,
                    &state.cfg.path,
                    snap.commit.as_str(),
                    rp.as_str(),
                    m.line as usize,
                    m.line as usize,
                ),
                path: rp.as_str().to_owned(),
                line: m.line,
                text: shape(&m.text),
                before: m.before.iter().map(|s| shape(s)).collect(),
                after: m.after.iter().map(|s| shape(s)).collect(),
            });
        }
        let mut files = hits.files;
        files.sort();
        for (fp, count) in files {
            let Ok(rp) = RepoPath::parse(&fp) else {
                continue;
            };
            if ex.deny.is_denied(&rp) {
                continue;
            }
            all_files.push(FileOut {
                repo: state.cfg.id.clone(),
                path: rp.as_str().to_owned(),
                count,
            });
        }
        redacted += red.hits;
    }

    if sources.is_empty() && timed_out > 0 {
        return Err(ToolError::timeout(ex.rg_timeout_message()));
    }

    let cap = p.max_results as usize;
    let before_cap = all_matches.len().max(all_files.len());
    all_matches.truncate(cap);
    all_files.truncate(cap);
    if before_cap > cap {
        notices.push(Notice::output_truncated(
            "max_results",
            "Narrow with path, glob or type, or raise max_results (max 1000).",
        ));
    }
    if per_file_capped {
        notices.push(Notice::output_truncated(
            "max_per_file",
            "A file has at least max_per_file matches; raise max_per_file (max 200) or narrow the pattern.",
        ));
    }
    if cut_any {
        notices.push(Notice::output_truncated(
            "max_line_chars",
            "Some lines were cut; read_file with a line range shows the full text.",
        ));
    }
    if redacted > 0 {
        notices.push(Notice::secrets_redacted(redacted));
    }

    let budget = ex.cfg.limits.max_response_bytes / 2;
    let skipped_ref = &skipped;
    let sources_ref = &sources;
    let (structured, fitted) = match p.output {
        Mode::Content => fit_response(
            &mut all_matches,
            |items| {
                to_value(&Output {
                    sources: sources_ref.clone(),
                    matches: Some(items.to_vec()),
                    files: None,
                    total_matches_seen: seen_total,
                    repos_skipped: skipped_ref.clone(),
                })
            },
            budget,
        ),
        Mode::Files | Mode::Count => fit_response(
            &mut all_files,
            |items| {
                to_value(&Output {
                    sources: sources_ref.clone(),
                    matches: None,
                    files: Some(items.to_vec()),
                    total_matches_seen: seen_total,
                    repos_skipped: skipped_ref.clone(),
                })
            },
            budget,
        ),
    };
    if fitted {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "Narrow with path, glob or type, or lower context_before and context_after.",
        ));
    }

    let mut text = String::new();
    for m in &all_matches {
        for (i, line) in m.before.iter().enumerate() {
            let n = m.line as usize - m.before.len() + i;
            text.push_str(&format!("{}:{}-{n}- {line}\n", m.repo, m.path));
        }
        text.push_str(&format!("{}:{}:{}: {}\n", m.repo, m.path, m.line, m.text));
        for (i, line) in m.after.iter().enumerate() {
            let n = m.line as usize + 1 + i;
            text.push_str(&format!("{}:{}-{n}- {line}\n", m.repo, m.path));
        }
    }
    for f in &all_files {
        match f.count {
            Some(c) => text.push_str(&format!("{}:{}: {c}\n", f.repo, f.path)),
            None => text.push_str(&format!("{}:{}\n", f.repo, f.path)),
        }
    }
    if text.is_empty() {
        text.push_str("No matches.\n");
    }
    for s in &skipped {
        text.push_str(&format!("skipped {}: {}\n", s.repo, s.reason));
    }
    log.matches = Some(seen_total);
    Ok(ToolOutput::new(structured, text)
        .with_notices(notices)
        .with_log(log))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::errors::ErrorCode;
    use super::*;

    #[test]
    fn json_parse_collects_context_around_matches() {
        let lines = [
            r#"{"type":"begin","data":{"path":{"text":"./a.txt"}}}"#,
            r#"{"type":"context","data":{"path":{"text":"./a.txt"},"lines":{"text":"one\n"},"line_number":1}}"#,
            r#"{"type":"match","data":{"path":{"text":"./a.txt"},"lines":{"text":"two foo\r\n"},"line_number":2,"submatches":[]}}"#,
            r#"{"type":"context","data":{"path":{"text":"./a.txt"},"lines":{"bytes":"dGhyZWU="},"line_number":3}}"#,
            r#"{"type":"end","data":{"path":{"text":"./a.txt"}}}"#,
            r#"{"type":"summary","data":{}}"#,
            r#"{"type":"begin","data":{"path":{"text":"b.txt"}}}"#,
            r#"{"type":"match","data":{"path":{"text":"b.txt"},"lines":{"text":"foo\n"},"line_number":9"#,
        ]
        .join("\n");
        let got = parse_json(lines.as_bytes(), 1, 1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "a.txt");
        assert_eq!(got[0].line, 2);
        assert_eq!(got[0].text, "two foo");
        assert_eq!(got[0].before, vec!["one"]);
        assert_eq!(got[0].after, vec!["three"]);
    }

    #[test]
    fn plain_parsers_handle_null_separators() {
        let files = parse_plain(b"./a.txt\0./b/c.txt\0", false);
        assert_eq!(
            files,
            vec![("a.txt".into(), None), ("b/c.txt".into(), None)]
        );
        let counts = parse_plain(b"./a.txt\x002\n./b.txt\x001\n", true);
        assert_eq!(
            counts,
            vec![("a.txt".into(), Some(2)), ("b.txt".into(), Some(1))]
        );
    }

    #[test]
    fn rg_failures_are_classified() {
        assert!(classify_rg_failure(1, "").is_ok());
        let e = classify_rg_failure(
            2,
            "rg: regex parse error:\n    (?:(abc)\n    ^\nerror: unclosed group",
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidPattern);
        assert!(e.message.contains("unclosed group"));
        assert!(
            e.message
                .ends_with("For a literal search set fixed_strings: true.")
        );
        let e =
            classify_rg_failure(2, "rg: compiled regex exceeds size limit of 1024").unwrap_err();
        assert_eq!(e.code, ErrorCode::PatternTooComplex);
        let e = classify_rg_failure(2, "rg: unrecognized file type: nosuch").unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        let e = classify_rg_failure(2, "rg: something else").unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
    }
}
