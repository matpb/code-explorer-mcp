//! `grep`: ripgrep over the worktrees of one or several repos, run in parallel under the worker cap.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::StreamExt;
use futures::stream;
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

/// Cap on the ripgrep stdout buffered per repo.
const RG_STDOUT_CAP: usize = 16 * 1024 * 1024;

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

/// One context line around a match, with its real line number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CtxLine {
    pub line: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MatchOut {
    pub repo: String,
    pub path: String,
    pub line: u64,
    pub text: String,
    pub before: Vec<CtxLine>,
    pub after: Vec<CtxLine>,
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
    /// repo_not_ready, timeout or busy.
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
    pub before: Vec<(u64, String)>,
    pub after: Vec<(u64, String)>,
}

#[derive(Debug, Default)]
struct RepoHits {
    matches: Vec<RawMatch>,
    files: Vec<(String, Option<u64>)>,
    seen: u64,
    stdout_truncated: bool,
    file_capped: bool,
    /// Matches were found beyond the `keep` bound.
    trimmed: bool,
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

/// What `parse_json` keeps and counts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JsonOpts {
    pub before: u32,
    pub after: u32,
    /// Matches kept (the first by path and line); every allowed match is still counted.
    pub keep: usize,
    pub max_per_file: u32,
}

#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub matches: Vec<RawMatch>,
    /// Matches in files that passed the filter.
    pub seen: u64,
    /// Some file reached `max_per_file` matches.
    pub file_capped: bool,
}

/// Every line rg reported for one file (matches and context), by line number.
struct FileBlock {
    path: String,
    allowed: bool,
    matches: Vec<u64>,
    lines: BTreeMap<u64, String>,
}

impl Parsed {
    fn sort_and_trim(&mut self, keep: usize) {
        self.matches
            .sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
        self.matches.truncate(keep);
    }

    fn finish(&mut self, block: FileBlock, o: &JsonOpts) {
        if !block.allowed || block.matches.is_empty() {
            return;
        }
        self.seen += block.matches.len() as u64;
        self.file_capped |= block.matches.len() as u64 >= u64::from(o.max_per_file);
        let ctx = |range: std::ops::RangeInclusive<u64>| -> Vec<(u64, String)> {
            range
                .filter_map(|n| block.lines.get(&n).map(|t| (n, t.clone())))
                .collect()
        };
        for &line in &block.matches {
            let Some(text) = block.lines.get(&line) else {
                continue;
            };
            let lo = line.saturating_sub(u64::from(o.before)).max(1);
            self.matches.push(RawMatch {
                path: block.path.clone(),
                line,
                text: text.clone(),
                before: if lo < line {
                    ctx(lo..=line - 1)
                } else {
                    Vec::new()
                },
                after: ctx(line + 1..=line + u64::from(o.after)),
            });
        }
        if self.matches.len() > o.keep.saturating_mul(2).max(64) {
            self.sort_and_trim(o.keep);
        }
    }
}

/// Parses `rg --json` output; a trailing partial line (output cap) is ignored.
/// Files for which `allow(path)` is false are neither kept nor counted.
pub(crate) fn parse_json(stdout: &[u8], o: JsonOpts, allow: &dyn Fn(&str) -> bool) -> Parsed {
    let mut out = Parsed::default();
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
                    out.finish(done, &o);
                }
                if let Some(path) = data.get("path").and_then(decode_text) {
                    let path = clean_path(&path).to_owned();
                    current = Some(FileBlock {
                        allowed: allow(&path),
                        path,
                        matches: Vec::new(),
                        lines: BTreeMap::new(),
                    });
                }
            }
            Some(kind @ ("match" | "context")) => {
                let Some(block) = current.as_mut().filter(|b| b.allowed) else {
                    continue;
                };
                let (Some(line), Some(text)) = (
                    data["line_number"].as_u64(),
                    data.get("lines").and_then(decode_text),
                ) else {
                    continue;
                };
                if kind == "match" {
                    block.matches.push(line);
                }
                block.lines.insert(line, trim_eol(&text));
            }
            Some("end") => {
                if let Some(done) = current.take() {
                    out.finish(done, &o);
                }
            }
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        out.finish(done, &o);
    }
    out.sort_and_trim(o.keep);
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
    cmd.args(["--encoding", "none"]);
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
    for g in ex.deny.rg_globs_safe() {
        cmd.arg("--iglob").arg(g);
    }
    cmd.args(["--iglob", "!.git", "--iglob", "!**/.git"]);
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
    let _permit = ex.workers.acquire().await.map_err(|_| {
        ex.metrics.queue_rejection();
        RepoFail::Busy
    })?;
    let cmd = rg_command(ex, &snap, p, search_path);
    let output = match proc::run_capped(cmd, ex.cfg.limits.rg_timeout, "rg", RG_STDOUT_CAP).await {
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
    let allow = |path: &str| {
        RepoPath::parse(path).is_ok_and(|rp| !ex.deny.is_denied(&rp) && !snap.index.is_utf16(&rp))
    };
    let mut hits = RepoHits {
        stdout_truncated: output.stdout_truncated,
        ..Default::default()
    };
    match p.output {
        Mode::Content => {
            let parsed = parse_json(
                &output.stdout,
                JsonOpts {
                    before: p.context_before,
                    after: p.context_after,
                    keep: p.max_results as usize,
                    max_per_file: p.max_per_file,
                },
                &allow,
            );
            hits.trimmed = parsed.seen > parsed.matches.len() as u64;
            hits.matches = parsed.matches;
            hits.seen = parsed.seen;
            hits.file_capped = parsed.file_capped;
        }
        Mode::Files => {
            hits.files = parse_plain(&output.stdout, false);
            hits.files.retain(|(path, _)| allow(path));
            hits.seen = hits.files.len() as u64;
        }
        Mode::Count => {
            hits.files = parse_plain(&output.stdout, true);
            hits.files.retain(|(path, _)| allow(path));
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

    let jobs: Vec<(usize, Arc<Snapshot>)> = ready
        .iter()
        .enumerate()
        .filter_map(|(i, t)| t.snap.clone().map(|snap| (i, snap)))
        .collect();
    let width = jobs.len().min(ex.workers.max_concurrent()).max(1);
    let mut results: Vec<(usize, Result<RepoHits, RepoFail>)> = stream::iter(jobs)
        .map(|(i, snap)| {
            let search_path = &search_path;
            let params = &p;
            async move { (i, search_repo(ex, snap, params, search_path).await) }
        })
        .buffer_unordered(width)
        .collect()
        .await;
    results.sort_by_key(|(i, _)| *i);

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
    let mut redacted_files: HashSet<(String, String)> = HashSet::new();
    let mut seen_total = 0u64;
    let mut timed_out = 0usize;
    let mut busy = 0usize;
    let mut cut_any = false;
    let mut per_file_capped = false;
    let mut trimmed = false;
    let mut log = LogInfo::default();
    let mut redacted = 0usize;
    let max_chars = ex.cfg.limits.max_line_chars;

    for (t, (_, result)) in ready.iter().zip(results) {
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
            Err(RepoFail::Busy) => {
                busy += 1;
                skipped.push(Skipped {
                    repo: state.cfg.id.clone(),
                    reason: "busy".into(),
                });
                continue;
            }
            Err(RepoFail::Error(e)) => return Err(e),
        };
        let source = ex.source(state, snap);
        log.repo(&source);
        sources.push(source);
        notices.push_opt(stale_notice(&ex.cfg, state).map(|n| n.for_repo(&state.cfg.id)));
        if hits.stdout_truncated {
            notices.push(Notice::output_truncated(
                "max_results (search output cap)",
                "The search produced more output than one search may buffer, so matches are missing; narrow with path, glob or type.",
            ));
        }
        seen_total += hits.seen;
        per_file_capped |= hits.file_capped;
        trimmed |= hits.trimmed;
        let mut red = Redaction::new(&snap.redactor);
        for m in hits.matches {
            let Ok(rp) = RepoPath::parse(&m.path) else {
                continue;
            };
            if snap.index.is_redacted(&rp) {
                redacted_files.insert((state.cfg.id.clone(), rp.as_str().to_owned()));
            }
            let mut shape = |s: &str| {
                let masked = red.apply(s);
                let (cut, was) = cut_line(&masked, max_chars);
                cut_any |= was;
                cut.into_owned()
            };
            let mut ctx = |lines: &[(u64, String)]| -> Vec<CtxLine> {
                lines
                    .iter()
                    .map(|(line, text)| CtxLine {
                        line: *line,
                        text: shape(text),
                    })
                    .collect()
            };
            let before = ctx(&m.before);
            let after = ctx(&m.after);
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
                before,
                after,
            });
        }
        let mut files = hits.files;
        files.sort();
        for (fp, count) in files {
            let Ok(rp) = RepoPath::parse(&fp) else {
                continue;
            };
            if snap.index.is_redacted(&rp) {
                redacted_files.insert((state.cfg.id.clone(), rp.as_str().to_owned()));
            }
            all_files.push(FileOut {
                repo: state.cfg.id.clone(),
                path: rp.as_str().to_owned(),
                count,
            });
        }
        redacted += red.hits;
    }

    if sources.is_empty() {
        if timed_out > 0 {
            return Err(ToolError::timeout(ex.rg_timeout_message()));
        }
        if busy > 0 {
            return Err(ToolError::busy());
        }
    }

    let cap = p.max_results as usize;
    let before_cap = all_matches.len().max(all_files.len());
    all_matches.truncate(cap);
    all_files.truncate(cap);
    if before_cap > cap || trimmed {
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
    let served: HashSet<(&str, &str)> = all_matches
        .iter()
        .map(|m| (m.repo.as_str(), m.path.as_str()))
        .chain(all_files.iter().map(|f| (f.repo.as_str(), f.path.as_str())))
        .collect();
    let files_redacted = redacted_files
        .iter()
        .filter(|(r, p)| served.contains(&(r.as_str(), p.as_str())))
        .count();
    if redacted + files_redacted > 0 {
        notices.push(Notice::secrets_redacted(redacted.max(files_redacted)));
    }

    let mut text = String::new();
    for m in &all_matches {
        for c in &m.before {
            text.push_str(&format!("{}:{}-{}- {}\n", m.repo, m.path, c.line, c.text));
        }
        text.push_str(&format!("{}:{}:{}: {}\n", m.repo, m.path, m.line, m.text));
        for c in &m.after {
            text.push_str(&format!("{}:{}-{}- {}\n", m.repo, m.path, c.line, c.text));
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
        let got = parse_json(lines.as_bytes(), opts(1, 1, 10), &|_| true);
        assert_eq!(got.matches.len(), 1);
        assert_eq!(got.seen, 1);
        let m = &got.matches[0];
        assert_eq!(m.path, "a.txt");
        assert_eq!(m.line, 2);
        assert_eq!(m.text, "two foo");
        assert_eq!(m.before, vec![(1, "one".to_owned())]);
        assert_eq!(m.after, vec![(3, "three".to_owned())]);
    }

    fn opts(before: u32, after: u32, keep: usize) -> JsonOpts {
        JsonOpts {
            before,
            after,
            keep,
            max_per_file: 20,
        }
    }

    fn rg_file(path: &str, rows: &[(&str, u64, &str)]) -> String {
        let mut out = vec![format!(
            r#"{{"type":"begin","data":{{"path":{{"text":"{path}"}}}}}}"#
        )];
        for (kind, n, text) in rows {
            out.push(format!(
                r#"{{"type":"{kind}","data":{{"path":{{"text":"{path}"}},"lines":{{"text":"{text}\n"}},"line_number":{n}}}}}"#
            ));
        }
        out.push(format!(
            r#"{{"type":"end","data":{{"path":{{"text":"{path}"}}}}}}"#
        ));
        out.join("\n")
    }

    #[test]
    fn adjacent_matches_are_context_of_each_other_with_line_numbers() {
        let input = rg_file(
            "a.txt",
            &[
                ("context", 1, "zero"),
                ("match", 2, "foo one"),
                ("match", 3, "foo two"),
                ("context", 4, "after"),
            ],
        );
        let got = parse_json(input.as_bytes(), opts(2, 2, 10), &|_| true);
        assert_eq!(got.seen, 2);
        let (first, second) = (&got.matches[0], &got.matches[1]);
        assert_eq!(first.before, vec![(1, "zero".to_owned())]);
        assert_eq!(
            first.after,
            vec![(3, "foo two".to_owned()), (4, "after".to_owned())]
        );
        assert_eq!(
            second.before,
            vec![(1, "zero".to_owned()), (2, "foo one".to_owned())]
        );
        assert_eq!(second.after, vec![(4, "after".to_owned())]);
    }

    #[test]
    fn filtered_files_are_neither_kept_nor_counted() {
        let input = [
            rg_file("ok.txt", &[("match", 1, "foo")]),
            rg_file(".ENV", &[("match", 1, "foo"), ("match", 2, "foo")]),
        ]
        .join("\n");
        let allow = |p: &str| p != ".ENV";
        let got = parse_json(input.as_bytes(), opts(0, 0, 10), &allow);
        assert_eq!(got.seen, 1);
        assert_eq!(got.matches.len(), 1);
        assert_eq!(got.matches[0].path, "ok.txt");
    }

    #[test]
    fn keep_bounds_matches_but_not_the_count() {
        let mut input = Vec::new();
        for f in (0..200).rev() {
            input.push(rg_file(&format!("f{f:03}.txt"), &[("match", 1, "foo")]));
        }
        let got = parse_json(input.join("\n").as_bytes(), opts(0, 0, 3), &|_| true);
        assert_eq!(got.seen, 200);
        let paths: Vec<&str> = got.matches.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(paths, ["f000.txt", "f001.txt", "f002.txt"]);
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
