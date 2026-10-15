//! `glob`: gitignore-style file matching served from the in-memory index.

use globset::GlobBuilder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::caps::{fit_response, human_size};
use super::envelope::{LogInfo, Notice, Notices, Source, ToolOutput, stale_notice, to_value};
use super::errors::ToolError;
use crate::auth::AuthContext;
use crate::snapshot::EntryKind;

const MAX_PATTERN_CHARS: usize = 512;

fn default_max_results() -> u32 {
    200
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Repo id.
    pub repo: String,
    /// Glob such as src/**/*.tsx, up to 512 characters. Without a slash, such as *.tsx, it matches file names at any depth.
    #[schemars(length(max = 512))]
    pub pattern: String,
    /// Restrict to this subdirectory; the pattern is matched relative to it.
    #[serde(default)]
    pub path: String,
    /// Match case-insensitively.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Maximum files returned, 1 to 2000, sorted by path.
    #[serde(default = "default_max_results")]
    #[schemars(range(min = 1, max = 2000))]
    pub max_results: u32,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct FileHit {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub source: Source,
    pub files: Vec<FileHit>,
    pub total_matched: usize,
}

/// A pattern without `/` and `**` matches basenames anywhere.
fn effective_pattern(pattern: &str) -> String {
    let trimmed = pattern.strip_prefix("./").unwrap_or(pattern);
    if let Some(anchored) = trimmed.strip_prefix('/') {
        return anchored.to_owned();
    }
    if !trimmed.contains('/') && !trimmed.contains("**") {
        format!("**/{trimmed}")
    } else {
        trimmed.to_owned()
    }
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    if p.pattern.is_empty() {
        return Err(ToolError::invalid_argument("pattern must not be empty."));
    }
    if p.pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(ToolError::invalid_argument(format!(
            "pattern is longer than {MAX_PATTERN_CHARS} characters."
        )));
    }
    if !(1..=2000).contains(&p.max_results) {
        return Err(ToolError::invalid_argument(format!(
            "max_results must be between 1 and 2000; you passed {}.",
            p.max_results
        )));
    }
    let (state, snap) = ex.resolve_repo(auth, &p.repo)?;
    let base = ex.parse_path(&p.path)?;
    ex.check_allowed(&base)?;
    if snap.index.get(&base).is_some() {
        return Err(ToolError::not_a_directory(base.as_str()));
    }
    if !snap.index.is_dir(&base) {
        return Err(ToolError::path_not_found(
            base.as_str(),
            &p.repo,
            snap.commit.short(),
            &[],
        ));
    }
    let matcher = GlobBuilder::new(&effective_pattern(&p.pattern))
        .case_insensitive(p.case_insensitive)
        .literal_separator(true)
        .build()
        .map_err(|e| {
            ToolError::invalid_pattern(format!("Invalid glob {:?}: {}.", p.pattern, e.kind()))
        })?
        .compile_matcher();

    let prefix_len = if base.is_root() {
        0
    } else {
        base.as_str().len() + 1
    };
    let mut files = Vec::new();
    let mut total = 0usize;
    for entry in snap.index.iter() {
        if entry.kind == EntryKind::Submodule || !entry.path.starts_with(&base) {
            continue;
        }
        let rel = &entry.path.as_str()[prefix_len.min(entry.path.as_str().len())..];
        if rel.is_empty() || !matcher.is_match(rel) || ex.deny.is_denied(&entry.path) {
            continue;
        }
        total += 1;
        if files.len() < p.max_results as usize {
            files.push(FileHit {
                path: entry.path.as_str().to_owned(),
                size: entry.size,
            });
        }
    }

    let source = ex.source(&state, &snap);
    let (structured, cut) = fit_response(
        &mut files,
        |items| {
            to_value(&Output {
                source: source.clone(),
                files: items.to_vec(),
                total_matched: total,
            })
        },
        ex.cfg.limits.max_response_bytes / 2,
    );
    let mut notices = Notices::default();
    if total > p.max_results as usize {
        notices.push(Notice::output_truncated(
            "max_results",
            "Narrow the pattern or path, or raise max_results (max 2000).",
        ));
    }
    if cut {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "Narrow the pattern or path.",
        ));
    }
    notices.push_opt(stale_notice(&ex.cfg, &state));
    let mut text = format!(
        "{}@{} glob {:?}: {total} matched, {} shown\n",
        source.repo,
        &source.commit[..source.commit.len().min(7)],
        p.pattern,
        files.len()
    );
    for f in &files {
        text.push_str(&format!("{}  {}\n", f.path, human_size(f.size)));
    }
    let mut log = LogInfo::default();
    log.repo(&source);
    log.matches = Some(total as u64);
    Ok(ToolOutput::new(structured, text)
        .with_notices(notices)
        .with_log(log))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::effective_pattern;

    #[test]
    fn bare_patterns_match_anywhere() {
        assert_eq!(effective_pattern("*.tsx"), "**/*.tsx");
        assert_eq!(effective_pattern("src/*.ts"), "src/*.ts");
        assert_eq!(effective_pattern("**/x"), "**/x");
        assert_eq!(effective_pattern("/README.md"), "README.md");
    }
}
