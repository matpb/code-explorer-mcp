//! `list_tree`: breadth-first directory listing served from the in-memory index.

use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::Explorer;
use super::caps::{cut_line, fit_response, human_size};
use super::envelope::{
    LogInfo, Notice, Notices, Redaction, Source, ToolOutput, stale_notice, to_value,
};
use super::errors::ToolError;
use crate::auth::AuthContext;
use crate::paths::RepoPath;
use crate::snapshot::{ChildKind, Snapshot};

const TARGET_MAX_CHARS: usize = 1024;

fn default_depth() -> u32 {
    2
}

fn default_max_entries() -> u32 {
    500
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Repo id.
    pub repo: String,
    /// Directory to start from, relative to the repo root. Empty means the root.
    #[serde(default)]
    pub path: String,
    /// Levels below path to list, 1 to 6.
    #[serde(default = "default_depth")]
    #[schemars(range(min = 1, max = 6))]
    pub depth: u32,
    /// Maximum entries returned, 1 to 2000. Listing is breadth-first.
    #[serde(default = "default_max_entries")]
    #[schemars(range(min = 1, max = 2000))]
    pub max_entries: u32,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Entry {
    pub path: String,
    /// file, dir, symlink or submodule.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Link text of a symlink; never followed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// For directories: true when the listing stops here although the directory has children.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Output {
    pub source: Source,
    pub path: String,
    pub entries: Vec<Entry>,
}

fn render(source: &Source, path: &str, depth: u32, entries: &[Entry]) -> String {
    let mut out = format!(
        "{}@{} {} (depth {depth}, {} entries)\n",
        source.repo,
        &source.commit[..source.commit.len().min(7)],
        if path.is_empty() { "/" } else { path },
        entries.len()
    );
    for e in entries {
        match e.kind.as_str() {
            "dir" => {
                let more = if e.children_truncated == Some(true) {
                    "  (more below)"
                } else {
                    ""
                };
                out.push_str(&format!("dir      {}/{more}\n", e.path));
            }
            "symlink" => out.push_str(&format!(
                "symlink  {} -> {}\n",
                e.path,
                e.target.as_deref().unwrap_or("?")
            )),
            "submodule" => out.push_str(&format!("submodule {}\n", e.path)),
            _ => out.push_str(&format!(
                "file     {}  {}\n",
                e.path,
                human_size(e.size.unwrap_or(0))
            )),
        }
    }
    out
}

struct Walk {
    entries: Vec<Entry>,
    truncated: bool,
}

fn walk(ex: &Explorer, snap: &Snapshot, start: &RepoPath, depth: u32, max_entries: usize) -> Walk {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut queue: VecDeque<(RepoPath, u32)> = VecDeque::from([(start.clone(), 1)]);
    'walk: while let Some((dir, level)) = queue.pop_front() {
        for child in snap.index.children_ref(&dir) {
            if ex.deny.is_denied(&child.path) {
                continue;
            }
            if entries.len() >= max_entries {
                truncated = true;
                break 'walk;
            }
            let path = child.path.as_str().to_owned();
            let entry = match child.kind {
                ChildKind::Dir => {
                    let at_edge = level >= depth;
                    let has_children = at_edge
                        && snap
                            .index
                            .children_ref(&child.path)
                            .iter()
                            .any(|c| !ex.deny.is_denied(&c.path));
                    if !at_edge {
                        queue.push_back((child.path.clone(), level + 1));
                    }
                    Entry {
                        path,
                        kind: "dir".into(),
                        size: None,
                        target: None,
                        children_truncated: Some(has_children),
                    }
                }
                ChildKind::File => Entry {
                    path,
                    kind: "file".into(),
                    size: child.size,
                    target: None,
                    children_truncated: None,
                },
                ChildKind::Symlink => Entry {
                    path,
                    kind: "symlink".into(),
                    size: None,
                    target: None,
                    children_truncated: None,
                },
                ChildKind::Submodule => Entry {
                    path,
                    kind: "submodule".into(),
                    size: None,
                    target: None,
                    children_truncated: None,
                },
            };
            entries.push(entry);
        }
    }
    Walk { entries, truncated }
}

pub async fn run(ex: &Explorer, auth: &AuthContext, p: Params) -> Result<ToolOutput, ToolError> {
    if !(1..=6).contains(&p.depth) {
        return Err(ToolError::invalid_argument(format!(
            "depth must be between 1 and 6; you passed {}.",
            p.depth
        )));
    }
    if !(1..=2000).contains(&p.max_entries) {
        return Err(ToolError::invalid_argument(format!(
            "max_entries must be between 1 and 2000; you passed {}.",
            p.max_entries
        )));
    }
    let (state, snap) = ex.resolve_repo(auth, &p.repo)?;
    let start = ex.parse_path(&p.path)?;
    ex.check_allowed(&start)?;
    if snap.index.get(&start).is_some() {
        return Err(ToolError::not_a_directory(start.as_str()));
    }
    if !snap.index.is_dir(&start) {
        return Err(ToolError::path_not_found(
            start.as_str(),
            &p.repo,
            snap.commit.short(),
            &[],
        ));
    }

    let Walk {
        mut entries,
        truncated,
    } = walk(ex, &snap, &start, p.depth, p.max_entries as usize);

    let link_paths: Vec<RepoPath> = entries
        .iter()
        .filter(|e| e.kind == "symlink")
        .filter_map(|e| RepoPath::parse(&e.path).ok())
        .collect();
    let mut red = Redaction::new(&snap.redactor);
    let mut notices = Notices::default();
    for path in link_paths {
        let text = match super::read_worktree(&snap, &path, TARGET_MAX_CHARS as u64 * 4).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).trim_end().to_owned(),
            Err(_) => continue,
        };
        let redacted = red.apply(&text);
        let (cut, _) = cut_line(&redacted, TARGET_MAX_CHARS);
        if let Some(e) = entries.iter_mut().find(|e| e.path == path.as_str()) {
            e.target = Some(cut.into_owned());
        }
    }

    let source = ex.source(&state, &snap);
    let budget = ex.cfg.limits.max_response_bytes / 2;
    let (structured, cut) = fit_response(
        &mut entries,
        |items| {
            to_value(&Output {
                source: source.clone(),
                path: start.as_str().to_owned(),
                entries: items.to_vec(),
            })
        },
        budget,
    );
    if truncated {
        notices.push(Notice::output_truncated(
            "max_entries",
            "Raise max_entries (max 2000), lower depth, or list a subdirectory with path.",
        ));
    }
    if cut {
        notices.push(Notice::output_truncated(
            "max_response_bytes",
            "List a subdirectory with path or lower depth.",
        ));
    }
    notices.push_opt(stale_notice(&ex.cfg, &state));
    notices.push_opt(red.notice());
    let text = render(&source, start.as_str(), p.depth, &entries);
    let mut log = LogInfo::default();
    log.repo(&source);
    Ok(ToolOutput::new(structured, text)
        .with_notices(notices)
        .with_log(log))
}
