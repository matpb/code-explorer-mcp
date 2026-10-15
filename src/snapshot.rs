//! In-memory file index, immutable snapshots, per-repo pull state and the on-disk state file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{Config, RepoConfig};
use crate::git::{self, Oid, TreeKind};
use crate::paths::{PathError, RepoPath};
use crate::redact::Redactor;
use crate::scan::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Symlink,
    Submodule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub path: RepoPath,
    pub kind: EntryKind,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    File,
    Symlink,
    Submodule,
    Dir,
}

impl From<EntryKind> for ChildKind {
    fn from(kind: EntryKind) -> Self {
        match kind {
            EntryKind::File => ChildKind::File,
            EntryKind::Symlink => ChildKind::Symlink,
            EntryKind::Submodule => ChildKind::Submodule,
        }
    }
}

/// One direct child of a directory. `size` is set for files and symlinks only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexChild {
    pub path: RepoPath,
    pub kind: ChildKind,
    pub size: Option<u64>,
}

impl IndexChild {
    pub fn name(&self) -> &str {
        self.path.file_name().unwrap_or("")
    }
}

/// Every non-directory entry of a commit, with a precomputed child listing per directory.
#[derive(Debug, Default)]
pub struct FileIndex {
    entries: BTreeMap<RepoPath, TreeEntry>,
    dirs: BTreeMap<RepoPath, Vec<IndexChild>>,
}

impl FileIndex {
    /// Entries whose path fails `RepoPath::parse` are skipped with a warning.
    pub fn from_git(list: Vec<git::TreeEntry>) -> Result<FileIndex, PathError> {
        let mut entries = Vec::with_capacity(list.len());
        for e in list {
            let kind = match e.kind {
                TreeKind::Tree => continue,
                TreeKind::Blob => EntryKind::File,
                TreeKind::Symlink => EntryKind::Symlink,
                TreeKind::Submodule => EntryKind::Submodule,
            };
            match RepoPath::parse(&e.path) {
                Ok(path) if !path.is_root() => entries.push(TreeEntry {
                    path,
                    kind,
                    size: e.size.unwrap_or(0),
                }),
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "skipping tree entry with an unusable path");
                }
            }
        }
        Ok(Self::from_entries(entries))
    }

    pub fn from_entries(list: Vec<TreeEntry>) -> FileIndex {
        let entries: BTreeMap<RepoPath, TreeEntry> =
            list.into_iter().map(|e| (e.path.clone(), e)).collect();
        let mut dirs: BTreeMap<RepoPath, Vec<IndexChild>> = BTreeMap::new();
        dirs.entry(RepoPath::root()).or_default();
        for e in entries.values() {
            let mut child = IndexChild {
                path: e.path.clone(),
                kind: e.kind.into(),
                size: (e.kind != EntryKind::Submodule).then_some(e.size),
            };
            let mut cur = e.path.clone();
            while let Some(parent) = cur.parent() {
                let known = dirs.contains_key(&parent);
                dirs.entry(parent.clone()).or_default().push(child);
                if known {
                    break;
                }
                child = IndexChild {
                    path: parent.clone(),
                    kind: ChildKind::Dir,
                    size: None,
                };
                cur = parent;
            }
        }
        for list in dirs.values_mut() {
            list.sort_by(|a, b| {
                let key = |c: &IndexChild| (c.kind != ChildKind::Dir, c.name().to_owned());
                key(a).cmp(&key(b))
            });
        }
        FileIndex { entries, dirs }
    }

    pub fn get(&self, path: &RepoPath) -> Option<&TreeEntry> {
        self.entries.get(path)
    }

    /// True for the root and for any path that is a proper ancestor of an entry.
    pub fn is_dir(&self, path: &RepoPath) -> bool {
        self.dirs.contains_key(path)
    }

    /// Direct children, directories first, then by name.
    pub fn children(&self, dir: &RepoPath) -> Vec<IndexChild> {
        self.children_ref(dir).to_vec()
    }

    pub fn children_ref(&self, dir: &RepoPath) -> &[IndexChild] {
        self.dirs.get(dir).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn iter(&self) -> impl Iterator<Item = &TreeEntry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Up to `n` suggestions: same file name anywhere first, then the nearest paths by edit distance.
    pub fn close_matches(&self, target: &RepoPath, n: usize) -> Vec<RepoPath> {
        let Some(name) = target.file_name() else {
            return Vec::new();
        };
        if n == 0 {
            return Vec::new();
        }
        let tlen = target.as_str().len();
        let mut same: Vec<&RepoPath> = self
            .entries
            .keys()
            .filter(|p| *p != target && p.file_name() == Some(name))
            .collect();
        same.sort_by_key(|p| (p.as_str().len().abs_diff(tlen), p.as_str()));
        let mut out: Vec<RepoPath> = same.into_iter().take(n).cloned().collect();
        if out.len() >= n {
            return out;
        }
        let max = (tlen / 2).max(3);
        let mut near: Vec<(usize, &RepoPath)> = self
            .entries
            .keys()
            .filter(|p| *p != target && !out.contains(p))
            .filter_map(|p| {
                levenshtein_within(target.as_str().as_bytes(), p.as_str().as_bytes(), max)
                    .map(|d| (d, p))
            })
            .collect();
        near.sort();
        out.extend(near.into_iter().take(n - out.len()).map(|(_, p)| p.clone()));
        out
    }
}

/// Edit distance between `a` and `b`, or `None` when it exceeds `max`.
fn levenshtein_within(a: &[u8], b: &[u8], max: usize) -> Option<usize> {
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        let mut row_min = cur[0];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            row_min = row_min.min(cur[j + 1]);
        }
        if row_min > max {
            return None;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    let d = prev[b.len()];
    (d <= max).then_some(d)
}

/// One immutable view of a repo at a commit: the worktree on disk plus its index.
#[derive(Debug)]
pub struct Snapshot {
    pub commit: Oid,
    pub commit_time: DateTime<Utc>,
    pub commit_subject: String,
    pub root: PathBuf,
    pub index: FileIndex,
    pub redactor: Arc<Redactor>,
    pub findings: usize,
    pub pulled_at: DateTime<Utc>,
    pub remove_on_drop: AtomicBool,
}

impl Snapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commit: Oid,
        commit_time: DateTime<Utc>,
        commit_subject: String,
        root: PathBuf,
        index: FileIndex,
        redactor: Arc<Redactor>,
        findings: usize,
        pulled_at: DateTime<Utc>,
    ) -> Snapshot {
        Snapshot {
            commit,
            commit_time,
            commit_subject,
            root,
            index,
            redactor,
            findings,
            pulled_at,
            remove_on_drop: AtomicBool::new(false),
        }
    }

    /// The worktree directory is deleted when the last `Arc<Snapshot>` goes away.
    pub fn mark_remove_on_drop(&self) {
        self.remove_on_drop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if !self.remove_on_drop.load(Ordering::SeqCst) {
            return;
        }
        let root = self.root.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => drop(handle.spawn_blocking(move || remove_dir(&root))),
            Err(_) => remove_dir(&root),
        }
    }
}

fn remove_dir(root: &Path) {
    match std::fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "could not remove an old snapshot directory"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Auth,
    Network,
    Scan,
    SecretFound,
    Internal,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Auth => "auth",
            ErrorClass::Network => "network",
            ErrorClass::Scan => "scan",
            ErrorClass::SecretFound => "secret_found",
            ErrorClass::Internal => "internal",
        }
    }
}

impl From<git::ErrorClass> for ErrorClass {
    fn from(class: git::ErrorClass) -> Self {
        match class {
            git::ErrorClass::Auth => ErrorClass::Auth,
            git::ErrorClass::Network | git::ErrorClass::NotFound => ErrorClass::Network,
            git::ErrorClass::Internal => ErrorClass::Internal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PullError {
    pub class: ErrorClass,
    pub message: String,
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class.as_str(), self.message)
    }
}

impl std::error::Error for PullError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullStatus {
    pub last_success: Option<DateTime<Utc>>,
    pub last_attempt: Option<DateTime<Utc>>,
    pub last_error: Option<PullError>,
    pub consecutive_failures: u32,
    pub scan_held: bool,
    pub scan_findings: usize,
    pub initializing: bool,
    pub clone_started: Option<DateTime<Utc>>,
}

impl Default for PullStatus {
    fn default() -> Self {
        PullStatus {
            last_success: None,
            last_attempt: None,
            last_error: None,
            consecutive_failures: 0,
            scan_held: false,
            scan_findings: 0,
            initializing: true,
            clone_started: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoStatus {
    Ready,
    Stale,
    Initializing,
    Unavailable,
}

impl RepoStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoStatus::Ready => "ready",
            RepoStatus::Stale => "stale",
            RepoStatus::Initializing => "initializing",
            RepoStatus::Unavailable => "unavailable",
        }
    }
}

/// Live state of one configured repo: the served snapshot and the pull bookkeeping.
#[derive(Debug)]
pub struct RepoState {
    pub cfg: RepoConfig,
    pub current: ArcSwapOption<Snapshot>,
    pub status: Mutex<PullStatus>,
}

fn age(since: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    (now - since).to_std().unwrap_or(Duration::ZERO)
}

impl RepoState {
    pub fn new(cfg: RepoConfig) -> RepoState {
        RepoState {
            cfg,
            current: ArcSwapOption::empty(),
            status: Mutex::new(PullStatus::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PullStatus> {
        self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.current.load_full()
    }

    pub fn status(&self) -> PullStatus {
        self.lock().clone()
    }

    fn last_success_or_pulled(&self, st: &PullStatus) -> Option<DateTime<Utc>> {
        st.last_success
            .or_else(|| self.snapshot().map(|s| s.pulled_at))
    }

    pub fn status_word(&self, stale_after: Duration, now: DateTime<Utc>) -> RepoStatus {
        let st = self.lock();
        if self.current.load().is_none() {
            return if st.initializing {
                RepoStatus::Initializing
            } else {
                RepoStatus::Unavailable
            };
        }
        match self.last_success_or_pulled(&st) {
            Some(last) if age(last, now) > stale_after => RepoStatus::Stale,
            _ => RepoStatus::Ready,
        }
    }

    /// Seconds since the last successful pull when stale, else 0.
    pub fn stale_seconds(&self, stale_after: Duration, now: DateTime<Utc>) -> u64 {
        let st = self.lock();
        if self.current.load().is_none() {
            return 0;
        }
        match self.last_success_or_pulled(&st) {
            Some(last) if age(last, now) > stale_after => age(last, now).as_secs(),
            _ => 0,
        }
    }

    /// Publishes `snapshot` and returns the one it replaced.
    pub fn set_snapshot(&self, snapshot: Arc<Snapshot>) -> Option<Arc<Snapshot>> {
        self.current.swap(Some(snapshot))
    }

    pub fn record_attempt(&self) {
        self.lock().last_attempt = Some(Utc::now());
    }

    pub fn record_clone_started(&self) {
        self.lock().clone_started = Some(Utc::now());
    }

    pub fn record_clone_finished(&self) {
        self.lock().clone_started = None;
    }

    pub fn record_success(&self) {
        let now = Utc::now();
        let mut st = self.lock();
        st.last_success = Some(now);
        st.last_attempt = Some(now);
        st.last_error = None;
        st.consecutive_failures = 0;
        st.scan_held = false;
        st.initializing = false;
    }

    /// Marks a snapshot restored from disk as current without claiming a fresh pull.
    pub fn record_restored(&self, pulled_at: DateTime<Utc>, findings: usize) {
        let mut st = self.lock();
        st.last_success = Some(pulled_at);
        st.scan_findings = findings;
        st.initializing = false;
    }

    pub fn record_failure(&self, error: PullError) {
        let mut st = self.lock();
        st.last_attempt = Some(Utc::now());
        st.last_error = Some(error);
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        st.initializing = false;
    }

    pub fn record_scan(&self, findings: usize, held: bool) {
        let mut st = self.lock();
        st.scan_findings = findings;
        st.scan_held = held;
    }
}

/// Every configured repo, in config order.
#[derive(Debug)]
pub struct Registry {
    pub repos: Vec<Arc<RepoState>>,
}

impl Registry {
    pub fn new(config: &Config) -> Registry {
        Registry {
            repos: config
                .repo
                .iter()
                .map(|r| Arc::new(RepoState::new(r.clone())))
                .collect(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&Arc<RepoState>> {
        self.repos.iter().find(|r| r.cfg.id == id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<RepoState>> {
        self.repos.iter()
    }

    /// Repos in the allow-list; `None` means every repo.
    pub fn visible_to(&self, allow: Option<&[String]>) -> Vec<Arc<RepoState>> {
        self.repos
            .iter()
            .filter(|r| allow.is_none_or(|ids| ids.iter().any(|id| *id == r.cfg.id)))
            .cloned()
            .collect()
    }

    pub fn ids(&self) -> Vec<String> {
        self.repos.iter().map(|r| r.cfg.id.clone()).collect()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFinding {
    pub rule_id: String,
    pub secret: String,
    pub fingerprint: String,
}

impl std::fmt::Debug for StoredFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredFinding")
            .field("rule_id", &self.rule_id)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl From<&Finding> for StoredFinding {
    fn from(f: &Finding) -> Self {
        StoredFinding {
            rule_id: f.rule_id.clone(),
            secret: f.secret.clone(),
            fingerprint: f.fingerprint.clone(),
        }
    }
}

impl From<&StoredFinding> for Finding {
    fn from(f: &StoredFinding) -> Self {
        Finding {
            rule_id: f.rule_id.clone(),
            path: None,
            line: None,
            secret: f.secret.clone(),
            fingerprint: f.fingerprint.clone(),
        }
    }
}

/// `state.json`: what a restart needs to serve the last snapshot before any network call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    pub commit: Oid,
    pub commit_time: DateTime<Utc>,
    pub commit_subject: String,
    pub worktree: PathBuf,
    pub pulled_at: DateTime<Utc>,
    pub findings: Vec<StoredFinding>,
}

impl StateFile {
    pub fn read(path: &Path) -> std::io::Result<StateFile> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Writes a 0600 temp file beside `path`, then renames it into place.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".state-")
            .tempfile_in(dir)?;
        tmp.write_all(&body)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// On-disk locations for one repo under the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoDirs {
    pub git: PathBuf,
    pub snapshots: PathBuf,
    pub state: PathBuf,
}

pub fn data_layout(data_dir: &Path, repo_id: &str) -> RepoDirs {
    let base = data_dir.join(repo_id);
    RepoDirs {
        git: base.join("git"),
        snapshots: base.join("snapshots"),
        state: base.join("state.json"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn rp(s: &str) -> RepoPath {
        RepoPath::parse(s).unwrap()
    }

    fn gt(path: &str, kind: TreeKind, size: Option<u64>) -> git::TreeEntry {
        git::TreeEntry {
            mode: 0o100644,
            kind,
            size,
            path: path.to_owned(),
        }
    }

    fn sample() -> FileIndex {
        FileIndex::from_git(vec![
            gt("README.md", TreeKind::Blob, Some(10)),
            gt("src/main.rs", TreeKind::Blob, Some(100)),
            gt("src/util/mod.rs", TreeKind::Blob, Some(5)),
            gt("src/util/strings.rs", TreeKind::Blob, Some(7)),
            gt("src/link", TreeKind::Symlink, Some(8)),
            gt("vendor/lib", TreeKind::Submodule, None),
            gt("docs/a.md", TreeKind::Blob, Some(1)),
        ])
        .unwrap()
    }

    fn tmp_snapshot(root: PathBuf) -> Snapshot {
        Snapshot::new(
            Oid::parse(&"a".repeat(40)).unwrap(),
            Utc::now(),
            "subject".into(),
            root,
            FileIndex::default(),
            Arc::new(Redactor::empty()),
            0,
            Utc::now(),
        )
    }

    fn repo_cfg(id: &str) -> RepoConfig {
        RepoConfig {
            id: id.into(),
            host: crate::config::Host::Github,
            path: "example-org/x".into(),
            branch: "main".into(),
            description: String::new(),
            credential: "c".into(),
            pull_interval: None,
            scan_policy: None,
            remote_url_override: None,
        }
    }

    #[test]
    fn index_lookup_and_dirs() {
        let idx = sample();
        assert_eq!(idx.len(), 7);
        assert_eq!(idx.get(&rp("src/main.rs")).unwrap().size, 100);
        assert_eq!(
            idx.get(&rp("vendor/lib")).unwrap().kind,
            EntryKind::Submodule
        );
        assert!(idx.get(&rp("src")).is_none());
        assert!(idx.is_dir(&RepoPath::root()));
        assert!(idx.is_dir(&rp("src")));
        assert!(idx.is_dir(&rp("src/util")));
        assert!(!idx.is_dir(&rp("src/main.rs")));
        assert!(!idx.is_dir(&rp("nope")));
        assert_eq!(idx.iter().count(), 7);
    }

    #[test]
    fn children_sorted_dirs_first() {
        let idx = sample();
        let root: Vec<(String, ChildKind)> = idx
            .children(&RepoPath::root())
            .iter()
            .map(|c| (c.name().to_owned(), c.kind))
            .collect();
        assert_eq!(
            root,
            vec![
                ("docs".into(), ChildKind::Dir),
                ("src".into(), ChildKind::Dir),
                ("vendor".into(), ChildKind::Dir),
                ("README.md".into(), ChildKind::File),
            ]
        );
        let src = idx.children(&rp("src"));
        let names: Vec<_> = src.iter().map(|c| (c.name(), c.kind, c.size)).collect();
        assert_eq!(
            names,
            vec![
                ("util", ChildKind::Dir, None),
                ("link", ChildKind::Symlink, Some(8)),
                ("main.rs", ChildKind::File, Some(100)),
            ]
        );
        let vendor = idx.children(&rp("vendor"));
        assert_eq!(vendor[0].kind, ChildKind::Submodule);
        assert_eq!(vendor[0].size, None);
        assert!(idx.children(&rp("missing")).is_empty());
        assert_eq!(idx.children_ref(&rp("src/util")).len(), 2);
    }

    #[test]
    fn from_git_skips_bad_paths_and_trees() {
        let idx = FileIndex::from_git(vec![
            gt("ok.txt", TreeKind::Blob, Some(1)),
            gt("a/.git/config", TreeKind::Blob, Some(1)),
            gt("a/../b", TreeKind::Blob, Some(1)),
            gt("dir", TreeKind::Tree, None),
        ])
        .unwrap();
        assert_eq!(idx.len(), 1);
        assert!(idx.get(&rp("ok.txt")).is_some());
        assert!(!idx.is_dir(&rp("dir")));
    }

    #[test]
    fn close_matches_prefers_same_name() {
        let idx = sample();
        let m = idx.close_matches(&rp("lib/util/mod.rs"), 3);
        assert_eq!(m[0], rp("src/util/mod.rs"));
        let m = idx.close_matches(&rp("src/main.rss"), 2);
        assert_eq!(m[0], rp("src/main.rs"));
        assert!(m.len() <= 2);
        assert!(
            idx.close_matches(&rp("completely/unrelated/thing.xyz"), 3)
                .is_empty()
        );
        assert!(idx.close_matches(&RepoPath::root(), 3).is_empty());
        assert!(idx.close_matches(&rp("README.mdd"), 0).is_empty());
    }

    #[test]
    fn levenshtein_bounds() {
        assert_eq!(levenshtein_within(b"kitten", b"sitting", 3), Some(3));
        assert_eq!(levenshtein_within(b"kitten", b"sitting", 2), None);
        assert_eq!(levenshtein_within(b"", b"abc", 3), Some(3));
        assert_eq!(levenshtein_within(b"same", b"same", 0), Some(0));
    }

    #[test]
    fn status_words_and_staleness() {
        let state = RepoState::new(repo_cfg("a"));
        let now = Utc::now();
        let stale_after = Duration::from_secs(1800);
        assert_eq!(
            state.status_word(stale_after, now),
            RepoStatus::Initializing
        );
        state.record_failure(PullError {
            class: ErrorClass::Network,
            message: "down".into(),
        });
        assert_eq!(state.status_word(stale_after, now), RepoStatus::Unavailable);
        assert_eq!(state.stale_seconds(stale_after, now), 0);

        let snap = Arc::new(tmp_snapshot(PathBuf::from("/nonexistent")));
        assert!(state.set_snapshot(snap).is_none());
        state.record_success();
        assert_eq!(state.status_word(stale_after, now), RepoStatus::Ready);
        assert_eq!(state.stale_seconds(stale_after, now), 0);
        let later = now + chrono::Duration::seconds(3600);
        assert_eq!(state.status_word(stale_after, later), RepoStatus::Stale);
        let secs = state.stale_seconds(stale_after, later);
        assert!((3599..=3601).contains(&secs), "{secs}");

        state.record_failure(PullError {
            class: ErrorClass::Auth,
            message: "denied".into(),
        });
        let st = state.status();
        assert_eq!(st.consecutive_failures, 1);
        assert_eq!(st.last_error.as_ref().unwrap().class, ErrorClass::Auth);
        assert!(st.last_success.is_some());
        state.record_scan(3, true);
        assert!(state.status().scan_held);
        state.record_success();
        let st = state.status();
        assert_eq!(st.consecutive_failures, 0);
        assert!(st.last_error.is_none());
        assert!(!st.scan_held);
        assert_eq!(st.scan_findings, 3);
    }

    #[test]
    fn restored_snapshot_uses_pulled_at_for_staleness() {
        let state = RepoState::new(repo_cfg("a"));
        let snap = Arc::new(tmp_snapshot(PathBuf::from("/nonexistent")));
        let pulled = snap.pulled_at;
        state.set_snapshot(snap);
        let stale_after = Duration::from_secs(60);
        assert_eq!(state.status_word(stale_after, pulled), RepoStatus::Ready);
        let later = pulled + chrono::Duration::seconds(120);
        assert_eq!(state.status_word(stale_after, later), RepoStatus::Stale);
        state.record_restored(pulled, 2);
        assert_eq!(state.status().last_success, Some(pulled));
        assert!(!state.status().initializing);
    }

    #[test]
    fn error_class_mapping() {
        assert_eq!(ErrorClass::from(git::ErrorClass::Auth), ErrorClass::Auth);
        assert_eq!(
            ErrorClass::from(git::ErrorClass::NotFound),
            ErrorClass::Network
        );
        assert_eq!(
            ErrorClass::from(git::ErrorClass::Network),
            ErrorClass::Network
        );
        assert_eq!(
            ErrorClass::from(git::ErrorClass::Internal),
            ErrorClass::Internal
        );
        assert_eq!(ErrorClass::SecretFound.as_str(), "secret_found");
    }

    fn registry() -> Registry {
        Registry {
            repos: ["a", "b", "c"]
                .iter()
                .map(|id| Arc::new(RepoState::new(repo_cfg(id))))
                .collect(),
        }
    }

    #[test]
    fn registry_lookup_and_visibility() {
        let reg = registry();
        assert_eq!(reg.ids(), vec!["a", "b", "c"]);
        assert!(reg.get("b").is_some());
        assert!(reg.get("z").is_none());
        assert_eq!(reg.iter().count(), 3);
        assert_eq!(reg.visible_to(None).len(), 3);
        let allow = vec!["c".to_owned(), "a".to_owned(), "zzz".to_owned()];
        let seen: Vec<String> = reg
            .visible_to(Some(&allow))
            .iter()
            .map(|r| r.cfg.id.clone())
            .collect();
        assert_eq!(seen, vec!["a", "c"]);
        assert!(reg.visible_to(Some(&[])).is_empty());
    }

    #[test]
    fn state_file_round_trip_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repo").join("state.json");
        let sf = StateFile {
            commit: Oid::parse(&"b".repeat(40)).unwrap(),
            commit_time: Utc::now(),
            commit_subject: "hello".into(),
            worktree: dir.path().join("wt"),
            pulled_at: Utc::now(),
            findings: vec![StoredFinding {
                rule_id: "rule".into(),
                secret: "s3cr3t-value".into(),
                fingerprint: "a.txt:rule:1".into(),
            }],
        };
        sf.write(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = StateFile::read(&path).unwrap();
        assert_eq!(back.commit, sf.commit);
        assert_eq!(back.findings, sf.findings);
        assert_eq!(back.commit_subject, "hello");
        sf.write(&path).unwrap();
        let leftovers = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1);
        assert!(!format!("{:?}", sf.findings[0]).contains("s3cr3t"));
    }

    #[test]
    fn state_file_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(StateFile::read(&dir.path().join("none.json")).is_err());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        let err = StateFile::read(&bad).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn layout_paths() {
        let d = data_layout(Path::new("/data"), "web");
        assert_eq!(d.git, PathBuf::from("/data/web/git"));
        assert_eq!(d.snapshots, PathBuf::from("/data/web/snapshots"));
        assert_eq!(d.state, PathBuf::from("/data/web/state.json"));
    }

    #[tokio::test]
    async fn drop_removes_directory_when_marked() {
        let tmp = tempfile::tempdir().unwrap();
        let keep = tmp.path().join("keep");
        let gone = tmp.path().join("gone");
        std::fs::create_dir_all(keep.join("x")).unwrap();
        std::fs::create_dir_all(gone.join("x")).unwrap();
        std::fs::write(gone.join("x/f"), "data").unwrap();

        drop(tmp_snapshot(keep.clone()));
        let marked = tmp_snapshot(gone.clone());
        marked.mark_remove_on_drop();
        let arc = Arc::new(marked);
        let second = arc.clone();
        drop(arc);
        assert!(gone.exists(), "still referenced");
        drop(second);
        for _ in 0..100 {
            if !gone.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!gone.exists());
        assert!(keep.exists());
    }

    #[test]
    fn drop_without_runtime_removes_synchronously() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("gone");
        std::fs::create_dir_all(&gone).unwrap();
        let s = tmp_snapshot(gone.clone());
        s.mark_remove_on_drop();
        drop(s);
        assert!(!gone.exists());
    }
}
