//! Git subprocess layer: hardened invocations, credentials, parsing of plumbing output.

pub mod askpass;
pub mod scrub;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::process::Command;

use crate::proc::{self, ProcError};

pub use scrub::scrub_stderr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Auth,
    Network,
    NotFound,
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git {kind} timed out after {after:?}")]
    Timeout { kind: &'static str, after: Duration },
    #[error("git failed ({class:?}): {stderr_scrubbed}")]
    Failed {
        stderr_scrubbed: String,
        class: ErrorClass,
    },
    #[error("unexpected git output: {0}")]
    Parse(String),
    #[error("git output exceeds the capture cap")]
    OutputTooLarge,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl GitError {
    pub fn class(&self) -> ErrorClass {
        match self {
            GitError::Timeout { .. } => ErrorClass::Network,
            GitError::Failed { class, .. } => *class,
            _ => ErrorClass::Internal,
        }
    }
}

const AUTH_PHRASES: &[&str] = &[
    "authentication failed",
    "could not read username",
    "could not read password",
    "permission denied (publickey)",
    "invalid username or token",
    "http 401",
    "http 403",
    "returned error: 401",
    "returned error: 403",
];
const NOT_FOUND_PHRASES: &[&str] = &[
    "repository not found",
    "not found",
    "returned error: 404",
    "http 404",
    "does not appear to be a git repository",
    "could not find remote branch",
    "couldn't find remote ref",
    "does not exist",
    "needed a single revision",
    "unknown revision",
];
const NETWORK_PHRASES: &[&str] = &[
    "could not resolve host",
    "connection refused",
    "timed out",
    "unable to access",
    "connection reset",
];

fn classify(stderr: &str) -> ErrorClass {
    let lower = stderr.to_ascii_lowercase();
    let has = |phrases: &[&str]| phrases.iter().any(|p| lower.contains(p));
    if has(AUTH_PHRASES) {
        ErrorClass::Auth
    } else if has(NOT_FOUND_PHRASES) {
        ErrorClass::NotFound
    } else if has(NETWORK_PHRASES) {
        ErrorClass::Network
    } else {
        ErrorClass::Internal
    }
}

fn failed(stderr: &str) -> GitError {
    GitError::Failed {
        class: classify(stderr),
        stderr_scrubbed: scrub_stderr(stderr),
    }
}

fn map_proc(err: ProcError) -> GitError {
    match err {
        ProcError::Timeout { kind, after } => GitError::Timeout { kind, after },
        ProcError::Busy => GitError::Io(std::io::Error::other("worker pool busy")),
        ProcError::Spawn(e) => GitError::Io(e),
        ProcError::Failed { stderr, .. } => failed(&stderr),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GitTimeouts {
    pub fetch: Duration,
    pub clone: Duration,
    pub command: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Oid(String);

impl Oid {
    /// Accepts 40 (SHA-1) or 64 (SHA-256) hex characters, lowercased.
    pub fn parse(s: &str) -> Option<Oid> {
        let s = s.trim();
        let ok_len = s.len() == 40 || s.len() == 64;
        (ok_len && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Oid(s.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn short(&self) -> &str {
        &self.0[..7]
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct CommitMeta {
    pub time: DateTime<Utc>,
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    Blob,
    Symlink,
    Submodule,
    Tree,
}

/// `mode` is the numeric file mode (octal digits of `ls-tree` parsed as base 8, so a symlink is `0o120000`).
#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: u32,
    pub kind: TreeKind,
    pub size: Option<u64>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct FileChange {
    pub status: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub oid: Oid,
    pub parents: Vec<Oid>,
    pub author_name: String,
    pub author_email: String,
    pub author_time: DateTime<Utc>,
    pub subject: String,
    pub body: String,
    pub files: Vec<FileChange>,
}

#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    pub path: Option<String>,
    pub max_count: usize,
    pub since: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub include_files: bool,
}

#[derive(Debug, Clone)]
pub struct BlameLine {
    pub line: u32,
    pub oid: Oid,
    pub author_name: String,
    pub author_time: DateTime<Utc>,
    pub boundary: bool,
    pub text: String,
}

#[derive(Debug, Clone)]
pub enum ResolvedCredential {
    HttpsToken {
        username: String,
        secret_path: PathBuf,
    },
    SshKey {
        key_path: PathBuf,
    },
    None,
}

/// Private 0700 directory holding secrets that came from environment variables.
#[derive(Debug)]
pub struct CredentialFiles {
    dir: TempDir,
    written: HashMap<String, PathBuf>,
}

impl CredentialFiles {
    pub fn new() -> std::io::Result<Self> {
        let dir = tempfile::Builder::new().prefix("cex-cred-").tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            dir,
            written: HashMap::new(),
        })
    }

    /// Writes the value of `env_var` to a 0600 file named after `name`; repeated calls reuse the file.
    pub fn materialize_env(&mut self, name: &str, env_var: &str) -> std::io::Result<PathBuf> {
        if let Some(path) = self.written.get(name) {
            return Ok(path.clone());
        }
        let mut value = std::env::var(env_var).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("environment variable {env_var} is not set"),
            )
        })?;
        if !value.ends_with('\n') {
            value.push('\n');
        }
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self
            .dir
            .path()
            .join(format!("{}-{safe}", self.written.len()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
        self.written.insert(name.to_owned(), path.clone());
        Ok(path)
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ssh_command(identity: Option<&Path>, known_hosts: &Path) -> String {
    let mut cmd = String::from("ssh -F /dev/null");
    if let Some(key) = identity {
        cmd.push_str(&format!(
            " -i {} -o IdentitiesOnly=yes",
            shell_quote(&key.to_string_lossy())
        ));
    }
    cmd.push_str(&format!(
        " -o StrictHostKeyChecking=yes -o UserKnownHostsFile={} -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes",
        shell_quote(&known_hosts.to_string_lossy())
    ));
    cmd
}

/// Sets credential env on `cmd`. `GIT_ASKPASS` is the current exe, which must call
/// `git::askpass::try_handle()` first thing in `main` (git runs it as `exe <prompt>`, without a shell).
pub fn apply_credential(cmd: &mut Command, cred: &ResolvedCredential, known_hosts: &Path) {
    let askpass = std::env::current_exe()
        .map(|exe| exe.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "false".to_owned());
    apply_credential_with(cmd, cred, known_hosts, &askpass);
}

fn apply_credential_with(
    cmd: &mut Command,
    cred: &ResolvedCredential,
    known_hosts: &Path,
    askpass: &str,
) {
    match cred {
        ResolvedCredential::HttpsToken {
            username,
            secret_path,
        } => {
            cmd.env("GIT_ASKPASS", askpass)
                .env("CODE_EXPLORER_ASKPASS_FILE", secret_path)
                .env("CODE_EXPLORER_ASKPASS_USER", username)
                .env("GIT_SSH_COMMAND", ssh_command(None, known_hosts));
        }
        ResolvedCredential::SshKey { key_path } => {
            cmd.env("GIT_ASKPASS", "false")
                .env("GIT_SSH_COMMAND", ssh_command(Some(key_path), known_hosts));
        }
        ResolvedCredential::None => {
            cmd.env("GIT_ASKPASS", "false")
                .env("GIT_SSH_COMMAND", ssh_command(None, known_hosts));
        }
    }
}

/// Directory with no hooks, created once per process.
pub fn empty_hooks_dir() -> PathBuf {
    static DIR: OnceLock<(Option<TempDir>, PathBuf)> = OnceLock::new();
    DIR.get_or_init(
        || match tempfile::Builder::new().prefix("cex-hooks-").tempdir() {
            Ok(dir) => {
                let path = dir.path().to_path_buf();
                (Some(dir), path)
            }
            Err(_) => (None, PathBuf::from("/nonexistent-hooks")),
        },
    )
    .1
    .clone()
}

fn validate_branch(branch: &str) -> Result<(), GitError> {
    let bad = branch.is_empty()
        || branch.starts_with('-')
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with(".lock")
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c));
    if bad {
        return Err(GitError::Parse(format!("invalid branch name: {branch:?}")));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), GitError> {
    if url.is_empty() || url.starts_with('-') || url.chars().any(char::is_control) {
        return Err(GitError::Parse("invalid remote url".into()));
    }
    Ok(())
}

fn validate_rev(rev: &str) -> Result<(), GitError> {
    if rev.is_empty() || rev.starts_with('-') || rev.chars().any(|c| c.is_control() || c == ' ') {
        return Err(GitError::Parse(format!("invalid revision: {rev:?}")));
    }
    Ok(())
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn parse_time(s: &str) -> Result<DateTime<Utc>, GitError> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| GitError::Parse(format!("bad timestamp {s:?}: {e}")))
}

fn parse_oid(s: &str) -> Result<Oid, GitError> {
    Oid::parse(s).ok_or_else(|| GitError::Parse(format!("bad object id {s:?}")))
}

#[derive(Debug, Clone)]
pub struct GitRunner {
    git_bin: PathBuf,
    timeouts: GitTimeouts,
    known_hosts: PathBuf,
    hooks_dir: PathBuf,
    allow_local: bool,
}

impl GitRunner {
    /// `allow_local` permits `file://` remotes (tests and local fixtures only).
    pub fn new(
        git_bin: PathBuf,
        timeouts: GitTimeouts,
        known_hosts: PathBuf,
        hooks_dir: PathBuf,
        allow_local: bool,
    ) -> Self {
        Self {
            git_bin,
            timeouts,
            known_hosts,
            hooks_dir,
            allow_local,
        }
    }

    /// Scrubbed git command carrying the hardening `-c` flags every invocation must have.
    pub fn base_cmd(&self) -> Command {
        let mut cmd = proc::scrubbed_command(&self.git_bin);
        let file_proto = if self.allow_local { "always" } else { "never" };
        let hooks = format!("core.hooksPath={}", self.hooks_dir.display());
        let file = format!("protocol.file.allow={file_proto}");
        for setting in [
            "core.symlinks=false",
            hooks.as_str(),
            "protocol.allow=never",
            "protocol.https.allow=always",
            "protocol.ssh.allow=always",
            file.as_str(),
            "submodule.recurse=false",
            "core.fsmonitor=false",
            "credential.helper=",
            "uploadpack.allowAnySHA1InWant=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "advice.detachedHead=false",
        ] {
            cmd.arg("-c").arg(setting);
        }
        cmd
    }

    fn repo_cmd(&self, repo_dir: &Path) -> Command {
        let mut cmd = self.base_cmd();
        cmd.arg("-C").arg(repo_dir);
        cmd
    }

    fn net_cmd(&self, repo_dir: Option<&Path>, cred: &ResolvedCredential) -> Command {
        let mut cmd = match repo_dir {
            Some(dir) => self.repo_cmd(dir),
            None => self.base_cmd(),
        };
        apply_credential(&mut cmd, cred, &self.known_hosts);
        cmd
    }

    async fn exec(
        &self,
        cmd: Command,
        timeout: Duration,
        kind: &'static str,
    ) -> Result<proc::Output, GitError> {
        let out = proc::run(cmd, timeout, kind).await.map_err(map_proc)?;
        if out.stdout_truncated {
            return Err(GitError::OutputTooLarge);
        }
        Ok(out)
    }

    async fn exec_local(&self, cmd: Command, kind: &'static str) -> Result<proc::Output, GitError> {
        self.exec(cmd, self.timeouts.command, kind).await
    }

    pub async fn clone_bare(
        &self,
        url: &str,
        branch: &str,
        depth: u32,
        dest: &Path,
        cred: &ResolvedCredential,
    ) -> Result<(), GitError> {
        validate_url(url)?;
        validate_branch(branch)?;
        let existed = dest.exists();
        let mut cmd = self.net_cmd(None, cred);
        cmd.args(["clone", "--bare", "--depth"])
            .arg(depth.max(1).to_string())
            .args(["--single-branch", "--branch", branch, "--no-tags", "--"])
            .arg(url)
            .arg(dest);
        let result = self.exec(cmd, self.timeouts.clone, "clone").await;
        if let Err(e) = result {
            if !existed {
                let _ = std::fs::remove_dir_all(dest);
            }
            return Err(e);
        }
        let mut cfg = self.repo_cmd(dest);
        cfg.args(["config", "remote.origin.fetch"])
            .arg(format!("+refs/heads/{branch}:refs/heads/{branch}"));
        self.exec_local(cfg, "config").await?;
        Ok(())
    }

    pub async fn fetch(
        &self,
        repo_dir: &Path,
        branch: &str,
        depth: u32,
        cred: &ResolvedCredential,
    ) -> Result<(), GitError> {
        validate_branch(branch)?;
        let mut cmd = self.net_cmd(Some(repo_dir), cred);
        cmd.args(["fetch", "--depth"])
            .arg(depth.max(1).to_string())
            .args(["--no-tags", "--prune", "origin"])
            .arg(format!("+refs/heads/{branch}:refs/heads/{branch}"));
        self.exec(cmd, self.timeouts.fetch, "fetch").await?;
        Ok(())
    }

    pub async fn ls_remote(
        &self,
        url: &str,
        branch: &str,
        cred: &ResolvedCredential,
    ) -> Result<Oid, GitError> {
        validate_url(url)?;
        validate_branch(branch)?;
        let mut cmd = self.net_cmd(None, cred);
        cmd.args(["ls-remote", "--exit-code", "--", url])
            .arg(format!("refs/heads/{branch}"));
        let out = match proc::run(cmd, self.timeouts.fetch, "ls-remote").await {
            Ok(out) => out,
            Err(ProcError::Failed { status: 2, .. }) => {
                return Err(GitError::Failed {
                    stderr_scrubbed: format!("branch {branch} not found on remote"),
                    class: ErrorClass::NotFound,
                });
            }
            Err(e) => return Err(map_proc(e)),
        };
        let text = lossy(&out.stdout);
        let first = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().next())
            .ok_or_else(|| GitError::Parse("empty ls-remote output".into()))?;
        parse_oid(first)
    }

    pub async fn rev_parse(&self, repo_dir: &Path, rev: &str) -> Result<Oid, GitError> {
        validate_rev(rev)?;
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{rev}^{{commit}}"));
        let out = match proc::run(cmd, self.timeouts.command, "rev-parse").await {
            Ok(out) => out,
            Err(ProcError::Failed { status: 1, .. }) => {
                return Err(GitError::Failed {
                    stderr_scrubbed: format!("unknown revision {rev}"),
                    class: ErrorClass::NotFound,
                });
            }
            Err(e) => return Err(map_proc(e)),
        };
        parse_oid(&lossy(&out.stdout))
    }

    pub async fn commit_meta(&self, repo_dir: &Path, oid: &Oid) -> Result<CommitMeta, GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["show", "-s", "--format=%cI%x00%s"])
            .arg(oid.as_str());
        let out = self.exec_local(cmd, "show").await?;
        let text = lossy(&out.stdout);
        let (time, subject) = text
            .split_once('\0')
            .ok_or_else(|| GitError::Parse("commit meta without separator".into()))?;
        Ok(CommitMeta {
            time: parse_time(time)?,
            subject: subject.trim_end_matches('\n').to_owned(),
        })
    }

    pub async fn worktree_add(
        &self,
        repo_dir: &Path,
        oid: &Oid,
        dest: &Path,
    ) -> Result<(), GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["worktree", "add", "--detach", "--"])
            .arg(dest)
            .arg(oid.as_str());
        self.exec_local(cmd, "worktree-add").await?;
        Ok(())
    }

    /// Removes the worktree, prunes its metadata and deletes the directory if git left it behind.
    pub async fn worktree_remove(&self, repo_dir: &Path, dest: &Path) -> Result<(), GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["worktree", "remove", "--force", "--"]).arg(dest);
        let removed = self.exec_local(cmd, "worktree-remove").await;
        let pruned = self.worktree_prune(repo_dir).await;
        match std::fs::remove_dir_all(dest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(GitError::Io(e)),
        }
        removed.and(pruned)
    }

    pub async fn worktree_prune(&self, repo_dir: &Path) -> Result<(), GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["worktree", "prune"]);
        self.exec_local(cmd, "worktree-prune").await?;
        Ok(())
    }

    pub async fn ls_tree(&self, repo_dir: &Path, oid: &Oid) -> Result<Vec<TreeEntry>, GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["ls-tree", "-r", "-l", "-z"]).arg(oid.as_str());
        let out = self.exec_local(cmd, "ls-tree").await?;
        parse_ls_tree(&out.stdout)
    }

    /// Returns the commits (newest first) and whether the walk reached the shallow boundary.
    pub async fn log(
        &self,
        repo_dir: &Path,
        oid: &Oid,
        query: &LogQuery,
    ) -> Result<(Vec<Commit>, bool), GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["log", "-z", "--no-renames"]);
        cmd.arg("--format=%x1e%H%x00%P%x00%an%x00%ae%x00%aI%x00%s%x00%b");
        if query.max_count > 0 {
            cmd.arg(format!("--max-count={}", query.max_count));
        }
        if let Some(since) = query.since {
            cmd.arg(format!("--since={}", since.to_rfc3339()));
        }
        if query.include_files {
            cmd.args(["--name-status", "--diff-merges=first-parent"]);
        }
        cmd.arg(oid.as_str()).arg("--");
        if let Some(path) = &query.path {
            cmd.arg(path);
        }
        let out = self.exec_local(cmd, "log").await?;
        let mut commits = parse_log(&out.stdout, query.include_body)?;
        if !query.include_files {
            for c in &mut commits {
                c.files.clear();
            }
        }
        let shallow = read_shallow(repo_dir);
        let hit_boundary = commits.iter().any(|c| shallow.contains(&c.oid));
        let exhausted = !shallow.is_empty()
            && query.since.is_none()
            && query.max_count > 0
            && commits.len() < query.max_count;
        Ok((commits, hit_boundary || exhausted))
    }

    pub async fn show_file(
        &self,
        repo_dir: &Path,
        oid: &Oid,
        path: &str,
    ) -> Result<Vec<u8>, GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["cat-file", "blob"]).arg(format!("{oid}:{path}"));
        Ok(self.exec_local(cmd, "cat-file").await?.stdout)
    }

    /// Size in bytes of the blob at `path` in commit `oid`, without reading its content.
    pub async fn blob_size(&self, repo_dir: &Path, oid: &Oid, path: &str) -> Result<u64, GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.args(["cat-file", "-s"]).arg(format!("{oid}:{path}"));
        let out = self.exec_local(cmd, "cat-file").await?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .map_err(|_| GitError::Parse("cat-file -s printed no size".into()))
    }

    /// True when `oid` is a commit present in the clone and an ancestor of `refs/heads/<branch>`.
    pub async fn commit_in_history(
        &self,
        repo_dir: &Path,
        oid: &Oid,
        branch: &str,
    ) -> Result<bool, GitError> {
        validate_branch(branch)?;
        let mut exists = self.repo_cmd(repo_dir);
        exists
            .args(["cat-file", "-e"])
            .arg(format!("{oid}^{{commit}}"));
        match proc::run(exists, self.timeouts.command, "cat-file").await {
            Ok(_) => {}
            Err(ProcError::Failed { .. }) => return Ok(false),
            Err(e) => return Err(map_proc(e)),
        }
        let mut anc = self.repo_cmd(repo_dir);
        anc.args(["merge-base", "--is-ancestor"])
            .arg(oid.as_str())
            .arg(format!("refs/heads/{branch}"));
        match proc::run(anc, self.timeouts.command, "merge-base").await {
            Ok(_) => Ok(true),
            Err(ProcError::Failed { status: 1, .. }) => Ok(false),
            Err(e) => Err(map_proc(e)),
        }
    }

    /// Blames `path` in the worktree, or in `commit` when given (the worktree may be rewritten).
    pub async fn blame(
        &self,
        worktree_dir: &Path,
        commit: Option<&Oid>,
        path: &str,
        start: u32,
        end: u32,
    ) -> Result<Vec<BlameLine>, GitError> {
        if start == 0 || end < start {
            return Err(GitError::Parse(format!("invalid line range {start},{end}")));
        }
        let mut cmd = self.repo_cmd(worktree_dir);
        cmd.args(["blame", "--porcelain", "-L"])
            .arg(format!("{start},{end}"));
        if let Some(commit) = commit {
            cmd.arg(commit.as_str());
        }
        cmd.arg("--").arg(path);
        let out = self.exec_local(cmd, "blame").await?;
        parse_blame(&out.stdout)
    }

    /// Commit messages of the last `max_count` commits reachable from `oid`, for the secret scanner.
    pub async fn commit_messages(
        &self,
        repo_dir: &Path,
        oid: &Oid,
        max_count: usize,
    ) -> Result<String, GitError> {
        let mut cmd = self.repo_cmd(repo_dir);
        cmd.arg("log")
            .arg(format!("--max-count={}", max_count.max(1)))
            .arg("--format=%B%x00")
            .arg(oid.as_str())
            .arg("--");
        let out = self.exec_local(cmd, "log-messages").await?;
        let text = lossy(&out.stdout);
        Ok(text
            .split('\0')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn read_shallow(repo_dir: &Path) -> HashSet<Oid> {
    std::fs::read_to_string(repo_dir.join("shallow"))
        .map(|s| s.lines().filter_map(Oid::parse).collect())
        .unwrap_or_default()
}

fn parse_ls_tree(bytes: &[u8]) -> Result<Vec<TreeEntry>, GitError> {
    let mut entries = Vec::new();
    for rec in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = rec
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| GitError::Parse("ls-tree entry without tab".into()))?;
        let meta = lossy(&rec[..tab]);
        let path = lossy(&rec[tab + 1..]);
        let mut fields = meta.split_whitespace();
        let (Some(mode), Some(kind), Some(_oid), Some(size)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(GitError::Parse(format!("bad ls-tree line: {meta:?}")));
        };
        let mode = u32::from_str_radix(mode, 8)
            .map_err(|_| GitError::Parse(format!("bad mode {mode:?}")))?;
        let kind = match (mode, kind) {
            (0o120000, _) => TreeKind::Symlink,
            (0o160000, _) | (_, "commit") => TreeKind::Submodule,
            (_, "tree") => TreeKind::Tree,
            _ => TreeKind::Blob,
        };
        entries.push(TreeEntry {
            mode,
            kind,
            size: size.parse().ok(),
            path,
        });
    }
    Ok(entries)
}

fn parse_log(bytes: &[u8], include_body: bool) -> Result<Vec<Commit>, GitError> {
    let mut tokens = bytes.split(|b| *b == 0).peekable();
    let mut commits = Vec::new();
    while let Some(first) = tokens.next() {
        let first = lossy(first);
        let first = first.trim_start_matches('\n');
        if first.is_empty() {
            continue;
        }
        let Some(hash) = first.strip_prefix('\x1e') else {
            return Err(GitError::Parse("log record without marker".into()));
        };
        let mut field = |name: &str| -> Result<String, GitError> {
            tokens
                .next()
                .map(lossy)
                .ok_or_else(|| GitError::Parse(format!("log record missing {name}")))
        };
        let parents = field("parents")?
            .split_whitespace()
            .map(parse_oid)
            .collect::<Result<Vec<_>, _>>()?;
        let author_name = field("author name")?;
        let author_email = field("author email")?;
        let author_time = parse_time(&field("author time")?)?;
        let subject = field("subject")?;
        let body = field("body")?;
        let mut files = Vec::new();
        while let Some(tok) = tokens.peek() {
            let status = lossy(tok);
            let status = status.trim_start_matches('\n');
            if status.is_empty() {
                tokens.next();
                continue;
            }
            if status.starts_with('\x1e') {
                break;
            }
            let status = status.to_owned();
            tokens.next();
            let path = tokens
                .next()
                .map(lossy)
                .ok_or_else(|| GitError::Parse("name-status entry without path".into()))?;
            files.push(FileChange { status, path });
        }
        commits.push(Commit {
            oid: parse_oid(hash)?,
            parents,
            author_name,
            author_email,
            author_time,
            subject,
            body: if include_body {
                body.trim_end().to_owned()
            } else {
                String::new()
            },
            files,
        });
    }
    Ok(commits)
}

struct BlameMeta {
    author: String,
    time: DateTime<Utc>,
    boundary: bool,
}

fn parse_blame(bytes: &[u8]) -> Result<Vec<BlameLine>, GitError> {
    let text = lossy(bytes);
    let mut metas: HashMap<Oid, BlameMeta> = HashMap::new();
    let mut lines = Vec::new();
    let mut current: Option<(Oid, u32)> = None;
    let mut pending: Option<(String, Option<DateTime<Utc>>, bool)> = None;
    for raw in text.split('\n') {
        if let Some(content) = raw.strip_prefix('\t') {
            let (oid, line) = current
                .take()
                .ok_or_else(|| GitError::Parse("blame content before header".into()))?;
            if let Some((author, time, boundary)) = pending.take() {
                metas.insert(
                    oid.clone(),
                    BlameMeta {
                        author,
                        time: time.unwrap_or(DateTime::UNIX_EPOCH),
                        boundary,
                    },
                );
            }
            let meta = metas
                .get(&oid)
                .ok_or_else(|| GitError::Parse("blame line without commit info".into()))?;
            lines.push(BlameLine {
                line,
                oid,
                author_name: meta.author.clone(),
                author_time: meta.time,
                boundary: meta.boundary,
                text: content.to_owned(),
            });
            continue;
        }
        if current.is_none() {
            let mut parts = raw.split_whitespace();
            if let (Some(hash), Some(_orig), Some(fin)) = (parts.next(), parts.next(), parts.next())
                && let (Some(oid), Ok(fin)) = (Oid::parse(hash), fin.parse::<u32>())
            {
                current = Some((oid.clone(), fin));
                if !metas.contains_key(&oid) {
                    pending = Some((String::new(), None, false));
                }
            }
            continue;
        }
        if let Some(p) = pending.as_mut() {
            if let Some(name) = raw.strip_prefix("author ") {
                p.0 = name.to_owned();
            } else if let Some(ts) = raw.strip_prefix("author-time ") {
                p.1 = ts
                    .parse::<i64>()
                    .ok()
                    .and_then(|s| DateTime::from_timestamp(s, 0));
            } else if raw == "boundary" {
                p.2 = true;
            }
        }
    }
    Ok(lines)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn git_available() -> bool {
        StdCommand::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sh_git(dir: &Path, args: &[&str]) {
        let out = StdCommand::new("git")
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Ada Tester")
            .env("GIT_AUTHOR_EMAIL", "ada@example.com")
            .env("GIT_COMMITTER_NAME", "Ada Tester")
            .env("GIT_COMMITTER_EMAIL", "ada@example.com")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn fixture() -> (TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        sh_git(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("a.txt"), "one\n").unwrap();
        std::fs::create_dir(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/b.txt"), "bee\n").unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
        sh_git(&src, &["add", "."]);
        sh_git(&src, &["commit", "-q", "-m", "first commit"]);
        std::fs::write(src.join("a.txt"), "one\ntwo\n").unwrap();
        sh_git(&src, &["add", "."]);
        sh_git(
            &src,
            &["commit", "-q", "-m", "second commit", "-m", "with a body"],
        );
        (tmp, src)
    }

    fn runner() -> GitRunner {
        GitRunner::new(
            PathBuf::from("git"),
            GitTimeouts {
                fetch: Duration::from_secs(60),
                clone: Duration::from_secs(60),
                command: Duration::from_secs(30),
            },
            PathBuf::from("/nonexistent/known_hosts"),
            empty_hooks_dir(),
            true,
        )
    }

    fn url(src: &Path) -> String {
        format!("file://{}", src.display())
    }

    async fn cloned(depth: u32) -> Option<(TempDir, PathBuf, PathBuf, GitRunner, Oid)> {
        if !git_available() {
            eprintln!("git not installed, skipping");
            return None;
        }
        let (tmp, src) = fixture();
        let git = runner();
        let bare = tmp.path().join("bare");
        git.clone_bare(&url(&src), "main", depth, &bare, &ResolvedCredential::None)
            .await
            .unwrap();
        let tip = git.rev_parse(&bare, "refs/heads/main").await.unwrap();
        Some((tmp, src, bare, git, tip))
    }

    #[tokio::test]
    async fn tree_symlink_and_worktree_checkout() {
        let Some((tmp, _src, bare, git, tip)) = cloned(50).await else {
            return;
        };
        let entries = git.ls_tree(&bare, &tip).await.unwrap();
        let link = entries.iter().find(|e| e.path == "link").unwrap();
        assert_eq!(link.kind, TreeKind::Symlink);
        assert_eq!(link.mode, 0o120000);
        let sub = entries.iter().find(|e| e.path == "sub/b.txt").unwrap();
        assert_eq!(sub.kind, TreeKind::Blob);
        assert_eq!(sub.size, Some(4));

        let wt = tmp.path().join("wt");
        git.worktree_add(&bare, &tip, &wt).await.unwrap();
        let meta = std::fs::symlink_metadata(wt.join("link")).unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(wt.join("link")).unwrap(), "a.txt");

        git.worktree_remove(&bare, &wt).await.unwrap();
        assert!(!wt.exists());
        let listed = StdCommand::new("git")
            .args(["worktree", "list", "--porcelain"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&listed.stdout).contains("wt"));
    }

    #[tokio::test]
    async fn fetch_sees_new_commit() {
        let Some((_tmp, src, bare, git, tip)) = cloned(50).await else {
            return;
        };
        std::fs::write(src.join("c.txt"), "new\n").unwrap();
        sh_git(&src, &["add", "."]);
        sh_git(&src, &["commit", "-q", "-m", "third commit"]);
        git.fetch(&bare, "main", 50, &ResolvedCredential::None)
            .await
            .unwrap();
        let newer = git.rev_parse(&bare, "refs/heads/main").await.unwrap();
        assert_ne!(newer, tip);
        let meta = git.commit_meta(&bare, &newer).await.unwrap();
        assert_eq!(meta.subject, "third commit");
        assert!(git.commit_in_history(&bare, &tip, "main").await.unwrap());
        let remote = git
            .ls_remote(&url(&src), "main", &ResolvedCredential::None)
            .await
            .unwrap();
        assert_eq!(remote, newer);
    }

    #[tokio::test]
    async fn log_lists_files_and_filters_by_path() {
        let Some((_tmp, _src, bare, git, tip)) = cloned(50).await else {
            return;
        };
        let query = LogQuery {
            max_count: 10,
            include_body: true,
            include_files: true,
            ..LogQuery::default()
        };
        let (commits, boundary) = git.log(&bare, &tip, &query).await.unwrap();
        assert!(!boundary);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].subject, "second commit");
        assert_eq!(commits[0].body, "with a body");
        assert_eq!(commits[0].author_email, "ada@example.com");
        assert_eq!(commits[0].parents, vec![commits[1].oid.clone()]);
        let changed: Vec<_> = commits[0]
            .files
            .iter()
            .map(|f| (f.status.as_str(), f.path.as_str()))
            .collect();
        assert_eq!(changed, vec![("M", "a.txt")]);
        assert_eq!(commits[1].files.len(), 3);
        assert!(commits[1].parents.is_empty());

        let query = LogQuery {
            path: Some("sub".into()),
            max_count: 10,
            ..LogQuery::default()
        };
        let (only_sub, _) = git.log(&bare, &tip, &query).await.unwrap();
        assert_eq!(only_sub.len(), 1);
        assert!(only_sub[0].files.is_empty() && only_sub[0].body.is_empty());
    }

    #[tokio::test]
    async fn shallow_clone_reaches_boundary() {
        let Some((_tmp, _src, bare, git, tip)) = cloned(1).await else {
            return;
        };
        let query = LogQuery {
            max_count: 10,
            ..LogQuery::default()
        };
        let (commits, boundary) = git.log(&bare, &tip, &query).await.unwrap();
        assert_eq!(commits.len(), 1);
        assert!(boundary);
    }

    #[tokio::test]
    async fn show_file_blame_and_messages() {
        let Some((tmp, _src, bare, git, tip)) = cloned(50).await else {
            return;
        };
        assert_eq!(
            git.show_file(&bare, &tip, "a.txt").await.unwrap(),
            b"one\ntwo\n"
        );
        assert!(git.show_file(&bare, &tip, "missing.txt").await.is_err());

        let wt = tmp.path().join("wt");
        git.worktree_add(&bare, &tip, &wt).await.unwrap();
        let lines = git.blame(&wt, None, "a.txt", 1, 2).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!((lines[0].line, lines[0].text.as_str()), (1, "one"));
        assert_eq!((lines[1].line, lines[1].text.as_str()), (2, "two"));
        assert_eq!(lines[0].author_name, "Ada Tester");
        assert_ne!(lines[0].oid, lines[1].oid);
        assert!(lines[0].boundary && !lines[1].boundary);
        assert!(git.blame(&wt, None, "a.txt", 0, 2).await.is_err());
        assert_eq!(git.blob_size(&bare, &tip, "a.txt").await.unwrap(), 8);
        assert!(git.blob_size(&bare, &tip, "missing.txt").await.is_err());

        std::fs::write(wt.join("a.txt"), "ONE\nTWO\n").unwrap();
        let at = git.blame(&wt, Some(&tip), "a.txt", 1, 2).await.unwrap();
        assert_eq!(at[0].text, "one");
        assert_eq!(at[0].oid, lines[0].oid);

        let msgs = git.commit_messages(&bare, &tip, 10).await.unwrap();
        assert!(msgs.contains("first commit") && msgs.contains("with a body"));
    }

    #[tokio::test]
    async fn blame_marks_boundary_in_shallow_clone() {
        let Some((tmp, _src, bare, git, tip)) = cloned(1).await else {
            return;
        };
        let wt = tmp.path().join("wt");
        git.worktree_add(&bare, &tip, &wt).await.unwrap();
        let lines = git.blame(&wt, None, "a.txt", 1, 2).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.boundary));
    }

    #[tokio::test]
    async fn history_check_rejects_unknown_commit() {
        let Some((_tmp, _src, bare, git, _tip)) = cloned(50).await else {
            return;
        };
        let bogus = Oid::parse(&"ab".repeat(20)).unwrap();
        assert!(!git.commit_in_history(&bare, &bogus, "main").await.unwrap());
    }

    #[tokio::test]
    async fn errors_are_classified_and_bad_input_rejected() {
        if !git_available() {
            return;
        }
        let git = runner();
        let tmp = tempfile::tempdir().unwrap();
        let err = git
            .clone_bare(
                "file:///nonexistent/repo.git",
                "main",
                1,
                &tmp.path().join("d"),
                &ResolvedCredential::None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }), "{err:?}");
        assert!(!tmp.path().join("d").exists());
        let bad = git
            .clone_bare(
                "file:///x",
                "--upload-pack=evil",
                1,
                &tmp.path().join("e"),
                &ResolvedCredential::None,
            )
            .await;
        assert!(matches!(bad, Err(GitError::Parse(_))));
        let missing = git
            .rev_parse(tmp.path(), "refs/heads/nope")
            .await
            .unwrap_err();
        assert!(matches!(missing, GitError::Failed { .. } | GitError::Io(_)));
    }

    #[tokio::test]
    async fn ls_remote_missing_branch_is_not_found() {
        let Some((_tmp, src, _bare, git, _tip)) = cloned(50).await else {
            return;
        };
        let err = git
            .ls_remote(&url(&src), "nope", &ResolvedCredential::None)
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::NotFound);
    }

    #[tokio::test]
    async fn local_remotes_are_refused_unless_allowed() {
        if !git_available() {
            return;
        }
        let (tmp, src) = fixture();
        let strict = GitRunner::new(
            PathBuf::from("git"),
            runner().timeouts,
            PathBuf::from("/nonexistent/known_hosts"),
            empty_hooks_dir(),
            false,
        );
        let err = strict
            .clone_bare(
                &url(&src),
                "main",
                1,
                &tmp.path().join("b"),
                &ResolvedCredential::None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::Failed { .. }));
    }

    #[test]
    fn classify_covers_spec_patterns() {
        assert_eq!(
            classify("fatal: Authentication failed for 'x'"),
            ErrorClass::Auth
        );
        assert_eq!(
            classify("error: The requested URL returned error: 403"),
            ErrorClass::Auth
        );
        assert_eq!(
            classify("fatal: could not read Username for 'https://h'"),
            ErrorClass::Auth
        );
        assert_eq!(
            classify("git@h: Permission denied (publickey)."),
            ErrorClass::Auth
        );
        assert_eq!(
            classify("fatal: Could not resolve host: h"),
            ErrorClass::Network
        );
        assert_eq!(
            classify("fatal: unable to access 'x': Connection refused"),
            ErrorClass::Network
        );
        assert_eq!(
            classify("remote: Repository not found."),
            ErrorClass::NotFound
        );
        assert_eq!(
            classify("fatal: Remote branch zz not found in upstream origin"),
            ErrorClass::NotFound
        );
        assert_eq!(classify("something odd"), ErrorClass::Internal);
    }

    #[test]
    fn classify_ignores_bare_status_digits() {
        assert_eq!(
            classify(
                "fatal: unable to access 'https://host:4403/x.git': Could not resolve host: host"
            ),
            ErrorClass::Network
        );
        assert_eq!(
            classify("fatal: bad object deadbeef404cafe0123"),
            ErrorClass::Internal
        );
        assert_eq!(
            classify("fatal: unable to access 'https://203.0.113.40:4013/r.git/': timed out"),
            ErrorClass::Network
        );
        assert_eq!(
            classify("remote: HTTP 401 for https://h/r.git"),
            ErrorClass::Auth
        );
        assert_eq!(
            classify("fatal: The requested URL returned error: 404"),
            ErrorClass::NotFound
        );
        assert_eq!(
            classify("fatal: 'https://h/r.git' does not appear to be a git repository"),
            ErrorClass::NotFound
        );
        assert_eq!(
            classify("fatal: couldn't find remote ref refs/heads/zz"),
            ErrorClass::NotFound
        );
        assert_eq!(
            classify("remote: Invalid username or token."),
            ErrorClass::Auth
        );
    }

    #[test]
    fn oid_parse_and_short() {
        let oid = Oid::parse(&"AB12".repeat(10)).unwrap();
        assert_eq!(oid.short(), "ab12ab1");
        assert!(Oid::parse("xyz").is_none());
        assert!(Oid::parse(&"a".repeat(64)).is_some());
    }

    #[test]
    fn parse_ls_tree_handles_submodule_and_sizes() {
        let raw = b"160000 commit 0123456789012345678901234567890123456789       -\tvendor/lib\x00100755 blob 0123456789012345678901234567890123456789      12\trun.sh\0";
        let entries = parse_ls_tree(raw).unwrap();
        assert_eq!(entries[0].kind, TreeKind::Submodule);
        assert_eq!(entries[0].size, None);
        assert_eq!(entries[1].mode, 0o100755);
        assert_eq!(entries[1].size, Some(12));
    }

    #[test]
    fn credential_files_are_private() {
        let mut files = CredentialFiles::new().unwrap();
        // CARGO_PKG_NAME is always exported by cargo to tests.
        let path = files
            .materialize_env("my cred/1", "CARGO_PKG_NAME")
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            env!("CARGO_PKG_NAME")
        );
        assert_eq!(
            files
                .materialize_env("my cred/1", "CARGO_PKG_NAME")
                .unwrap(),
            path
        );
        assert!(
            files
                .materialize_env("x", "CODE_EXPLORER_SURELY_UNSET_VAR")
                .is_err()
        );
    }

    fn envs(cmd: &Command) -> HashMap<String, String> {
        cmd.as_std()
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect()
    }

    #[test]
    fn credential_env_for_each_kind() {
        let kh = Path::new("/etc/known hosts");
        let mut cmd = proc::scrubbed_command("git");
        apply_credential(
            &mut cmd,
            &ResolvedCredential::SshKey {
                key_path: PathBuf::from("/k/it's"),
            },
            kh,
        );
        let e = envs(&cmd);
        let ssh = &e["GIT_SSH_COMMAND"];
        assert!(ssh.contains("-i '/k/it'\\''s'"), "{ssh}");
        assert!(ssh.contains("IdentitiesOnly=yes") && ssh.contains("StrictHostKeyChecking=yes"));
        assert!(
            ssh.contains("UserKnownHostsFile='/etc/known hosts'") && ssh.contains("BatchMode=yes")
        );

        let mut cmd = proc::scrubbed_command("git");
        apply_credential(
            &mut cmd,
            &ResolvedCredential::HttpsToken {
                username: "bob".into(),
                secret_path: PathBuf::from("/s/f"),
            },
            kh,
        );
        let e = envs(&cmd);
        assert!(Path::new(&e["GIT_ASKPASS"]).is_absolute());
        assert_eq!(e["CODE_EXPLORER_ASKPASS_USER"], "bob");
        assert_eq!(e["CODE_EXPLORER_ASKPASS_FILE"], "/s/f");
        assert!(!e["GIT_SSH_COMMAND"].contains("-i "));
    }

    #[tokio::test]
    async fn askpass_wiring_feeds_git_credential_fill() {
        if !git_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("askpass.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s' \"$CODE_EXPLORER_ASKPASS_USER\" ;;\n  *) cat \"$CODE_EXPLORER_ASKPASS_FILE\" ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = tmp.path().join("secret");
        std::fs::write(&secret, "tok-123\n").unwrap();

        let git = runner();
        let mut cmd = git.base_cmd();
        cmd.args(["credential", "fill"]);
        apply_credential_with(
            &mut cmd,
            &ResolvedCredential::HttpsToken {
                username: "bob".into(),
                secret_path: secret,
            },
            Path::new("/nonexistent"),
            &script.to_string_lossy(),
        );
        let out = proc::run_with_stdin(
            cmd,
            Duration::from_secs(10),
            "credential",
            b"protocol=https\nhost=example.com\n\n".to_vec(),
        )
        .await
        .unwrap();
        let text = lossy(&out.stdout);
        assert!(text.contains("username=bob"), "{text}");
        assert!(text.contains("password=tok-123"), "{text}");
    }

    #[tokio::test]
    async fn missing_credential_fails_fast_instead_of_hanging() {
        if !git_available() {
            return;
        }
        let git = runner();
        let mut cmd = git.base_cmd();
        cmd.args(["credential", "fill"]);
        apply_credential(
            &mut cmd,
            &ResolvedCredential::None,
            Path::new("/nonexistent"),
        );
        let started = std::time::Instant::now();
        let err = proc::run_with_stdin(
            cmd,
            Duration::from_secs(10),
            "credential",
            b"protocol=https\nhost=example.com\n\n".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        let ProcError::Failed { stderr, .. } = err else {
            panic!("expected failure, got {err:?}");
        };
        assert_eq!(classify(&stderr), ErrorClass::Auth, "{stderr}");
    }
}
