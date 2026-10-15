//! Background puller: one task per repo that clones, fetches, scans and swaps snapshots.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Credential, OnScanError, ScanPolicy};
use crate::git::{self, CredentialFiles, GitError, GitRunner, Oid, ResolvedCredential};
use crate::proc;
use crate::redact::Redactor;
use crate::scan::{self, Finding, Scanner};
use crate::snapshot::{
    ErrorClass, FileIndex, PullError, Registry, RepoDirs, RepoState, Snapshot, StateFile,
    StoredFinding, data_layout,
};

const BACKOFF_BASE: Duration = Duration::from_secs(30);
const COMMIT_MESSAGES_FILE: &str = "commit_messages";
static NO_CREDENTIAL: ResolvedCredential = ResolvedCredential::None;

/// Credential name to ready-to-use git credential. Owns the temp files written for env-var secrets.
#[derive(Debug)]
pub struct ResolvedCreds {
    map: HashMap<String, ResolvedCredential>,
    _files: CredentialFiles,
}

impl ResolvedCreds {
    pub fn prepare(config: &Config) -> std::io::Result<ResolvedCreds> {
        let mut files = CredentialFiles::new()?;
        let mut map = HashMap::new();
        for (name, cred) in &config.credentials {
            let resolved = match cred {
                Credential::HttpsToken {
                    username,
                    secret_file,
                    env,
                    ..
                } => {
                    let secret_path = match (secret_file, env) {
                        (Some(path), _) => path.clone(),
                        (None, Some(var)) => files.materialize_env(name, var)?,
                        (None, None) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("credential {name:?} has neither secret_file nor env"),
                            ));
                        }
                    };
                    ResolvedCredential::HttpsToken {
                        username: username.clone(),
                        secret_path,
                    }
                }
                Credential::SshKey { secret_file, .. } => ResolvedCredential::SshKey {
                    key_path: secret_file.clone(),
                },
            };
            map.insert(name.clone(), resolved);
        }
        Ok(ResolvedCreds { map, _files: files })
    }

    /// Unknown names resolve to no credential, which makes git fail with an auth error.
    pub fn get(&self, name: &str) -> &ResolvedCredential {
        self.map.get(name).unwrap_or(&NO_CREDENTIAL)
    }
}

#[derive(Clone)]
pub struct PullerDeps {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
    pub git: Arc<GitRunner>,
    pub scanner: Arc<dyn Scanner>,
    pub creds: Arc<ResolvedCreds>,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    Unchanged,
    Updated(Oid),
}

pub struct Puller;

impl Puller {
    /// Starts one task per configured repo; they stop when `deps.cancel` fires.
    pub fn spawn(deps: PullerDeps) -> Vec<JoinHandle<()>> {
        deps.registry
            .iter()
            .map(|state| tokio::spawn(run_repo(deps.clone(), state.clone())))
            .collect()
    }
}

fn internal(message: impl Into<String>) -> PullError {
    PullError {
        class: ErrorClass::Internal,
        message: git::scrub_stderr(&message.into()),
    }
}

fn git_err(e: GitError) -> PullError {
    PullError {
        class: e.class().into(),
        message: git::scrub_stderr(&e.to_string()),
    }
}

/// `min(interval, 30s * 2^(failures-1))`, or the plain interval with no failures.
pub fn backoff(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return interval;
    }
    let factor = 1u32 << (failures - 1).min(16);
    interval.min(BACKOFF_BASE.saturating_mul(factor))
}

fn jitter(max: Duration) -> Duration {
    let ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    if ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::random_range(0..=ms))
}

fn next_delay(deps: &PullerDeps, state: &RepoState) -> Duration {
    let interval = state.cfg.pull_interval_or(deps.config.pull.interval);
    let failures = state.status().consecutive_failures;
    backoff(interval, failures) + jitter(deps.config.pull.jitter)
}

/// Serves the stored snapshot before any network call, then fetches forever until cancelled.
pub async fn run_repo(deps: PullerDeps, state: Arc<RepoState>) {
    restore_state(&deps, &state).await;
    loop {
        tokio::select! {
            () = deps.cancel.cancelled() => return,
            _ = pull_once(&deps, &state) => {}
        }
        let delay = next_delay(&deps, &state);
        tokio::select! {
            () = deps.cancel.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

fn stale_dirs_cleanup(snapshots: &Path, keep: Option<&Path>) {
    let Ok(read) = std::fs::read_dir(snapshots) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if keep.is_some_and(|k| k == path) {
            continue;
        }
        if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(error = %e, "could not remove a stale snapshot directory");
        }
    }
}

fn worktree_is_safe(snapshots: &Path, worktree: &Path) -> bool {
    worktree.starts_with(snapshots)
        && worktree != snapshots
        && !worktree.components().any(|c| c == Component::ParentDir)
}

/// Publishes the snapshot recorded in `state.json` when its worktree and commit are still on disk.
/// Returns whether a snapshot was published. Stray snapshot directories are removed either way.
pub async fn restore_state(deps: &PullerDeps, state: &Arc<RepoState>) -> bool {
    let dirs = data_layout(&deps.config.server.data_dir, &state.cfg.id);
    let restored = try_restore(deps, state, &dirs).await;
    let keep = restored.as_deref();
    let snapshots = dirs.snapshots.clone();
    let keep_owned = keep.map(Path::to_path_buf);
    let _ =
        tokio::task::spawn_blocking(move || stale_dirs_cleanup(&snapshots, keep_owned.as_deref()))
            .await;
    if dirs.git.join("HEAD").exists() {
        let _ = deps.git.worktree_prune(&dirs.git).await;
    }
    restored.is_some()
}

async fn try_restore(
    deps: &PullerDeps,
    state: &Arc<RepoState>,
    dirs: &RepoDirs,
) -> Option<PathBuf> {
    let started = Instant::now();
    let state_path = dirs.state.clone();
    let sf = tokio::task::spawn_blocking(move || StateFile::read(&state_path))
        .await
        .ok()?
        .ok()?;
    if !worktree_is_safe(&dirs.snapshots, &sf.worktree)
        || !sf.worktree.is_dir()
        || !dirs.git.join("HEAD").exists()
    {
        return None;
    }
    match deps.git.rev_parse(&dirs.git, sf.commit.as_str()).await {
        Ok(oid) if oid == sf.commit => {}
        _ => return None,
    }
    let policy = state.cfg.scan_policy_or(deps.config.scan.policy);
    let stored: Vec<Finding> = sf.findings.iter().map(Finding::from).collect();
    let findings = scan::apply_allowlist(stored, &deps.config.scan.allowlist);
    if policy == ScanPolicy::Block && !findings.is_empty() {
        return None;
    }
    let tree = deps.git.ls_tree(&dirs.git, &sf.commit).await.ok()?;
    let index = FileIndex::from_git(tree).ok()?;
    let redactor = match policy {
        ScanPolicy::Redact => scan::findings_to_redactor(&findings),
        ScanPolicy::Warn | ScanPolicy::Block => Redactor::empty(),
    };
    let snapshot = Snapshot::new(
        sf.commit.clone(),
        sf.commit_time,
        sf.commit_subject,
        sf.worktree.clone(),
        index,
        Arc::new(redactor),
        findings.len(),
        sf.pulled_at,
    );
    state.set_snapshot(Arc::new(snapshot));
    state.record_restored(sf.pulled_at, findings.len());
    tracing::info!(
        event = "pull",
        repo = %state.cfg.id,
        new_commit = %sf.commit.short(),
        duration_ms = elapsed_ms(started),
        result = "restored",
    );
    Some(sf.worktree)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One pull attempt: clone or fetch, and build and swap a snapshot when the branch moved.
/// Records success or failure on `state`; this is the single code path the loop and tests use.
pub async fn pull_once(
    deps: &PullerDeps,
    state: &Arc<RepoState>,
) -> Result<PullOutcome, PullError> {
    let started = Instant::now();
    let old = state.snapshot().map(|s| s.commit.short().to_owned());
    state.record_attempt();
    let result = pull_inner(deps, state).await;
    let (outcome, new_commit, error): (&str, Option<String>, Option<&PullError>) = match &result {
        Ok(PullOutcome::Unchanged) => ("unchanged", old.clone(), None),
        Ok(PullOutcome::Updated(oid)) => ("updated", Some(oid.short().to_owned()), None),
        Err(e) => ("error", old.clone(), Some(e)),
    };
    match error {
        None => tracing::info!(
            event = "pull",
            repo = %state.cfg.id,
            old_commit = old.as_deref().unwrap_or(""),
            new_commit = new_commit.as_deref().unwrap_or(""),
            duration_ms = elapsed_ms(started),
            result = outcome,
        ),
        Some(e) => tracing::warn!(
            event = "pull",
            repo = %state.cfg.id,
            old_commit = old.as_deref().unwrap_or(""),
            new_commit = new_commit.as_deref().unwrap_or(""),
            duration_ms = elapsed_ms(started),
            result = outcome,
            error_class = e.class.as_str(),
            error = %e.message,
        ),
    }
    match &result {
        Ok(_) => state.record_success(),
        Err(e) => state.record_failure(e.clone()),
    }
    result
}

async fn pull_inner(deps: &PullerDeps, state: &Arc<RepoState>) -> Result<PullOutcome, PullError> {
    let cfg = &state.cfg;
    let dirs = data_layout(&deps.config.server.data_dir, &cfg.id);
    let credential = deps
        .config
        .credentials
        .get(&cfg.credential)
        .ok_or_else(|| internal(format!("unknown credential {:?}", cfg.credential)))?;
    let url = cfg.remote_url(credential);
    let cred = deps.creds.get(&cfg.credential);
    let depth = deps.config.pull.depth;

    if dirs.git.join("HEAD").exists() {
        point_origin_at(deps, &dirs.git, &url).await?;
        deps.git
            .fetch(&dirs.git, &cfg.branch, depth, cred)
            .await
            .map_err(git_err)?;
    } else {
        clone_into(deps, state, &dirs, &url, cred).await?;
    }

    let tip = deps
        .git
        .rev_parse(&dirs.git, &format!("refs/heads/{}", cfg.branch))
        .await
        .map_err(git_err)?;
    if state.snapshot().is_some_and(|s| s.commit == tip) {
        return Ok(PullOutcome::Unchanged);
    }

    let built = build_snapshot(deps, state, &dirs, &tip).await?;
    let state_file = StateFile {
        commit: built.snapshot.commit.clone(),
        commit_time: built.snapshot.commit_time,
        commit_subject: built.snapshot.commit_subject.clone(),
        worktree: built.snapshot.root.clone(),
        pulled_at: built.snapshot.pulled_at,
        findings: built.findings.iter().map(StoredFinding::from).collect(),
    };
    let state_path = dirs.state.clone();
    match tokio::task::spawn_blocking(move || state_file.write(&state_path)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(repo = %cfg.id, error = %e, "could not write state.json"),
        Err(e) => tracing::warn!(repo = %cfg.id, error = %e, "state.json writer failed"),
    }
    state.record_scan(built.findings.len(), false);
    if let Some(prev) = state.set_snapshot(Arc::new(built.snapshot)) {
        prev.mark_remove_on_drop();
    }
    Ok(PullOutcome::Updated(tip))
}

/// Keeps `remote.origin.url` in step with the config, which can change between runs.
async fn point_origin_at(deps: &PullerDeps, git_dir: &Path, url: &str) -> Result<(), PullError> {
    let mut cmd = deps.git.base_cmd();
    cmd.arg("-C")
        .arg(git_dir)
        .args(["remote", "set-url", "origin", "--"])
        .arg(url);
    proc::run(cmd, deps.config.limits.git_timeout, "remote-set-url")
        .await
        .map(|_| ())
        .map_err(|e| internal(e.to_string()))
}

async fn clone_into(
    deps: &PullerDeps,
    state: &RepoState,
    dirs: &RepoDirs,
    url: &str,
    cred: &ResolvedCredential,
) -> Result<(), PullError> {
    let base = dirs
        .git
        .parent()
        .ok_or_else(|| internal("repo directory has no parent"))?;
    let staging = base.join("git.clone");
    for leftover in [&staging, &dirs.git] {
        match tokio::fs::remove_dir_all(leftover).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(internal(format!(
                    "cannot clear {}: {e}",
                    leftover.display()
                )));
            }
        }
    }
    tokio::fs::create_dir_all(base)
        .await
        .map_err(|e| internal(format!("cannot create {}: {e}", base.display())))?;
    state.record_clone_started();
    let cloned = deps
        .git
        .clone_bare(
            url,
            &state.cfg.branch,
            deps.config.pull.depth,
            &staging,
            cred,
        )
        .await;
    state.record_clone_finished();
    cloned.map_err(git_err)?;
    tokio::fs::rename(&staging, &dirs.git)
        .await
        .map_err(|e| internal(format!("cannot move the fresh clone into place: {e}")))
}

struct Built {
    snapshot: Snapshot,
    findings: Vec<Finding>,
}

async fn build_snapshot(
    deps: &PullerDeps,
    state: &RepoState,
    dirs: &RepoDirs,
    tip: &Oid,
) -> Result<Built, PullError> {
    let _ = deps.git.worktree_prune(&dirs.git).await;
    tokio::fs::create_dir_all(&dirs.snapshots)
        .await
        .map_err(|e| internal(format!("cannot create snapshots dir: {e}")))?;
    let mut dest = dirs.snapshots.join(tip.as_str());
    if dest.exists() {
        dest = dirs.snapshots.join(format!(
            "{}-{}",
            tip.as_str(),
            Utc::now().timestamp_millis()
        ));
    }
    deps.git
        .worktree_add(&dirs.git, tip, &dest)
        .await
        .map_err(git_err)?;
    match prepare_snapshot(deps, state, dirs, tip, &dest).await {
        Ok(built) => Ok(built),
        Err(e) => {
            if let Err(clean) = deps.git.worktree_remove(&dirs.git, &dest).await {
                tracing::warn!(repo = %state.cfg.id, error = %git::scrub_stderr(&clean.to_string()), "could not remove an unused worktree");
            }
            Err(e)
        }
    }
}

async fn prepare_snapshot(
    deps: &PullerDeps,
    state: &RepoState,
    dirs: &RepoDirs,
    tip: &Oid,
    dest: &Path,
) -> Result<Built, PullError> {
    let tree = deps.git.ls_tree(&dirs.git, tip).await.map_err(git_err)?;
    let index = FileIndex::from_git(tree).map_err(|e| internal(e.to_string()))?;
    let meta = deps
        .git
        .commit_meta(&dirs.git, tip)
        .await
        .map_err(git_err)?;
    let messages = deps
        .git
        .commit_messages(&dirs.git, tip, deps.config.pull.depth as usize)
        .await
        .map_err(git_err)?;
    let scratch = tempfile::Builder::new()
        .prefix("cex-msgs-")
        .tempdir()
        .map_err(|e| internal(format!("cannot create scan scratch dir: {e}")))?;
    let messages_file = scratch.path().join(COMMIT_MESSAGES_FILE);
    tokio::fs::write(&messages_file, messages)
        .await
        .map_err(|e| internal(format!("cannot write commit messages: {e}")))?;

    let repo = &state.cfg.id;
    let policy = state.cfg.scan_policy_or(deps.config.scan.policy);
    let scanned = deps.scanner.scan_dir(dest, &[messages_file]).await;
    drop(scratch);

    let findings = match scanned {
        Ok(found) => scan::apply_allowlist(found, &deps.config.scan.allowlist),
        Err(e) => {
            let message = git::scrub_stderr(&e.to_string());
            let action = match deps.config.scan.on_scan_error {
                OnScanError::Hold => "hold",
                OnScanError::Serve => "served_unscanned",
            };
            tracing::warn!(event = "scan", repo = %repo, commit = %tip.short(), policy = ?policy, action, error = %message);
            if deps.config.scan.on_scan_error == OnScanError::Hold {
                return Err(PullError {
                    class: ErrorClass::Scan,
                    message: format!("scanner failed, keeping the previous snapshot: {message}"),
                });
            }
            Vec::new()
        }
    };
    let count = findings.len();
    let action = match (policy, count) {
        (_, 0) => "clean",
        (ScanPolicy::Redact, _) => "redacted",
        (ScanPolicy::Warn, _) => "warned",
        (ScanPolicy::Block, _) => "held",
    };
    tracing::info!(
        event = "scan",
        repo = %repo,
        commit = %tip.short(),
        findings = count,
        policy = ?policy,
        action,
    );
    if count > 0 {
        let mut rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        rules.sort_unstable();
        rules.dedup();
        tracing::warn!(repo = %repo, commit = %tip.short(), findings = count, rules = %rules.join(","), "secrets found in snapshot");
    }
    if policy == ScanPolicy::Block && count > 0 {
        state.record_scan(count, true);
        return Err(PullError {
            class: ErrorClass::SecretFound,
            message: format!(
                "{count} secret finding(s) in {} after the allowlist; snapshot not published (scan.policy = block)",
                tip.short()
            ),
        });
    }
    let redactor = match policy {
        ScanPolicy::Redact => scan::findings_to_redactor(&findings),
        ScanPolicy::Warn | ScanPolicy::Block => Redactor::empty(),
    };
    let snapshot = Snapshot::new(
        tip.clone(),
        meta.time,
        meta.subject,
        dest.to_path_buf(),
        index,
        Arc::new(redactor),
        count,
        Utc::now(),
    );
    Ok(Built { snapshot, findings })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::scan::{GitleaksScanner, ScanError};
    use crate::snapshot::RepoStatus;
    use futures::future::BoxFuture;
    use std::process::Command as StdCommand;

    fn fake_aws() -> String {
        format!("{}{}", "AKIA", "QYLPMN5HHHFPZAM2")
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

    fn commit(src: &Path, file: &str, body: &str, msg: &str) {
        let path = src.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        sh_git(src, &["add", "."]);
        sh_git(src, &["commit", "-q", "-m", msg]);
    }

    fn remove_file_commit(src: &Path, file: &str, msg: &str) {
        sh_git(src, &["rm", "-q", file]);
        sh_git(src, &["commit", "-q", "-m", msg]);
    }

    struct NoScan;

    impl Scanner for NoScan {
        fn scan_dir<'a>(
            &'a self,
            _: &'a Path,
            _: &'a [PathBuf],
        ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn name(&self) -> &str {
            "none"
        }
        fn version(&self) -> BoxFuture<'_, Option<String>> {
            Box::pin(async { None })
        }
    }

    struct BrokenScan;

    impl Scanner for BrokenScan {
        fn scan_dir<'a>(
            &'a self,
            _: &'a Path,
            _: &'a [PathBuf],
        ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>> {
            Box::pin(async { Err(ScanError::Failed("boom".into())) })
        }
        fn name(&self) -> &str {
            "broken"
        }
        fn version(&self) -> BoxFuture<'_, Option<String>> {
            Box::pin(async { None })
        }
    }

    struct Fx {
        tmp: tempfile::TempDir,
        src: PathBuf,
        deps: PullerDeps,
        state: Arc<RepoState>,
    }

    impl Fx {
        fn data(&self) -> PathBuf {
            self.tmp.path().join("data")
        }

        fn dirs(&self) -> RepoDirs {
            data_layout(&self.data(), "a")
        }

        fn worktrees(&self) -> usize {
            std::fs::read_dir(self.dirs().snapshots)
                .map(|d| d.count())
                .unwrap_or(0)
        }
    }

    fn config_text(tmp: &Path, remote: &Path, scan: &str) -> String {
        let secret = tmp.join("secret");
        std::fs::write(&secret, "not-a-real-token\n").unwrap();
        format!(
            "version = 1\n[server]\ndata_dir = {:?}\n[auth]\n[credentials.c]\ntype = \"https_token\"\nusername = \"u\"\nsecret_file = {:?}\n[scan]\n{scan}\n[[repo]]\nid = \"a\"\nhost = \"github\"\npath = \"example-org/a\"\nbranch = \"main\"\ndescription = \"d\"\ncredential = \"c\"\nremote_url_override = {:?}\n",
            tmp.join("data").display().to_string(),
            secret.display().to_string(),
            format!("file://{}", remote.display()),
        )
    }

    fn load_config(text: &str) -> Config {
        let env = |name: &str| (name == crate::config::ALLOW_LOCAL_REMOTES_ENV).then(|| "1".into());
        Config::from_str_with_env(text, Path::new("config.toml"), &env)
            .unwrap()
            .config
    }

    fn runner() -> Arc<GitRunner> {
        Arc::new(GitRunner::new(
            PathBuf::from("git"),
            git::GitTimeouts {
                fetch: Duration::from_secs(60),
                clone: Duration::from_secs(60),
                command: Duration::from_secs(30),
            },
            PathBuf::from("/nonexistent/known_hosts"),
            git::empty_hooks_dir(),
            true,
        ))
    }

    fn deps_from(config: Config, scanner: Arc<dyn Scanner>) -> (PullerDeps, Arc<RepoState>) {
        let config = Arc::new(config);
        let registry = Arc::new(Registry::new(&config));
        let creds = Arc::new(ResolvedCreds::prepare(&config).unwrap());
        let state = registry.get("a").unwrap().clone();
        let deps = PullerDeps {
            config,
            registry,
            git: runner(),
            scanner,
            creds,
            cancel: CancellationToken::new(),
        };
        (deps, state)
    }

    fn fixture_with(scan: &str, scanner: Arc<dyn Scanner>, secret_in_first: bool) -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("remote");
        std::fs::create_dir(&src).unwrap();
        sh_git(&src, &["init", "-q", "-b", "main"]);
        commit(&src, "README.md", "hello\n", "first commit");
        commit(&src, "src/lib.rs", "pub fn x() {}\n", "add lib");
        if secret_in_first {
            let body = format!("key = \"{}\"\n", fake_aws());
            commit(&src, "config/app.txt", &body, "add config");
        }
        let text = config_text(tmp.path(), &src, scan);
        let (deps, state) = deps_from(load_config(&text), scanner);
        Fx {
            tmp,
            src,
            deps,
            state,
        }
    }

    fn fixture() -> Fx {
        fixture_with("", Arc::new(NoScan), false)
    }

    fn gitleaks() -> Option<Arc<dyn Scanner>> {
        let ok = StdCommand::new("gitleaks")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("gitleaks not on PATH, skipping");
            return None;
        }
        Some(Arc::new(GitleaksScanner::new(
            PathBuf::from("gitleaks"),
            Duration::from_secs(60),
        )))
    }

    fn head(src: &Path) -> Oid {
        let out = StdCommand::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(src)
            .output()
            .unwrap();
        Oid::parse(String::from_utf8_lossy(&out.stdout).trim()).unwrap()
    }

    #[tokio::test]
    async fn first_pull_clones_and_publishes() {
        let fx = fixture();
        assert_eq!(
            fx.state.status_word(Duration::from_secs(60), Utc::now()),
            RepoStatus::Initializing
        );
        let outcome = pull_once(&fx.deps, &fx.state).await.unwrap();
        let tip = head(&fx.src);
        assert_eq!(outcome, PullOutcome::Updated(tip.clone()));
        let snap = fx.state.snapshot().unwrap();
        assert_eq!(snap.commit, tip);
        assert_eq!(snap.commit_subject, "add lib");
        assert_eq!(snap.index.len(), 2);
        assert!(snap.root.join("src/lib.rs").is_file());
        assert!(snap.root.starts_with(fx.dirs().snapshots));
        assert!(snap.redactor.is_empty());
        assert_eq!(snap.findings, 0);
        let st = fx.state.status();
        assert!(st.last_success.is_some());
        assert!(!st.initializing);
        assert!(st.clone_started.is_none());
        assert_eq!(
            fx.state.status_word(Duration::from_secs(60), Utc::now()),
            RepoStatus::Ready
        );
        let sf = StateFile::read(&fx.dirs().state).unwrap();
        assert_eq!(sf.commit, tip);
        assert_eq!(sf.worktree, snap.root);
    }

    #[tokio::test]
    async fn same_tip_is_unchanged_and_new_commit_updates() {
        let fx = fixture();
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let first = fx.state.snapshot().unwrap();
        assert_eq!(
            pull_once(&fx.deps, &fx.state).await.unwrap(),
            PullOutcome::Unchanged
        );
        assert!(Arc::ptr_eq(&first, &fx.state.snapshot().unwrap()));

        commit(&fx.src, "docs/guide.md", "guide\n", "add guide");
        let tip = head(&fx.src);
        assert_eq!(
            pull_once(&fx.deps, &fx.state).await.unwrap(),
            PullOutcome::Updated(tip.clone())
        );
        let second = fx.state.snapshot().unwrap();
        assert_eq!(second.commit, tip);
        assert_eq!(second.index.len(), 3);
        assert_eq!(StateFile::read(&fx.dirs().state).unwrap().commit, tip);

        let old_root = first.root.clone();
        assert!(old_root.exists(), "still held by a reader");
        drop(first);
        for _ in 0..100 {
            if !old_root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!old_root.exists(), "old worktree removed once released");
        assert!(second.root.exists());
        assert_eq!(fx.worktrees(), 1);
    }

    #[tokio::test]
    async fn fetch_failure_keeps_serving_and_recovers() {
        let fx = fixture();
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let commit_before = fx.state.snapshot().unwrap().commit.clone();
        let moved = fx.tmp.path().join("remote-away");
        std::fs::rename(&fx.src, &moved).unwrap();

        let err = pull_once(&fx.deps, &fx.state).await.unwrap_err();
        assert!(
            matches!(err.class, ErrorClass::Network | ErrorClass::Internal),
            "{err:?}"
        );
        assert_eq!(fx.state.snapshot().unwrap().commit, commit_before);
        let st = fx.state.status();
        assert_eq!(st.consecutive_failures, 1);
        assert_eq!(st.last_error.as_ref().unwrap().class, err.class);
        assert!(st.last_success.is_some());
        pull_once(&fx.deps, &fx.state).await.unwrap_err();
        assert_eq!(fx.state.status().consecutive_failures, 2);

        std::fs::rename(&moved, &fx.src).unwrap();
        assert_eq!(
            pull_once(&fx.deps, &fx.state).await.unwrap(),
            PullOutcome::Unchanged
        );
        let st = fx.state.status();
        assert_eq!(st.consecutive_failures, 0);
        assert!(st.last_error.is_none());
    }

    #[tokio::test]
    async fn first_clone_failure_is_unavailable() {
        let fx = fixture();
        std::fs::rename(&fx.src, fx.tmp.path().join("gone")).unwrap();
        pull_once(&fx.deps, &fx.state).await.unwrap_err();
        assert!(fx.state.snapshot().is_none());
        assert_eq!(
            fx.state.status_word(Duration::from_secs(60), Utc::now()),
            RepoStatus::Unavailable
        );
        assert!(!fx.dirs().git.exists());
        assert!(!fx.dirs().git.with_file_name("git.clone").exists());
    }

    #[tokio::test]
    async fn redact_policy_masks_the_planted_secret() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with("policy = \"redact\"", scanner, true);
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let snap = fx.state.snapshot().unwrap();
        assert_eq!(snap.findings, 1);
        assert_eq!(snap.redactor.len(), 1);
        let text = format!("line with {} inside", fake_aws());
        let (out, hit) = snap.redactor.redact(&text);
        assert!(hit);
        assert_eq!(out, "line with [REDACTED:aws-access-token] inside");
        let st = fx.state.status();
        assert_eq!(st.scan_findings, 1);
        assert!(!st.scan_held);
        let sf = StateFile::read(&fx.dirs().state).unwrap();
        assert_eq!(sf.findings.len(), 1);
        assert_eq!(
            sf.findings[0].fingerprint,
            "config/app.txt:aws-access-token:1"
        );
    }

    #[tokio::test]
    async fn warn_policy_serves_with_empty_redactor() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with("policy = \"warn\"", scanner, true);
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let snap = fx.state.snapshot().unwrap();
        assert_eq!(snap.findings, 1);
        assert!(snap.redactor.is_empty());
        assert!(!fx.state.status().scan_held);
    }

    #[tokio::test]
    async fn allowlisted_fingerprint_is_not_a_finding() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with(
            "policy = \"block\"\nallowlist = [\"config/app.txt:aws-access-token:1\"]",
            scanner,
            true,
        );
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let snap = fx.state.snapshot().unwrap();
        assert_eq!(snap.findings, 0);
        assert!(snap.redactor.is_empty());
    }

    #[tokio::test]
    async fn block_policy_holds_and_keeps_the_previous_snapshot() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with("policy = \"block\"", scanner, false);
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let clean = fx.state.snapshot().unwrap().commit.clone();

        let body = format!("key = \"{}\"\n", fake_aws());
        commit(&fx.src, "leak.txt", &body, "oops");
        let err = pull_once(&fx.deps, &fx.state).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::SecretFound);
        assert!(!err.message.contains(&fake_aws()));
        assert_eq!(fx.state.snapshot().unwrap().commit, clean);
        let st = fx.state.status();
        assert!(st.scan_held);
        assert_eq!(st.scan_findings, 1);
        assert_eq!(
            st.last_error.as_ref().unwrap().class,
            ErrorClass::SecretFound
        );
        assert_eq!(fx.worktrees(), 1, "held worktree removed");
        assert_eq!(StateFile::read(&fx.dirs().state).unwrap().commit, clean);

        remove_file_commit(&fx.src, "leak.txt", "remove it");
        let tip = head(&fx.src);
        assert_eq!(
            pull_once(&fx.deps, &fx.state).await.unwrap(),
            PullOutcome::Updated(tip)
        );
        assert!(!fx.state.status().scan_held);
    }

    #[tokio::test]
    async fn block_policy_without_a_snapshot_stays_unavailable() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with("policy = \"block\"", scanner, true);
        let err = pull_once(&fx.deps, &fx.state).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::SecretFound);
        assert!(fx.state.snapshot().is_none());
        assert_eq!(
            fx.state.status_word(Duration::from_secs(60), Utc::now()),
            RepoStatus::Unavailable
        );
        assert_eq!(fx.worktrees(), 0);
        assert!(!fx.dirs().state.exists());
    }

    #[tokio::test]
    async fn scan_error_hold_keeps_old_snapshot() {
        let fx = fixture();
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let before = fx.state.snapshot().unwrap().commit.clone();
        commit(&fx.src, "more.txt", "more\n", "more");

        let mut broken = fx.deps.clone();
        broken.scanner = Arc::new(BrokenScan);
        let err = pull_once(&broken, &fx.state).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Scan);
        assert_eq!(fx.state.snapshot().unwrap().commit, before);
        assert_eq!(fx.worktrees(), 1);
    }

    #[tokio::test]
    async fn scan_error_serve_swaps_with_empty_redactor() {
        let fx = fixture_with("on_scan_error = \"serve\"", Arc::new(BrokenScan), false);
        let outcome = pull_once(&fx.deps, &fx.state).await.unwrap();
        assert!(matches!(outcome, PullOutcome::Updated(_)));
        let snap = fx.state.snapshot().unwrap();
        assert!(snap.redactor.is_empty());
        assert_eq!(snap.findings, 0);
    }

    #[tokio::test]
    async fn restart_serves_stored_snapshot_before_any_network() {
        let Some(scanner) = gitleaks() else { return };
        let fx = fixture_with("policy = \"redact\"", scanner, true);
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let commit_id = fx.state.snapshot().unwrap().commit.clone();
        let root = fx.state.snapshot().unwrap().root.clone();
        let stray = fx.dirs().snapshots.join("stray-dir");
        std::fs::create_dir_all(&stray).unwrap();

        let missing = fx.tmp.path().join("no-such-remote");
        let text = config_text(fx.tmp.path(), &missing, "policy = \"redact\"");
        let (deps2, state2) = deps_from(load_config(&text), Arc::new(NoScan));
        assert!(state2.snapshot().is_none());
        assert!(restore_state(&deps2, &state2).await);

        let snap = state2.snapshot().unwrap();
        assert_eq!(snap.commit, commit_id);
        assert_eq!(snap.root, root);
        assert_eq!(snap.findings, 1);
        let key = fake_aws();
        let (out, hit) = snap.redactor.redact(&key);
        assert!(hit, "{out}");
        assert!(
            snap.index
                .get(&crate::paths::RepoPath::parse("config/app.txt").unwrap())
                .is_some()
        );
        assert_eq!(
            state2.status_word(Duration::from_secs(60), Utc::now()),
            RepoStatus::Ready
        );
        assert!(!stray.exists(), "stray snapshot dir cleaned");
        assert!(root.exists());

        let err = pull_once(&deps2, &state2).await.unwrap_err();
        assert!(matches!(
            err.class,
            ErrorClass::Network | ErrorClass::Internal
        ));
        assert_eq!(state2.snapshot().unwrap().commit, commit_id);
    }

    #[tokio::test]
    async fn run_repo_serves_restored_snapshot_while_the_remote_is_down() {
        let fx = fixture();
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let commit_id = fx.state.snapshot().unwrap().commit.clone();

        let missing = fx.tmp.path().join("no-such-remote");
        let text = config_text(fx.tmp.path(), &missing, "");
        let (deps2, state2) = deps_from(load_config(&text), Arc::new(NoScan));
        let cancel = deps2.cancel.clone();
        let handles = Puller::spawn(deps2);
        assert_eq!(handles.len(), 1);
        let mut waited = 0;
        while state2.status().last_error.is_none() && waited < 400 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        }
        cancel.cancel();
        for h in handles {
            h.await.unwrap();
        }
        assert!(state2.status().last_error.is_some());
        assert_eq!(state2.snapshot().unwrap().commit, commit_id);
    }

    #[tokio::test]
    async fn restore_rejects_bad_state() {
        let fx = fixture();
        pull_once(&fx.deps, &fx.state).await.unwrap();
        let sf = StateFile::read(&fx.dirs().state).unwrap();

        std::fs::write(fx.dirs().state, "{broken").unwrap();
        let (deps, state) = deps_from(
            load_config(&config_text(fx.tmp.path(), &fx.src, "")),
            Arc::new(NoScan),
        );
        assert!(!restore_state(&deps, &state).await);
        assert!(state.snapshot().is_none());

        let outside = StateFile {
            worktree: fx.tmp.path().to_path_buf(),
            ..sf.clone()
        };
        outside.write(&fx.dirs().state).unwrap();
        assert!(!restore_state(&deps, &state).await);
        assert!(
            fx.tmp.path().exists(),
            "never deletes outside the snapshots dir"
        );

        let escaping = StateFile {
            worktree: fx.dirs().snapshots.join("../../x"),
            ..sf
        };
        escaping.write(&fx.dirs().state).unwrap();
        assert!(!restore_state(&deps, &state).await);
    }

    #[test]
    fn backoff_schedule() {
        let interval = Duration::from_secs(300);
        assert_eq!(backoff(interval, 0), interval);
        assert_eq!(backoff(interval, 1), Duration::from_secs(30));
        assert_eq!(backoff(interval, 2), Duration::from_secs(60));
        assert_eq!(backoff(interval, 3), Duration::from_secs(120));
        assert_eq!(backoff(interval, 4), Duration::from_secs(240));
        assert_eq!(backoff(interval, 5), interval);
        assert_eq!(backoff(interval, 5000), interval);
        assert_eq!(backoff(Duration::from_secs(10), 1), Duration::from_secs(10));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
        for _ in 0..50 {
            assert!(jitter(Duration::from_millis(40)) <= Duration::from_millis(40));
        }
    }

    #[test]
    fn creds_resolve_files_and_env() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret");
        let key = tmp.path().join("key");
        std::fs::write(&secret, "tok\n").unwrap();
        std::fs::write(&key, "k\n").unwrap();
        let known = tmp.path().join("known_hosts");
        std::fs::write(&known, "example.com ssh-ed25519 AAAA\n").unwrap();
        let text = format!(
            "version = 1\n[server]\ndata_dir = {:?}\n[auth]\n[pull]\nknown_hosts_file = {:?}\n[credentials.file]\ntype = \"https_token\"\nusername = \"u\"\nsecret_file = {:?}\n[credentials.envc]\ntype = \"https_token\"\nusername = \"v\"\nenv = \"PATH\"\n[credentials.ssh]\ntype = \"ssh_key\"\nsecret_file = {:?}\n[[repo]]\nid = \"a\"\nhost = \"github\"\npath = \"example-org/a\"\nbranch = \"main\"\ndescription = \"d\"\ncredential = \"file\"\n",
            tmp.path().join("data").display().to_string(),
            known.display().to_string(),
            secret.display().to_string(),
            key.display().to_string(),
        );
        let env = |n: &str| std::env::var(n).ok();
        let cfg = Config::from_str_with_env(&text, Path::new("c.toml"), &env)
            .unwrap()
            .config;
        let creds = ResolvedCreds::prepare(&cfg).unwrap();
        match creds.get("file") {
            ResolvedCredential::HttpsToken {
                username,
                secret_path,
            } => {
                assert_eq!(username, "u");
                assert_eq!(secret_path, &secret);
            }
            other => panic!("{other:?}"),
        }
        match creds.get("envc") {
            ResolvedCredential::HttpsToken { secret_path, .. } => {
                assert!(secret_path.is_file());
                assert_ne!(secret_path, &secret);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            creds.get("ssh"),
            ResolvedCredential::SshKey { key_path } if key_path == &key
        ));
        assert!(matches!(creds.get("nope"), ResolvedCredential::None));
    }
}
