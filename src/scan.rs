//! Secret scanning: the `Scanner` trait, the gitleaks adapter, allowlist, onboarding report and redactor glue.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::Deserialize;

use crate::git::Oid;
use crate::proc::{self, ProcError};
use crate::redact::Redactor;

/// gitleaks' default rules without its global path allowlist; used instead of any config in the repo.
const GITLEAKS_CONFIG: &str = include_str!("gitleaks.toml");
const MAX_TARGET_MEGABYTES: &str = "50";
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// One detected secret. `path` is relative to the worktree (or the file at `commit` for history
/// findings) and `None` for extra files such as commit messages.
#[derive(Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub path: Option<String>,
    pub line: Option<u64>,
    pub secret: String,
    pub fingerprint: String,
    pub commit: Option<String>,
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("rule_id", &self.rule_id)
            .field("path", &self.path)
            .field("line", &self.line)
            .field("fingerprint", &self.fingerprint)
            .field("commit", &self.commit)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scanner timed out")]
    Timeout,
    #[error("scanner failed: {0}")]
    Failed(String),
    #[error("scanner report could not be parsed: {0}")]
    Parse(String),
    #[error("scanner io error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait Scanner: Send + Sync {
    /// Scans `dir` and, in the same call, every file in `extra_files` (reported with `path: None`).
    fn scan_dir<'a>(
        &'a self,
        dir: &'a Path,
        extra_files: &'a [PathBuf],
    ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>>;

    /// Scans the patches of every commit reachable from `tip` in the (bare, possibly shallow) repo.
    fn scan_git<'a>(
        &'a self,
        repo_dir: &'a Path,
        tip: &'a Oid,
    ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>>;

    fn name(&self) -> &str;

    fn version(&self) -> BoxFuture<'_, Option<String>>;
}

#[derive(Debug, Clone)]
pub struct GitleaksScanner {
    bin: PathBuf,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    #[serde(rename = "RuleID", default)]
    rule_id: String,
    #[serde(rename = "File", default)]
    file: String,
    #[serde(rename = "StartLine", default)]
    start_line: Option<u64>,
    #[serde(rename = "EndLine", default)]
    end_line: Option<u64>,
    #[serde(rename = "StartColumn", default)]
    start_column: Option<u64>,
    #[serde(rename = "EndColumn", default)]
    end_column: Option<u64>,
    #[serde(rename = "Secret", default)]
    secret: String,
    #[serde(rename = "Fingerprint", default)]
    fingerprint: String,
    #[serde(rename = "Commit", default)]
    commit: String,
    #[serde(rename = "Tags", default)]
    tags: Option<Vec<String>>,
}

/// Where gitleaks found a secret it decoded (base64, hex, percent), so the encoded text can be located.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedSpan {
    file: PathBuf,
    line: u64,
    start_column: u64,
    end_column: u64,
}

#[derive(Debug)]
struct Parsed {
    finding: Finding,
    encoded: Option<EncodedSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Worktree findings: paths relative to the target.
    Tree,
    /// Extra files such as commit messages: no path.
    Extra,
    /// `gitleaks git`: paths at a commit, gitleaks' own fingerprint.
    History,
}

fn is_encoding_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-' | b'%')
}

/// The run of base64, hex or percent-encoded characters around gitleaks' (approximate) columns.
fn encoded_token(line: &str, start_column: u64, end_column: u64) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mid = usize::try_from((start_column + end_column) / 2)
        .ok()?
        .saturating_sub(1)
        .min(bytes.len() - 1);
    if !is_encoding_char(bytes[mid]) {
        return None;
    }
    let mut lo = mid;
    while lo > 0 && is_encoding_char(bytes[lo - 1]) {
        lo -= 1;
    }
    let mut hi = mid + 1;
    while hi < bytes.len() && is_encoding_char(bytes[hi]) {
        hi += 1;
    }
    let token = line.get(lo..hi)?;
    (token.len() >= 6).then_some(token)
}

async fn literal_for(span: &EncodedSpan) -> Option<String> {
    let bytes = tokio::fs::read(&span.file).await.ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let idx = usize::try_from(span.line.checked_sub(1)?).ok()?;
    let line = text.lines().nth(idx)?;
    encoded_token(line, span.start_column, span.end_column).map(str::to_owned)
}

impl GitleaksScanner {
    pub fn new(bin: PathBuf, timeout: Duration) -> Self {
        Self { bin, timeout }
    }

    fn command(&self, work: &Path, report: &Path) -> tokio::process::Command {
        let mut cmd = proc::scrubbed_command(&self.bin);
        cmd.args(["--no-banner", "--exit-code", "0", "--report-format", "json"])
            .arg("--report-path")
            .arg(report)
            .args(["--max-target-megabytes", MAX_TARGET_MEGABYTES])
            .args(["--log-level", "error", "--ignore-gitleaks-allow"])
            .arg("--config")
            .arg(work.join("gitleaks.toml"))
            .arg("--gitleaks-ignore-path")
            .arg(work.join("ignore"));
        cmd
    }

    async fn execute(
        &self,
        cmd: tokio::process::Command,
        report: &Path,
    ) -> Result<Vec<u8>, ScanError> {
        match proc::run(cmd, self.timeout, "gitleaks").await {
            Ok(_) => {}
            Err(ProcError::Timeout { .. }) => return Err(ScanError::Timeout),
            Err(ProcError::Spawn(e)) => return Err(ScanError::Io(e)),
            Err(ProcError::Failed { status, stderr, .. }) => {
                let first = stderr.lines().next().unwrap_or("").trim();
                let first: String = first.chars().take(200).collect();
                return Err(ScanError::Failed(format!("exit status {status}: {first}")));
            }
            Err(ProcError::Busy) => return Err(ScanError::Failed("worker pool busy".into())),
        }
        match tokio::fs::read(report).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(ScanError::Io(e)),
        }
    }

    /// One `gitleaks dir` run over `target`; paths and fingerprints come back relative to it.
    async fn run_one(
        &self,
        target: &Path,
        work: &Path,
        tag: &str,
        mode: Mode,
    ) -> Result<Vec<Finding>, ScanError> {
        let report = work.join(format!("{tag}.json"));
        let mut cmd = self.command(work, &report);
        cmd.arg("dir").arg(target);
        let bytes = self.execute(cmd, &report).await?;
        let mut out = Vec::new();
        for p in parse_report(&bytes, target, mode)? {
            let mut finding = p.finding;
            if let Some(span) = &p.encoded {
                match literal_for(span).await {
                    Some(literal) => finding.secret = literal,
                    None => tracing::warn!(
                        rule = %finding.rule_id,
                        "decoded secret could not be located in its file; only the decoded value is redacted"
                    ),
                }
            }
            out.push(finding);
        }
        Ok(out)
    }

    fn workdir() -> Result<tempfile::TempDir, ScanError> {
        let work = tempfile::Builder::new().prefix("cex-scan-").tempdir()?;
        std::fs::write(work.path().join("gitleaks.toml"), GITLEAKS_CONFIG)?;
        std::fs::create_dir(work.path().join("ignore"))?;
        Ok(work)
    }

    async fn scan(&self, dir: &Path, extra_files: &[PathBuf]) -> Result<Vec<Finding>, ScanError> {
        let work = Self::workdir()?;
        let extra_dir = work.path().join("extra");
        if !extra_files.is_empty() {
            std::fs::create_dir(&extra_dir)?;
            for (i, file) in extra_files.iter().enumerate() {
                let name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("extra-{i}"));
                let mut dest = extra_dir.join(&name);
                if dest.exists() {
                    dest = extra_dir.join(format!("{i}-{name}"));
                }
                std::fs::copy(file, dest)?;
            }
        }
        let main = self.run_one(dir, work.path(), "tree", Mode::Tree);
        let extra = async {
            if extra_files.is_empty() {
                Ok(Vec::new())
            } else {
                self.run_one(&extra_dir, work.path(), "extra", Mode::Extra)
                    .await
            }
        };
        let (main, extra) = tokio::join!(main, extra);
        let mut findings = main?;
        findings.extend(extra?);
        Ok(findings)
    }

    async fn scan_history(&self, repo_dir: &Path, tip: &Oid) -> Result<Vec<Finding>, ScanError> {
        let work = Self::workdir()?;
        let report = work.path().join("history.json");
        let mut cmd = self.command(work.path(), &report);
        // first-parent diffs of merges catch content introduced by the merge itself.
        cmd.arg("git")
            .arg(repo_dir)
            .arg(format!("--log-opts=--diff-merges=first-parent {tip}"));
        let bytes = self.execute(cmd, &report).await?;
        Ok(parse_report(&bytes, repo_dir, Mode::History)?
            .into_iter()
            .map(|p| p.finding)
            .collect())
    }
}

impl Scanner for GitleaksScanner {
    fn scan_dir<'a>(
        &'a self,
        dir: &'a Path,
        extra_files: &'a [PathBuf],
    ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>> {
        Box::pin(self.scan(dir, extra_files))
    }

    fn scan_git<'a>(
        &'a self,
        repo_dir: &'a Path,
        tip: &'a Oid,
    ) -> BoxFuture<'a, Result<Vec<Finding>, ScanError>> {
        Box::pin(self.scan_history(repo_dir, tip))
    }

    fn name(&self) -> &str {
        "gitleaks"
    }

    fn version(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move {
            let mut cmd = proc::scrubbed_command(&self.bin);
            cmd.arg("version");
            let out = proc::run(cmd, VERSION_TIMEOUT, "gitleaks-version")
                .await
                .ok()?;
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            (!text.is_empty()).then_some(text)
        })
    }
}

fn parse_report(bytes: &[u8], target: &Path, mode: Mode) -> Result<Vec<Parsed>, ScanError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let raw: Option<Vec<RawFinding>> =
        serde_json::from_slice(bytes).map_err(|e| ScanError::Parse(e.to_string()))?;
    let prefix = format!("{}/", target.display());
    Ok(raw
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            let decoded = r.tags.iter().flatten().any(|t| t.starts_with("decoded:"));
            let encoded = match (mode, decoded, r.start_line, r.start_column, r.end_column) {
                (Mode::Tree | Mode::Extra, true, Some(line), Some(start), Some(end))
                    if r.end_line.is_none_or(|e| e == line) =>
                {
                    let file = Path::new(&r.file);
                    let file = if file.is_absolute() {
                        file.to_path_buf()
                    } else {
                        std::env::current_dir().unwrap_or_default().join(file)
                    };
                    Some(EncodedSpan {
                        file,
                        line,
                        start_column: start,
                        end_column: end,
                    })
                }
                _ => None,
            };
            let rel = r.file.strip_prefix(&prefix).unwrap_or(&r.file).to_owned();
            let finding = match mode {
                Mode::History => Finding {
                    rule_id: r.rule_id,
                    path: Some(rel),
                    line: r.start_line,
                    secret: r.secret,
                    fingerprint: r.fingerprint,
                    commit: (!r.commit.is_empty()).then_some(r.commit),
                },
                Mode::Tree | Mode::Extra => Finding {
                    rule_id: r.rule_id,
                    path: (mode == Mode::Tree).then_some(rel),
                    line: r.start_line,
                    secret: r.secret,
                    fingerprint: r.fingerprint.replace(&prefix, ""),
                    commit: None,
                },
            };
            Parsed { finding, encoded }
        })
        .collect())
}

/// Adds history findings whose value is not already a worktree finding, so one value counts once
/// and allowlisting it at the tip also covers its copies in history.
pub fn merge_history(mut tree: Vec<Finding>, history: Vec<Finding>) -> Vec<Finding> {
    let known: HashSet<String> = tree.iter().map(|f| f.secret.clone()).collect();
    tree.extend(history.into_iter().filter(|f| !known.contains(&f.secret)));
    tree
}

/// The one scan a snapshot gets, shared by the puller and the `scan` command: the worktree and
/// commit messages, plus the kept history when `history` names the bare repo and tip.
pub async fn scan_snapshot(
    scanner: &dyn Scanner,
    worktree: &Path,
    messages_file: &Path,
    history: Option<(&Path, &Oid)>,
    allowlist: &[String],
) -> Result<Vec<Finding>, ScanError> {
    let extra = [messages_file.to_path_buf()];
    let tree = scanner.scan_dir(worktree, &extra);
    let past = async {
        match history {
            Some((repo, tip)) => scanner.scan_git(repo, tip).await,
            None => Ok(Vec::new()),
        }
    };
    let (tree, past) = tokio::join!(tree, past);
    Ok(apply_allowlist(merge_history(tree?, past?), allowlist))
}

/// Drops findings whose fingerprint is in `allowlist`.
pub fn apply_allowlist(findings: Vec<Finding>, allowlist: &[String]) -> Vec<Finding> {
    if allowlist.is_empty() {
        return findings;
    }
    let allowed: HashSet<&str> = allowlist.iter().map(String::as_str).collect();
    findings
        .into_iter()
        .filter(|f| !allowed.contains(f.fingerprint.as_str()))
        .collect()
}

/// First four characters of a long secret plus `****`; short secrets are fully hidden.
fn mask(secret: &str) -> String {
    if secret.chars().count() >= 8 {
        let head: String = secret.chars().take(4).collect();
        format!("{head}****")
    } else {
        "****".to_owned()
    }
}

/// One line per finding: rule, location, fingerprint and a masked value.
pub fn onboarding_report(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            let path = f.path.as_deref().unwrap_or("<commit messages>");
            let place = match &f.commit {
                Some(c) => format!("{}:{path}", c.get(..12).unwrap_or(c)),
                None => path.to_owned(),
            };
            let loc = match f.line {
                Some(line) => format!("{place}:{line}"),
                None => place,
            };
            format!(
                "{}  {}  fingerprint={}  value={}",
                f.rule_id,
                loc,
                f.fingerprint,
                mask(&f.secret)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Redactor over the distinct secret values of `findings`.
pub fn findings_to_redactor(findings: &[Finding]) -> Redactor {
    let mut seen = HashSet::new();
    let pairs: Vec<(String, String)> = findings
        .iter()
        .filter(|f| seen.insert(f.secret.as_str()))
        .map(|f| (f.secret.clone(), f.rule_id.clone()))
        .collect();
    Redactor::new(&pairs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn bin() -> Option<PathBuf> {
        let ok = std::process::Command::new("gitleaks")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("gitleaks not on PATH, skipping");
        }
        ok.then(|| PathBuf::from("gitleaks"))
    }

    fn scanner() -> Option<GitleaksScanner> {
        bin().map(|b| GitleaksScanner::new(b, Duration::from_secs(60)))
    }

    fn fake_aws() -> String {
        format!("{}{}", "AKIA", "QYLPMN5HHHFPZAM2")
    }

    /// Base64 of `aws_key = "<fake_aws>"`, split so a scan of this file does not decode it.
    fn encoded_aws() -> String {
        ["YXdzX2tleSA9ICJBS0lB", "UVlMUE1ONUhISEZQWkFNMiI="].concat()
    }

    fn planted_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/a.txt"),
            format!("first line\naws_key = \"{}\"\n", fake_aws()),
        )
        .unwrap();
        std::fs::write(dir.path().join("src/clean.txt"), "nothing here\n").unwrap();
        dir
    }

    fn finding(secret: &str, fp: &str) -> Finding {
        Finding {
            rule_id: "rule-x".into(),
            path: Some("a.txt".into()),
            line: Some(3),
            secret: secret.into(),
            fingerprint: fp.into(),
            commit: None,
        }
    }

    #[tokio::test]
    async fn finds_planted_secret_with_relative_path() {
        let Some(s) = scanner() else { return };
        let dir = planted_tree();
        let found = s.scan_dir(dir.path(), &[]).await.unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        let f = &found[0];
        assert_eq!(f.rule_id, "aws-access-token");
        assert_eq!(f.path.as_deref(), Some("src/a.txt"));
        assert_eq!(f.line, Some(2));
        assert_eq!(f.secret, fake_aws());
        assert_eq!(f.fingerprint, "src/a.txt:aws-access-token:2");
        assert_eq!(s.name(), "gitleaks");
        assert!(s.version().await.unwrap().contains('.'));
    }

    #[tokio::test]
    async fn clean_tree_has_no_findings() {
        let Some(s) = scanner() else { return };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        assert!(s.scan_dir(dir.path(), &[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn extra_files_are_scanned_without_a_path() {
        let Some(s) = scanner() else { return };
        let dir = planted_tree();
        let extra_dir = tempfile::tempdir().unwrap();
        let msgs = extra_dir.path().join("commit_messages");
        std::fs::write(&msgs, format!("oops pasted {}\n", fake_aws())).unwrap();
        let found = s.scan_dir(dir.path(), &[msgs]).await.unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        let extra = found.iter().find(|f| f.path.is_none()).unwrap();
        assert_eq!(extra.rule_id, "aws-access-token");
        assert_eq!(extra.fingerprint, "commit_messages:aws-access-token:1");
        assert!(found.iter().any(|f| f.path.as_deref() == Some("src/a.txt")));
    }

    #[tokio::test]
    async fn repo_shipped_config_ignore_and_allow_comments_cannot_hide_secrets() {
        let Some(s) = scanner() else { return };
        let dir = planted_tree();
        std::fs::write(
            dir.path().join(".gitleaks.toml"),
            "[allowlist]\npaths = ['''.*''']\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".gitleaksignore"),
            "src/a.txt:aws-access-token:2\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/b.txt"),
            format!("key = \"{}\" # gitleaks:allow\n", fake_aws()),
        )
        .unwrap();
        let found = s.scan_dir(dir.path(), &[]).await.unwrap();
        let mut paths: Vec<_> = found.iter().filter_map(|f| f.path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec!["src/a.txt", "src/b.txt"], "{found:?}");
    }

    #[tokio::test]
    async fn tiny_timeout_reports_timeout() {
        let Some(b) = bin() else { return };
        let s = GitleaksScanner::new(b, Duration::from_millis(1));
        let dir = planted_tree();
        let err = s.scan_dir(dir.path(), &[]).await.unwrap_err();
        assert!(matches!(err, ScanError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn missing_binary_is_an_io_error() {
        let s = GitleaksScanner::new(
            PathBuf::from("/nonexistent/gitleaks-binary"),
            Duration::from_secs(5),
        );
        let dir = tempfile::tempdir().unwrap();
        let err = s.scan_dir(dir.path(), &[]).await.unwrap_err();
        assert!(matches!(err, ScanError::Io(_)), "{err:?}");
        assert!(s.version().await.is_none());
    }

    #[test]
    fn report_parsing() {
        let t = Path::new("/w/tree");
        let parse = |b: &[u8], m| {
            parse_report(b, t, m).map(|v| v.into_iter().map(|p| p.finding).collect::<Vec<_>>())
        };
        assert!(parse(b"", Mode::Tree).unwrap().is_empty());
        assert!(parse(b"  \n", Mode::Tree).unwrap().is_empty());
        assert!(parse(b"[]", Mode::Tree).unwrap().is_empty());
        assert!(parse(b"null", Mode::Tree).unwrap().is_empty());
        assert!(matches!(
            parse(b"{oops", Mode::Tree),
            Err(ScanError::Parse(_))
        ));
        let json = br#"[{"RuleID":"r","File":"/w/tree/x/y.txt","StartLine":4,"Secret":"s3cr3t-val","Fingerprint":"/w/tree/x/y.txt:r:4","Match":"m"}]"#;
        let f = &parse(json, Mode::Tree).unwrap()[0];
        assert_eq!(f.path.as_deref(), Some("x/y.txt"));
        assert_eq!(f.fingerprint, "x/y.txt:r:4");
        assert_eq!(f.commit, None);
        let f = &parse(json, Mode::Extra).unwrap()[0];
        assert_eq!(f.path, None);
        let git = br#"[{"RuleID":"r","File":"x/y.txt","StartLine":4,"Secret":"s3cr3t-val","Commit":"abc123","Fingerprint":"abc123:x/y.txt:r:4"}]"#;
        let f = &parse(git, Mode::History).unwrap()[0];
        assert_eq!(f.path.as_deref(), Some("x/y.txt"));
        assert_eq!(f.fingerprint, "abc123:x/y.txt:r:4");
        assert_eq!(f.commit.as_deref(), Some("abc123"));
    }

    #[test]
    fn decoded_findings_carry_their_encoded_span() {
        let t = Path::new("/w/tree");
        let json = br#"[{"RuleID":"r","File":"/w/tree/e.txt","StartLine":2,"EndLine":2,"StartColumn":10,"EndColumn":53,"Secret":"plain","Fingerprint":"/w/tree/e.txt:r:2","Tags":["decoded:base64","decode-depth:1"]}]"#;
        let p = &parse_report(json, t, Mode::Tree).unwrap()[0];
        let span = p.encoded.as_ref().unwrap();
        assert_eq!(span.file, PathBuf::from("/w/tree/e.txt"));
        assert_eq!((span.line, span.start_column, span.end_column), (2, 10, 53));
        assert!(
            parse_report(json, t, Mode::History).unwrap()[0]
                .encoded
                .is_none()
        );
    }

    #[test]
    fn encoded_token_tolerates_column_drift() {
        let token = encoded_aws();
        let line = format!("blob = \"{token}\"");
        assert_eq!(encoded_token(&line, 9, 52), Some(token.as_str()));
        assert_eq!(encoded_token(&line, 10, 53), Some(token.as_str()));
        assert_eq!(
            encoded_token("é = \"6162636465666768\"", 7, 22),
            Some("6162636465666768")
        );
        assert_eq!(encoded_token("a = \"abc\"", 6, 8), None);
        assert_eq!(encoded_token("", 1, 5), None);
        assert_eq!(encoded_token("        ", 2, 6), None);
    }

    #[test]
    fn merge_history_counts_each_value_once() {
        let tree = vec![finding("value-at-tip", "a.txt:r:1")];
        let mut dup = finding("value-at-tip", "c1:a.txt:r:1");
        dup.commit = Some("c1".into());
        let mut old = finding("value-only-in-history", "c0:b.txt:r:2");
        old.commit = Some("c0".into());
        let merged = merge_history(tree, vec![dup, old]);
        let fps: Vec<&str> = merged.iter().map(|f| f.fingerprint.as_str()).collect();
        assert_eq!(fps, ["a.txt:r:1", "c0:b.txt:r:2"]);
    }

    #[test]
    fn allowlist_by_fingerprint() {
        let all = vec![
            finding("secret-one", "a.txt:r:3"),
            finding("secret-two", "b.txt:r:9"),
        ];
        let left = apply_allowlist(all.clone(), &["a.txt:r:3".into()]);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].fingerprint, "b.txt:r:9");
        assert_eq!(apply_allowlist(all.clone(), &[]).len(), 2);
        assert!(apply_allowlist(all, &["a.txt:r:3".into(), "b.txt:r:9".into()]).is_empty());
    }

    #[tokio::test]
    async fn allowlist_removes_a_real_finding() {
        let Some(s) = scanner() else { return };
        let dir = planted_tree();
        let found = s.scan_dir(dir.path(), &[]).await.unwrap();
        let left = apply_allowlist(found, &["src/a.txt:aws-access-token:2".into()]);
        assert!(left.is_empty());
    }

    #[test]
    fn onboarding_report_masks_values() {
        let mut msg = finding("short", "commit_messages:r:1");
        msg.path = None;
        msg.line = Some(1);
        let report = onboarding_report(&[finding("AKIAEXAMPLEVALUE1234", "a.txt:rule-x:3"), msg]);
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "rule-x  a.txt:3  fingerprint=a.txt:rule-x:3  value=AKIA****"
        );
        assert!(lines[1].contains("<commit messages>:1"));
        assert!(lines[1].ends_with("value=****"));
        assert!(!report.contains("AKIAEXAMPLEVALUE1234"));
        assert_eq!(onboarding_report(&[]), "");
    }

    #[test]
    fn redactor_dedupes_and_masks() {
        let r = findings_to_redactor(&[
            finding("super-secret-value", "a:r:1"),
            finding("super-secret-value", "b:r:2"),
            finding("tiny", "c:r:3"),
        ]);
        assert_eq!(r.len(), 1);
        let (out, hit) = r.redact("x super-secret-value y");
        assert!(hit);
        assert_eq!(out, "x [REDACTED:rule-x] y");
        assert!(findings_to_redactor(&[]).is_empty());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let f = finding("super-secret-value", "a:r:1");
        assert!(!format!("{f:?}").contains("super-secret"));
    }

    #[tokio::test]
    async fn default_path_allowlist_is_disabled() {
        let Some(s) = scanner() else { return };
        let dir = tempfile::tempdir().unwrap();
        let line = format!("aws_key = \"{}\"\n", fake_aws());
        for path in [
            "node_modules/x/index.js",
            "logo.svg",
            "docs/guide.pdf",
            "package-lock.json",
            "go.sum",
        ] {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, &line).unwrap();
        }
        let found = s.scan_dir(dir.path(), &[]).await.unwrap();
        let mut paths: Vec<String> = found.into_iter().filter_map(|f| f.path).collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                "docs/guide.pdf",
                "go.sum",
                "logo.svg",
                "node_modules/x/index.js",
                "package-lock.json"
            ]
        );
        let global = GITLEAKS_CONFIG.split("[[rules]]").next().unwrap();
        assert!(!global.contains("paths"), "no global path allowlist");
        assert!(GITLEAKS_CONFIG.matches("[[rules]]").count() > 100);
    }

    #[tokio::test]
    async fn decoded_secret_is_reported_as_its_encoded_text() {
        let Some(s) = scanner() else { return };
        let dir = tempfile::tempdir().unwrap();
        let encoded = encoded_aws();
        std::fs::write(
            dir.path().join("enc.txt"),
            format!("first\nblob = \"{encoded}\"\n"),
        )
        .unwrap();
        let found = s.scan_dir(dir.path(), &[]).await.unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].secret, encoded);
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(dir)
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
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[tokio::test]
    async fn history_scan_finds_secrets_removed_before_the_tip() {
        let Some(s) = scanner() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("a.txt"), format!("k = \"{}\"\n", fake_aws())).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "add"]);
        let leaked = git(&work, &["rev-parse", "HEAD"]);
        std::fs::write(work.join("a.txt"), "clean\n").unwrap();
        git(&work, &["commit", "-q", "-am", "clean"]);
        let bare = tmp.path().join("bare.git");
        git(
            tmp.path(),
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        let tip = Oid::parse(&git(&bare, &["rev-parse", "refs/heads/main"])).unwrap();

        let found = s.scan_git(&bare, &tip).await.unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        let f = &found[0];
        assert_eq!(f.path.as_deref(), Some("a.txt"));
        assert_eq!(f.commit.as_deref(), Some(leaked.as_str()));
        assert_eq!(f.fingerprint, format!("{leaked}:a.txt:aws-access-token:1"));
        assert_eq!(f.secret, fake_aws());
        assert!(onboarding_report(&found).contains(&format!("{}:a.txt:1", &leaked[..12])));

        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("b.txt"), format!("again {}\n", fake_aws())).unwrap();
        let msgs = tree.path().join("msgs");
        std::fs::write(&msgs, "nothing\n").unwrap();
        let wt = tree.path().join("wt");
        std::fs::create_dir(&wt).unwrap();
        std::fs::rename(tree.path().join("b.txt"), wt.join("b.txt")).unwrap();
        let merged = scan_snapshot(&s, &wt, &msgs, Some((&bare, &tip)), &[])
            .await
            .unwrap();
        assert_eq!(merged.len(), 1, "same value counted once: {merged:?}");
        assert_eq!(merged[0].path.as_deref(), Some("b.txt"));
        let tree_only = scan_snapshot(&s, &wt, &msgs, None, &[]).await.unwrap();
        assert_eq!(tree_only.len(), 1);
        let allowed = scan_snapshot(
            &s,
            &wt,
            &msgs,
            Some((&bare, &tip)),
            &["b.txt:aws-access-token:1".into()],
        )
        .await
        .unwrap();
        assert!(allowed.is_empty(), "{allowed:?}");
    }
}
