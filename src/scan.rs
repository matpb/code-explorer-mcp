//! Secret scanning: the `Scanner` trait, the gitleaks adapter, allowlist, onboarding report and redactor glue.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::Deserialize;

use crate::proc::{self, ProcError};
use crate::redact::Redactor;

/// gitleaks reads this instead of any config shipped inside the scanned repo.
const GITLEAKS_CONFIG: &str = "[extend]\nuseDefault = true\n";
const MAX_TARGET_MEGABYTES: &str = "50";
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// One detected secret. `path` is relative to the worktree, `None` for extra files such as commit messages.
#[derive(Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub path: Option<String>,
    pub line: Option<u64>,
    pub secret: String,
    pub fingerprint: String,
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("rule_id", &self.rule_id)
            .field("path", &self.path)
            .field("line", &self.line)
            .field("fingerprint", &self.fingerprint)
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
    #[serde(rename = "Secret", default)]
    secret: String,
    #[serde(rename = "Fingerprint", default)]
    fingerprint: String,
}

impl GitleaksScanner {
    pub fn new(bin: PathBuf, timeout: Duration) -> Self {
        Self { bin, timeout }
    }

    /// One gitleaks run over `target`; paths and fingerprints come back relative to it.
    async fn run_one(
        &self,
        target: &Path,
        work: &Path,
        tag: &str,
        relative: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        let report = work.join(format!("{tag}.json"));
        let mut cmd = proc::scrubbed_command(&self.bin);
        cmd.arg("dir")
            .arg(target)
            .args(["--no-banner", "--exit-code", "0", "--report-format", "json"])
            .arg("--report-path")
            .arg(&report)
            .args(["--max-target-megabytes", MAX_TARGET_MEGABYTES])
            .args(["--log-level", "error", "--ignore-gitleaks-allow"])
            .arg("--config")
            .arg(work.join("gitleaks.toml"))
            .arg("--gitleaks-ignore-path")
            .arg(work.join("ignore"));
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
        let bytes = match tokio::fs::read(&report).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(ScanError::Io(e)),
        };
        parse_report(&bytes, target, relative)
    }

    async fn scan(&self, dir: &Path, extra_files: &[PathBuf]) -> Result<Vec<Finding>, ScanError> {
        let work = tempfile::Builder::new().prefix("cex-scan-").tempdir()?;
        std::fs::write(work.path().join("gitleaks.toml"), GITLEAKS_CONFIG)?;
        std::fs::create_dir(work.path().join("ignore"))?;
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
        let main = self.run_one(dir, work.path(), "tree", true);
        let extra = async {
            if extra_files.is_empty() {
                Ok(Vec::new())
            } else {
                self.run_one(&extra_dir, work.path(), "extra", false).await
            }
        };
        let (main, extra) = tokio::join!(main, extra);
        let mut findings = main?;
        findings.extend(extra?);
        Ok(findings)
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

fn parse_report(bytes: &[u8], target: &Path, relative: bool) -> Result<Vec<Finding>, ScanError> {
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
            let rel = r.file.strip_prefix(&prefix).unwrap_or(&r.file).to_owned();
            Finding {
                rule_id: r.rule_id,
                path: relative.then_some(rel),
                line: r.start_line,
                secret: r.secret,
                fingerprint: r.fingerprint.replace(&prefix, ""),
            }
        })
        .collect())
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
            let place = f.path.as_deref().unwrap_or("<commit messages>");
            let loc = match f.line {
                Some(line) => format!("{place}:{line}"),
                None => place.to_owned(),
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
        assert!(parse_report(b"", t, true).unwrap().is_empty());
        assert!(parse_report(b"  \n", t, true).unwrap().is_empty());
        assert!(parse_report(b"[]", t, true).unwrap().is_empty());
        assert!(parse_report(b"null", t, true).unwrap().is_empty());
        assert!(matches!(
            parse_report(b"{oops", t, true),
            Err(ScanError::Parse(_))
        ));
        let json = br#"[{"RuleID":"r","File":"/w/tree/x/y.txt","StartLine":4,"Secret":"s3cr3t-val","Fingerprint":"/w/tree/x/y.txt:r:4","Match":"m"}]"#;
        let f = &parse_report(json, t, true).unwrap()[0];
        assert_eq!(f.path.as_deref(), Some("x/y.txt"));
        assert_eq!(f.fingerprint, "x/y.txt:r:4");
        let f = &parse_report(json, t, false).unwrap()[0];
        assert_eq!(f.path, None);
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
}
