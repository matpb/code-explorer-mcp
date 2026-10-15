//! Configuration: TOML schema, defaults, and startup validation that collects every problem.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::NaiveDate;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de::Error as _};

pub mod duration;
mod recover;
mod validate;

pub use validate::{is_valid_branch, line_of};

#[cfg(test)]
mod tests;

/// Highest schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Env var that allows `remote_url_override` (integration tests with local bare repos).
pub const ALLOW_LOCAL_REMOTES_ENV: &str = "CODE_EXPLORER_ALLOW_LOCAL_REMOTES";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub key: String,
    pub message: String,
    pub fix: String,
    pub fatal: bool,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        write!(f, ": {}: {} ({})", self.key, self.message, self.fix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<Problem>);

impl fmt::Display for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Problems {}

impl Problems {
    pub fn iter(&self) -> std::slice::Iter<'_, Problem> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<Problem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Host {
    Github,
    Bitbucket,
}

impl Host {
    pub fn as_str(self) -> &'static str {
        match self {
            Host::Github => "github",
            Host::Bitbucket => "bitbucket",
        }
    }

    pub fn domain(self) -> &'static str {
        match self {
            Host::Github => "github.com",
            Host::Bitbucket => "bitbucket.org",
        }
    }

    /// Host for Git over SSH. Bitbucket Cloud serves SSH from ssh.bitbucket.org from 2026-11-12.
    pub fn ssh_host(self) -> &'static str {
        match self {
            Host::Github => "github.com",
            Host::Bitbucket => "ssh.bitbucket.org",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanPolicy {
    Redact,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnScanError {
    Hold,
    Serve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogArguments {
    Shape,
    Full,
}

fn de_nets<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
    let raw = Vec::<String>::deserialize(d)?;
    raw.iter()
        .map(|s| {
            s.parse::<IpNet>().map_err(|e| {
                D::Error::custom(format!(
                    "invalid CIDR {s:?}: {e}; use a form like \"172.30.0.0/24\""
                ))
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub public_url: String,
    pub allowed_origins: Vec<String>,
    #[serde(deserialize_with = "de_nets")]
    pub trusted_proxies: Vec<IpNet>,
    /// An empty string disables client IP header handling.
    pub client_ip_header: Option<String>,
    pub data_dir: PathBuf,
    pub git_path: Option<PathBuf>,
    pub rg_path: Option<PathBuf>,
    /// Open connections per listener; extra connections are closed at once.
    pub max_connections: usize,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            listen: SocketAddr::from(([0, 0, 0, 0], 8080)),
            admin_listen: SocketAddr::from(([0, 0, 0, 0], 9090)),
            public_url: "https://explorer.example.com".into(),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            client_ip_header: Some("X-Forwarded-For".into()),
            data_dir: PathBuf::from("/data"),
            git_path: None,
            rg_path: None,
            max_connections: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Auth {
    pub keys_file: PathBuf,
    pub failed_attempts: FailedAttempts,
    /// Argon2 key verifications allowed at once; more wait briefly, then get 503.
    pub max_concurrent_verifications: usize,
}

impl Default for Auth {
    fn default() -> Self {
        Auth {
            keys_file: PathBuf::from("/etc/code-explorer/keys.toml"),
            failed_attempts: FailedAttempts::default(),
            max_concurrent_verifications: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FailedAttempts {
    pub max_failures: u32,
    #[serde(deserialize_with = "duration::deserialize")]
    pub window: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub base_backoff: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub max_backoff: Duration,
    pub ipv6_prefix: u8,
}

impl Default for FailedAttempts {
    fn default() -> Self {
        FailedAttempts {
            max_failures: 5,
            window: Duration::from_secs(600),
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(900),
            ipv6_prefix: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_response_bytes: usize,
    pub max_file_bytes: u64,
    pub max_line_chars: usize,
    pub max_concurrent_workers: usize,
    #[serde(deserialize_with = "duration::deserialize")]
    pub queue_timeout: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub rg_timeout: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub git_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_response_bytes: 262_144,
            max_file_bytes: 4_194_304,
            max_line_chars: 2000,
            max_concurrent_workers: 16,
            queue_timeout: Duration::from_secs(5),
            rg_timeout: Duration::from_secs(10),
            git_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Pull {
    #[serde(deserialize_with = "duration::deserialize")]
    pub interval: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub jitter: Duration,
    pub depth: u32,
    #[serde(deserialize_with = "duration::deserialize")]
    pub fetch_timeout: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub clone_timeout: Duration,
    #[serde(deserialize_with = "duration::deserialize")]
    pub stale_after: Duration,
    pub known_hosts_file: PathBuf,
}

impl Default for Pull {
    fn default() -> Self {
        Pull {
            interval: Duration::from_secs(300),
            jitter: Duration::from_secs(30),
            depth: 200,
            fetch_timeout: Duration::from_secs(120),
            clone_timeout: Duration::from_secs(600),
            stale_after: Duration::from_secs(1800),
            known_hosts_file: PathBuf::from("/etc/code-explorer/known_hosts"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scan {
    pub engine: String,
    pub policy: ScanPolicy,
    pub on_scan_error: OnScanError,
    #[serde(deserialize_with = "duration::deserialize")]
    pub timeout: Duration,
    pub allowlist: Vec<String>,
    pub engine_path: Option<PathBuf>,
}

impl Default for Scan {
    fn default() -> Self {
        Scan {
            engine: "gitleaks".into(),
            policy: ScanPolicy::Redact,
            on_scan_error: OnScanError::Hold,
            timeout: Duration::from_secs(300),
            allowlist: Vec::new(),
            engine_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Deny {
    pub use_defaults: bool,
    pub paths: Vec<String>,
    pub allow: Vec<String>,
}

impl Default for Deny {
    fn default() -> Self {
        Deny {
            use_defaults: true,
            paths: Vec::new(),
            allow: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Features {
    pub file_at_commit: bool,
    pub blame: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Logging {
    pub format: LogFormat,
    pub arguments: LogArguments,
    pub author_emails: bool,
}

impl Default for Logging {
    fn default() -> Self {
        Logging {
            format: LogFormat::Json,
            arguments: LogArguments::Shape,
            author_emails: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    pub enabled: bool,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    HttpsToken {
        username: String,
        #[serde(default)]
        secret_file: Option<PathBuf>,
        #[serde(default)]
        env: Option<String>,
        #[serde(default)]
        expires: Option<NaiveDate>,
    },
    SshKey {
        secret_file: PathBuf,
        #[serde(default)]
        expires: Option<NaiveDate>,
    },
}

impl Credential {
    pub fn expires(&self) -> Option<NaiveDate> {
        match self {
            Credential::HttpsToken { expires, .. } | Credential::SshKey { expires, .. } => *expires,
        }
    }

    pub fn is_ssh(&self) -> bool {
        matches!(self, Credential::SshKey { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub id: String,
    pub host: Host,
    pub path: String,
    pub branch: String,
    #[serde(default)]
    pub description: String,
    /// None means anonymous HTTPS access to a public repo.
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default, deserialize_with = "duration::option::deserialize")]
    pub pull_interval: Option<Duration>,
    #[serde(default)]
    pub scan_policy: Option<ScanPolicy>,
    /// Test hook, rejected unless `CODE_EXPLORER_ALLOW_LOCAL_REMOTES=1`.
    #[serde(default)]
    pub remote_url_override: Option<String>,
}

impl RepoConfig {
    pub fn pull_interval_or(&self, default: Duration) -> Duration {
        self.pull_interval.unwrap_or(default)
    }

    pub fn scan_policy_or(&self, default: ScanPolicy) -> ScanPolicy {
        self.scan_policy.unwrap_or(default)
    }

    /// Remote URL without credentials; SSH credentials get the scp-like form.
    pub fn remote_url(&self, cred: Option<&Credential>) -> String {
        if let Some(url) = &self.remote_url_override {
            return url.clone();
        }
        if cred.is_some_and(Credential::is_ssh) {
            format!("git@{}:{}.git", self.host.ssh_host(), self.path)
        } else {
            format!("https://{}/{}.git", self.host.domain(), self.path)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub server: Server,
    pub auth: Auth,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub pull: Pull,
    #[serde(default)]
    pub scan: Scan,
    #[serde(default)]
    pub deny: Deny,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub logging: Logging,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub credentials: BTreeMap<String, Credential>,
    pub repo: Vec<RepoConfig>,
    /// File the config was read from, used in problem reports.
    #[serde(skip)]
    pub source: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Loaded, Problems> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_str_at(&text, path),
            Err(e) => Err(Problems(vec![Problem {
                file: path.to_path_buf(),
                line: None,
                key: "(file)".into(),
                message: format!("cannot read config file: {e}"),
                fix: "check the path, the permissions and --config / CODE_EXPLORER_CONFIG".into(),
                fatal: true,
            }])),
        }
    }

    /// Parse and validate `text`, reading environment variables from the process.
    pub fn from_str_at(text: &str, file: &Path) -> Result<Loaded, Problems> {
        Self::from_str_with_env(text, file, &|name| std::env::var(name).ok())
    }

    /// Like `from_str_at` with an injectable environment lookup.
    pub fn from_str_with_env(
        text: &str,
        file: &Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Loaded, Problems> {
        let config = Self::parse_unvalidated(text, file)?;
        let problems = validate::validate(&config, text, file, env);
        if problems.iter().any(|p| p.fatal) {
            return Err(Problems(problems));
        }
        Ok(Loaded {
            config,
            warnings: problems,
        })
    }

    /// Deserialize only; no semantic or filesystem checks.
    pub fn parse_unvalidated(text: &str, file: &Path) -> Result<Config, Problems> {
        let mut config: Config = toml::from_str(text).map_err(|e| {
            Problems(recover::collect(
                text,
                file,
                validate::toml_problem(&e, text, file),
            ))
        })?;
        config.source = file.to_path_buf();
        if config.server.client_ip_header.as_deref() == Some("") {
            config.server.client_ip_header = None;
        }
        Ok(config)
    }

    pub fn repo(&self, id: &str) -> Option<&RepoConfig> {
        self.repo.iter().find(|r| r.id == id)
    }

    /// None for an anonymous repo. Panics only if a skipped validation left a dangling reference.
    pub fn credential_for(&self, repo: &RepoConfig) -> Option<&Credential> {
        let name = repo.credential.as_deref()?;
        match self.credentials.get(name) {
            Some(c) => Some(c),
            None => panic!(
                "repo {:?} references unknown credential {name:?}; validation should have rejected it",
                repo.id
            ),
        }
    }

    pub fn git_bin(&self) -> PathBuf {
        self.server.git_path.clone().unwrap_or_else(|| "git".into())
    }

    pub fn rg_bin(&self) -> PathBuf {
        self.server.rg_path.clone().unwrap_or_else(|| "rg".into())
    }

    pub fn scanner_bin(&self) -> PathBuf {
        self.scan
            .engine_path
            .clone()
            .unwrap_or_else(|| self.scan.engine.clone().into())
    }

    /// Checks `git`, `rg` and the scanner run and meet the minimum versions.
    pub fn validate_binaries(&self) -> Vec<Problem> {
        validate::validate_binaries(self)
    }
}
