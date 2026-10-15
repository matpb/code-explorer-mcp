//! Semantic validation: collects every problem, with line numbers from a spanned TOML document.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use toml_edit::{Document, Item, Table};

use super::*;

type BinaryCheck = (
    &'static str,
    std::path::PathBuf,
    Option<(u32, u32)>,
    &'static str,
);
type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

const MIN_PULL_INTERVAL: Duration = Duration::from_secs(30);
const MIN_GIT: (u32, u32) = (2, 40);
const MIN_RG: (u32, u32) = (13, 0);

fn line_at(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

/// 1-based line of `key_path` (for example `repo[1].branch`); falls back to the deepest key that exists.
pub fn line_of(doc: &Document<&str>, text: &str, key_path: &str) -> Option<usize> {
    let mut start: Option<usize> = None;
    let mut table: &Table = doc.as_table();
    for seg in key_path.split('.') {
        let (name, index) = match seg.split_once('[') {
            Some((n, rest)) => (
                n,
                rest.strip_suffix(']').and_then(|i| i.parse::<usize>().ok()),
            ),
            None => (seg, None),
        };
        let Some((key, item)) = table.get_key_value(name) else {
            break;
        };
        if let Some(s) = key.span() {
            start = Some(s.start);
        }
        table = match (item, index) {
            (Item::Table(t), None) => t,
            (Item::ArrayOfTables(a), Some(i)) => {
                let Some(t) = a.get(i) else { break };
                if let Some(s) = t.span() {
                    start = Some(s.start);
                }
                t
            }
            _ => break,
        };
    }
    start.map(|s| line_at(text, s))
}

pub(super) fn toml_problem(e: &toml::de::Error, text: &str, file: &Path) -> Problem {
    let message = e.message().to_string();
    let line = e.span().map(|s| line_at(text, s.start));
    let unknown = message.starts_with("unknown field");
    let key = if unknown {
        message
            .split('`')
            .nth(1)
            .map(str::to_string)
            .unwrap_or_else(|| "(toml)".into())
    } else {
        "(toml)".into()
    };
    let fix = if unknown {
        "remove the field or correct its spelling".to_string()
    } else {
        "correct the TOML syntax or the value type at this line".to_string()
    };
    Problem {
        file: file.to_path_buf(),
        line,
        key,
        message,
        fix,
        fatal: true,
    }
}

struct Ctx<'a> {
    file: &'a Path,
    text: &'a str,
    doc: Option<Document<&'a str>>,
    env: EnvFn<'a>,
    out: Vec<Problem>,
}

impl Ctx<'_> {
    fn add(&mut self, fatal: bool, key: &str, message: impl Into<String>, fix: impl Into<String>) {
        let line = self.doc.as_ref().and_then(|d| line_of(d, self.text, key));
        self.out.push(Problem {
            file: self.file.to_path_buf(),
            line,
            key: key.to_string(),
            message: message.into(),
            fix: fix.into(),
            fatal,
        });
    }

    fn err(&mut self, key: &str, message: impl Into<String>, fix: impl Into<String>) {
        self.add(true, key, message, fix);
    }

    fn warn(&mut self, key: &str, message: impl Into<String>, fix: impl Into<String>) {
        self.add(false, key, message, fix);
    }

    fn min_duration(&mut self, key: &str, value: Duration, min: Duration) {
        if value < min {
            let (v, m) = (
                humantime::format_duration(value),
                humantime::format_duration(min),
            );
            self.err(
                key,
                format!("{v} is below the minimum of {m}"),
                format!("set it to at least \"{m}\""),
            );
        }
    }

    fn nonzero_duration(&mut self, key: &str, value: Duration) {
        if value.is_zero() {
            self.err(
                key,
                "duration must be greater than zero",
                "set a positive duration such as \"10s\"",
            );
        }
    }

    fn positive(&mut self, key: &str, value: u64) {
        if value == 0 {
            self.err(key, "must be greater than zero", "set a positive number");
        }
    }
}

pub(super) fn validate(config: &Config, text: &str, file: &Path, env: EnvFn<'_>) -> Vec<Problem> {
    let mut c = Ctx {
        file,
        text,
        doc: Document::parse(text).ok(),
        env,
        out: Vec::new(),
    };
    version(&mut c, config);
    server(&mut c, config);
    auth(&mut c, config);
    limits(&mut c, config);
    pull(&mut c, config);
    scan(&mut c, config);
    deny(&mut c, config);
    credentials(&mut c, config);
    repos(&mut c, config);
    c.out
}

fn version(c: &mut Ctx, cfg: &Config) {
    if cfg.version != SCHEMA_VERSION {
        c.err(
            "version",
            format!("unsupported schema version {}", cfg.version),
            format!("set version = {SCHEMA_VERSION}"),
        );
    }
}

fn is_http_url(s: &str) -> bool {
    s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .is_some_and(|rest| {
            !rest.is_empty() && !rest.starts_with('/') && !rest.contains(char::is_whitespace)
        })
}

fn server(c: &mut Ctx, cfg: &Config) {
    let s = &cfg.server;
    if s.listen == s.admin_listen {
        c.err(
            "server.admin_listen",
            format!("admin_listen {} is the same as listen", s.admin_listen),
            "use a different port; the admin listener must not be the public one",
        );
    }
    if !is_http_url(&s.public_url) {
        c.err(
            "server.public_url",
            format!("{:?} is not an http(s) URL", s.public_url),
            "use a form like \"https://explorer.example.com\"",
        );
    }
    for (i, o) in s.allowed_origins.iter().enumerate() {
        let key = "server.allowed_origins";
        if !is_http_url(o) {
            c.err(
                key,
                format!("entry {i} ({o:?}) must start with http:// or https://"),
                "use a full origin such as \"https://app.example.com\"",
            );
        } else if o
            .split_once("://")
            .is_some_and(|(_, rest)| rest.contains('/'))
        {
            c.err(key, format!("entry {i} ({o:?}) has a path or trailing slash, so it can never match an Origin header"), "write the origin only: scheme, host and optional port");
        }
    }
    if let Some(h) = &s.client_ip_header
        && http::header::HeaderName::from_bytes(h.as_bytes()).is_err()
    {
        c.err(
            "server.client_ip_header",
            format!("{h:?} is not a valid HTTP header name"),
            "use a name such as \"X-Forwarded-For\", or \"\" to ignore client IP headers",
        );
    }
    if s.client_ip_header.is_some() && s.trusted_proxies.is_empty() {
        c.warn(
            "server.trusted_proxies",
            "client_ip_header is set but trusted_proxies is empty, so the header is never honored",
            "list your proxy CIDRs, or set client_ip_header = \"\"",
        );
    }
    data_dir(c, &s.data_dir);
}

fn data_dir(c: &mut Ctx, dir: &Path) {
    let key = "server.data_dir";
    if let Err(e) = std::fs::create_dir_all(dir) {
        c.err(
            key,
            format!("cannot create {}: {e}", dir.display()),
            "create the directory and make it writable by the server user",
        );
        return;
    }
    if let Err(e) = tempfile::Builder::new()
        .prefix(".ce-write-check")
        .tempfile_in(dir)
    {
        c.err(
            key,
            format!("{} is not writable: {e}", dir.display()),
            "fix the directory permissions or mount a writable volume",
        );
    }
}

fn auth(c: &mut Ctx, cfg: &Config) {
    let f = &cfg.auth.failed_attempts;
    let k = "auth.failed_attempts";
    c.positive(&format!("{k}.max_failures"), f.max_failures.into());
    c.nonzero_duration(&format!("{k}.window"), f.window);
    c.nonzero_duration(&format!("{k}.base_backoff"), f.base_backoff);
    c.nonzero_duration(&format!("{k}.max_backoff"), f.max_backoff);
    if f.max_backoff < f.base_backoff {
        c.err(
            &format!("{k}.max_backoff"),
            "max_backoff is smaller than base_backoff",
            "make max_backoff at least base_backoff",
        );
    }
    if f.ipv6_prefix == 0 || f.ipv6_prefix > 128 {
        c.err(
            &format!("{k}.ipv6_prefix"),
            format!("{} is outside 1..=128", f.ipv6_prefix),
            "use a prefix length such as 64",
        );
    }
}

fn limits(c: &mut Ctx, cfg: &Config) {
    let l = &cfg.limits;
    c.positive("limits.max_response_bytes", l.max_response_bytes as u64);
    if l.max_response_bytes > 0 && l.max_response_bytes < 4096 {
        c.err(
            "limits.max_response_bytes",
            format!("{} is below the minimum of 4096", l.max_response_bytes),
            "set at least 4096",
        );
    }
    c.positive("limits.max_file_bytes", l.max_file_bytes);
    c.positive("limits.max_line_chars", l.max_line_chars as u64);
    if l.max_line_chars > 0 && l.max_line_chars < 80 {
        c.err(
            "limits.max_line_chars",
            format!("{} is below the minimum of 80", l.max_line_chars),
            "set at least 80",
        );
    }
    c.positive(
        "limits.max_concurrent_workers",
        l.max_concurrent_workers as u64,
    );
    c.nonzero_duration("limits.queue_timeout", l.queue_timeout);
    c.nonzero_duration("limits.rg_timeout", l.rg_timeout);
    c.nonzero_duration("limits.git_timeout", l.git_timeout);
}

fn pull(c: &mut Ctx, cfg: &Config) {
    let p = &cfg.pull;
    c.min_duration("pull.interval", p.interval, MIN_PULL_INTERVAL);
    c.positive("pull.depth", p.depth.into());
    c.nonzero_duration("pull.fetch_timeout", p.fetch_timeout);
    c.nonzero_duration("pull.clone_timeout", p.clone_timeout);
    c.nonzero_duration("pull.stale_after", p.stale_after);
    if cfg.credentials.values().any(Credential::is_ssh) {
        match std::fs::read(&p.known_hosts_file) {
            Ok(b) if b.iter().any(|x| !x.is_ascii_whitespace()) => {}
            Ok(_) => c.err("pull.known_hosts_file", format!("{} is empty", p.known_hosts_file.display()), "add the host keys of github.com and bitbucket.org (ssh-keyscan on a trusted machine)"),
            Err(e) => c.err("pull.known_hosts_file", format!("cannot read {}: {e}", p.known_hosts_file.display()), "ssh_key credentials need a pinned known_hosts file; create it and set pull.known_hosts_file"),
        }
    }
}

fn scan(c: &mut Ctx, cfg: &Config) {
    if cfg.scan.engine != "gitleaks" {
        c.err(
            "scan.engine",
            format!("unsupported engine {:?}", cfg.scan.engine),
            "only \"gitleaks\" is supported",
        );
    }
    c.nonzero_duration("scan.timeout", cfg.scan.timeout);
}

fn deny(c: &mut Ctx, cfg: &Config) {
    for (field, list) in [("paths", &cfg.deny.paths), ("allow", &cfg.deny.allow)] {
        for (i, g) in list.iter().enumerate() {
            let built = globset::GlobBuilder::new(g)
                .case_insensitive(true)
                .literal_separator(false)
                .build();
            if let Err(e) = built {
                c.err(
                    &format!("deny.{field}"),
                    format!("entry {i} ({g:?}) is not a valid glob: {e}"),
                    "fix the pattern; see gitignore-style globs with ** and *",
                );
            }
        }
    }
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn credentials(c: &mut Ctx, cfg: &Config) {
    let referenced: BTreeSet<&str> = cfg.repo.iter().map(|r| r.credential.as_str()).collect();
    let today = chrono::Utc::now().date_naive();
    for (name, cred) in &cfg.credentials {
        let base = format!("credentials.{name}");
        if !name_ok(name) {
            c.err(
                &base,
                format!("credential name {name:?} must be 1 to 64 characters of [A-Za-z0-9_-]"),
                "rename the credential and update the repos that use it",
            );
            continue;
        }
        if !referenced.contains(name.as_str()) {
            c.warn(
                &base,
                "credential is not used by any repo",
                "remove it or reference it from a [[repo]]",
            );
        }
        if let Some(exp) = cred.expires()
            && exp < today
        {
            c.err(
                &format!("{base}.expires"),
                format!("credential expired on {exp}"),
                "rotate the secret and move or remove the expires date",
            );
        }
        match cred {
            Credential::HttpsToken {
                username,
                secret_file,
                env,
                ..
            } => {
                if username.trim().is_empty() {
                    c.err(&format!("{base}.username"), "username is empty", "set the token owner's username (Bitbucket repository tokens use \"x-token-auth\")");
                }
                match (secret_file, env) {
                    (Some(_), Some(_)) => c.err(
                        &base,
                        "set exactly one of secret_file and env, not both",
                        "remove one of them",
                    ),
                    (None, None) => c.err(
                        &base,
                        "https_token needs either secret_file or env",
                        "add secret_file = \"/run/secrets/<name>\" or env = \"<VAR>\"",
                    ),
                    (Some(p), None) => check_secret_file(c, &format!("{base}.secret_file"), p),
                    (None, Some(var)) => check_env(c, &format!("{base}.env"), var),
                }
            }
            Credential::SshKey { secret_file, .. } => {
                check_secret_file(c, &format!("{base}.secret_file"), secret_file);
            }
        }
    }
}

fn check_secret_file(c: &mut Ctx, key: &str, path: &Path) {
    match std::fs::read(path) {
        Ok(b) if b.iter().any(|x| !x.is_ascii_whitespace()) => {}
        Ok(_) => c.err(
            key,
            format!("{} is empty", path.display()),
            "write the secret into the file",
        ),
        Err(e) => c.err(
            key,
            format!("cannot read {}: {e}", path.display()),
            "create the file or mount the secret, and make it readable by the server user",
        ),
    }
}

fn check_env(c: &mut Ctx, key: &str, var: &str) {
    if var.is_empty() || var.contains('=') || var.contains('\0') {
        c.err(
            key,
            format!("{var:?} is not a valid environment variable name"),
            "use a name such as API_REPO_TOKEN",
        );
        return;
    }
    if (c.env)(var).is_none_or(|v| v.trim().is_empty()) {
        c.err(
            key,
            format!("environment variable {var} is not set or is empty"),
            format!("export {var} before starting the server, or use secret_file instead"),
        );
    }
}

fn id_ok(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn check_repo_path(p: &str) -> Result<(), String> {
    if p.chars().any(char::is_whitespace) {
        return Err("contains whitespace".into());
    }
    let segs: Vec<&str> = p.split('/').collect();
    if segs.len() != 2 || segs.iter().any(|s| s.is_empty()) {
        return Err("must be exactly two non-empty segments, owner/name".into());
    }
    for s in segs {
        if s.contains("..") || s == "." {
            return Err("contains a . or .. segment".into());
        }
        if s.starts_with('-') {
            return Err("a segment starts with '-'".into());
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("only letters, digits, '.', '_' and '-' are allowed in a segment".into());
        }
    }
    Ok(())
}

/// Local implementation of `git check-ref-format --branch` rules.
pub fn is_valid_branch(b: &str) -> Result<(), String> {
    if b.is_empty() {
        return Err("is empty".into());
    }
    if b == "@" {
        return Err("cannot be '@'".into());
    }
    if b.starts_with('-') {
        return Err("starts with '-'".into());
    }
    if b.starts_with('/') || b.ends_with('/') || b.contains("//") {
        return Err("has a leading, trailing or doubled '/'".into());
    }
    if b.ends_with('.') {
        return Err("ends with '.'".into());
    }
    if b.contains("..") {
        return Err("contains '..'".into());
    }
    if b.contains("@{") {
        return Err("contains '@{'".into());
    }
    if let Some(ch) = b
        .chars()
        .find(|c| c.is_ascii_control() || c.is_whitespace() || "~^:?*[\\".contains(*c))
    {
        return Err(format!("contains the forbidden character {ch:?}"));
    }
    for comp in b.split('/') {
        if comp.starts_with('.') {
            return Err("has a path component starting with '.'".into());
        }
        if comp.ends_with(".lock") {
            return Err("has a path component ending with '.lock'".into());
        }
    }
    Ok(())
}

fn repos(c: &mut Ctx, cfg: &Config) {
    if cfg.repo.is_empty() {
        c.err(
            "repo",
            "no [[repo]] entries",
            "add at least one [[repo]] table",
        );
    }
    let allow_local = (c.env)(ALLOW_LOCAL_REMOTES_ENV).as_deref() == Some("1");
    let mut ids: HashMap<&str, usize> = HashMap::new();
    let mut targets: HashMap<(Host, &str, &str), usize> = HashMap::new();
    for (i, r) in cfg.repo.iter().enumerate() {
        let k = |f: &str| format!("repo[{i}].{f}");
        if !id_ok(&r.id) {
            c.err(
                &k("id"),
                format!("{:?} does not match [a-z0-9][a-z0-9._-]{{0,62}}", r.id),
                "use lowercase letters, digits, '.', '_' and '-', at most 63 characters",
            );
        }
        if let Some(first) = ids.insert(&r.id, i) {
            c.err(
                &k("id"),
                format!("duplicate repo id {:?} (first used by repo[{first}])", r.id),
                "give every [[repo]] a unique id",
            );
        }
        if let Err(why) = check_repo_path(&r.path) {
            c.err(
                &k("path"),
                format!("{:?} is invalid: {why}", r.path),
                "use owner/name for GitHub or workspace/name for Bitbucket",
            );
        }
        if let Err(why) = is_valid_branch(&r.branch) {
            c.err(
                &k("branch"),
                format!("branch {:?} is invalid: {why}", r.branch),
                "use a valid git branch name such as \"main\"",
            );
        }
        if !cfg.credentials.contains_key(&r.credential) {
            c.err(
                &k("credential"),
                format!("credential {:?} is not defined", r.credential),
                "add a [credentials.<name>] table with that name, or fix the reference",
            );
        }
        if let Some(iv) = r.pull_interval {
            c.min_duration(&k("pull_interval"), iv, MIN_PULL_INTERVAL);
        }
        if r.description.trim().is_empty() {
            c.warn(
                &k("description"),
                "repo has no description, so agents get no hint about what it holds",
                "add a one-line description",
            );
        }
        if let Some(url) = &r.remote_url_override {
            if !allow_local {
                c.err(
                    &k("remote_url_override"),
                    "remote_url_override is a test hook and is not allowed here",
                    format!("remove it; tests set {ALLOW_LOCAL_REMOTES_ENV}=1"),
                );
            } else if url.trim().is_empty() {
                c.err(
                    &k("remote_url_override"),
                    "remote_url_override is empty",
                    "give a local path or file:// URL, or remove it",
                );
            }
        }
        if let Some(first) = targets.insert((r.host, &r.path, &r.branch), i) {
            c.warn(
                &k("branch"),
                format!(
                    "same host, path and branch as repo[{first}] ({:?})",
                    cfg.repo[first].id
                ),
                "drop the duplicate or point it at a different branch",
            );
        }
    }
}

fn parse_version(out: &str) -> Option<(u32, u32)> {
    let tok = out
        .split_whitespace()
        .find(|t| t.starts_with(|c: char| c.is_ascii_digit()) && t.contains('.'))?;
    let mut parts = tok.split('.').map(|p| {
        p.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    Some((parts.next()??, parts.next()??))
}

fn probe(bin: &Path) -> Result<String, String> {
    let mut child = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err(format!("{} --version exited with {status}", bin.display()));
                }
                let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
                s.push_str(&String::from_utf8_lossy(&out.stderr));
                return Ok(s);
            }
            Ok(None) if start.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} --version did not finish in 5s", bin.display()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(super) fn validate_binaries(cfg: &Config) -> Vec<Problem> {
    let mut out = Vec::new();
    let checks: [BinaryCheck; 3] = [
        (
            "server.git_path",
            cfg.git_bin(),
            Some(MIN_GIT),
            "install git 2.40 or newer, or set [server] git_path",
        ),
        (
            "server.rg_path",
            cfg.rg_bin(),
            Some(MIN_RG),
            "install ripgrep 13 or newer, or set [server] rg_path",
        ),
        (
            "scan.engine_path",
            cfg.scanner_bin(),
            None,
            "install gitleaks, or set [scan] engine_path",
        ),
    ];
    for (key, bin, min, fix) in checks {
        let problem = |message: String| Problem {
            file: cfg.source.clone(),
            line: None,
            key: key.into(),
            message,
            fix: fix.into(),
            fatal: true,
        };
        match probe(&bin) {
            Err(e) => out.push(problem(e)),
            Ok(text) => {
                if let Some(min) = min {
                    match parse_version(&text) {
                        None => out.push(problem(format!(
                            "cannot parse the version of {} from {:?}",
                            bin.display(),
                            text.lines().next().unwrap_or("")
                        ))),
                        Some(v) if v < min => out.push(problem(format!(
                            "{} is version {}.{}, need at least {}.{}",
                            bin.display(),
                            v.0,
                            v.1,
                            min.0,
                            min.1
                        ))),
                        Some(_) => {}
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("git version 2.56.0\n"), Some((2, 56)));
        assert_eq!(
            parse_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(
            parse_version("ripgrep 15.1.0\nfeatures:+pcre2"),
            Some((15, 1))
        );
        assert_eq!(parse_version("gitleaks version 8.30.1"), Some((8, 30)));
        assert_eq!(parse_version("nothing"), None);
    }
}
