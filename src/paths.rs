//! Repo-relative path normalization and the path deny-list.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Serialize;
use std::fmt;

const MAX_PATH_BYTES: usize = 1024;

/// Built-in deny globs, matched case-insensitively against the full repo-relative path.
pub const DEFAULT_DENY: &[&str] = &[
    ".git/**",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/credentials*.json",
    "**/secrets.*",
    "**/id_ecdsa*",
    "**/id_dsa*",
    "**/*.p8",
    "**/.htpasswd",
    "**/.git-credentials",
    "**/.docker/config.json",
    "**/kubeconfig*",
    "**/*.kdbx",
    "**/*.gpg",
    "**/service-account*.json",
];

/// Why a client-supplied path was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("path must be relative to the repository root, without a leading '/'")]
    Absolute,
    #[error("path must not contain '..' segments")]
    ParentSegment,
    #[error("path must use '/' as separator, not '\\'")]
    Backslash,
    #[error("path must not contain NUL bytes")]
    Nul,
    #[error("path is longer than {MAX_PATH_BYTES} bytes")]
    TooLong,
    #[error("path must not contain a '.git' segment")]
    GitDir,
}

/// A normalized repo-relative path: no leading or trailing slash, no `.` or empty segments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RepoPath(String);

impl RepoPath {
    /// The repository root (empty path).
    pub fn root() -> Self {
        RepoPath(String::new())
    }

    /// Validates and normalizes a client-supplied path; `""` and `"."` are the root.
    pub fn parse(input: &str) -> Result<RepoPath, PathError> {
        if input.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        if input.contains('\0') {
            return Err(PathError::Nul);
        }
        if input.contains('\\') {
            return Err(PathError::Backslash);
        }
        if input.starts_with('/') {
            return Err(PathError::Absolute);
        }
        let mut kept: Vec<&str> = Vec::new();
        for seg in input.split('/') {
            match seg {
                "" | "." => {}
                ".." => return Err(PathError::ParentSegment),
                s if s.eq_ignore_ascii_case(".git") => return Err(PathError::GitDir),
                s => kept.push(s),
            }
        }
        Ok(RepoPath(kept.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Last segment, or `None` for the root.
    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            Some(self.0.rsplit('/').next().unwrap_or(&self.0))
        }
    }

    /// Parent directory, or `None` for the root.
    pub fn parent(&self) -> Option<RepoPath> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(i) => RepoPath(self.0[..i].to_string()),
            None => RepoPath::root(),
        })
    }

    /// Appends one trusted segment (a name taken from the git index, not from a client).
    pub fn join(&self, name: &str) -> RepoPath {
        if self.is_root() {
            RepoPath(name.to_string())
        } else {
            RepoPath(format!("{}/{}", self.0, name))
        }
    }

    /// True when `prefix` is this path or one of its ancestor directories.
    pub fn starts_with(&self, prefix: &RepoPath) -> bool {
        if prefix.is_root() || self.0 == prefix.0 {
            return true;
        }
        self.0
            .strip_prefix(prefix.0.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RepoPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A deny or allow glob that failed to compile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid glob '{pattern}': {message}")]
pub struct PatternError {
    pub pattern: String,
    pub message: String,
}

/// Case-insensitive deny globs with an allow list that wins over them.
#[derive(Debug, Clone)]
pub struct DenyList {
    deny: GlobSet,
    allow: GlobSet,
    deny_patterns: Vec<String>,
    has_allow: bool,
}

/// Expands `**/x` to also match `x` at the root; a pattern without `/` matches at any depth, like gitignore.
fn with_root_form(pattern: &str) -> Vec<String> {
    if !pattern.contains('/') {
        return vec![format!("**/{pattern}"), pattern.to_string()];
    }
    let mut out = vec![pattern.to_string()];
    if let Some(rest) = pattern.strip_prefix("**/")
        && !rest.is_empty()
    {
        out.push(rest.to_string());
    }
    out
}

/// Compiles each pattern; a failure names the pattern as the operator wrote it.
fn build_set(patterns: &[(String, String)]) -> Result<GlobSet, PatternError> {
    let mut builder = GlobSetBuilder::new();
    for (p, original) in patterns {
        let glob = GlobBuilder::new(p)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .map_err(|e| PatternError {
                pattern: original.clone(),
                message: e.kind().to_string(),
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|e| PatternError {
        pattern: String::new(),
        message: e.kind().to_string(),
    })
}

/// Expanded patterns paired with the pattern they came from, without duplicates.
fn expand(patterns: impl IntoIterator<Item = String>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for p in patterns {
        for form in with_root_form(&p) {
            if !out.iter().any(|(f, _)| *f == form) {
                out.push((form, p.clone()));
            }
        }
    }
    out
}

impl DenyList {
    /// Builds the list from the defaults (when `use_defaults`), `extra` deny globs and `allow` exceptions.
    pub fn new(
        use_defaults: bool,
        extra: &[String],
        allow: &[String],
    ) -> Result<DenyList, PatternError> {
        let mut raw: Vec<String> = Vec::new();
        if use_defaults {
            raw.extend(DEFAULT_DENY.iter().map(|s| s.to_string()));
        }
        raw.extend(extra.iter().cloned());
        let deny_pairs = expand(raw);
        let allow_pairs = expand(allow.iter().cloned());
        Ok(DenyList {
            deny: build_set(&deny_pairs)?,
            allow: build_set(&allow_pairs)?,
            deny_patterns: deny_pairs.into_iter().map(|(f, _)| f).collect(),
            has_allow: !allow_pairs.is_empty(),
        })
    }

    /// True when the path, or any ancestor directory of it, matches a deny glob that no allow glob overrides.
    pub fn is_denied(&self, path: &RepoPath) -> bool {
        if path.is_root() {
            return false;
        }
        let s = path.as_str();
        let mut end = 0;
        loop {
            end = match s[end..].find('/') {
                Some(i) => end + i,
                None => s.len(),
            };
            let prefix = &s[..end];
            if self.deny.is_match(prefix) && !self.allow.is_match(prefix) {
                return true;
            }
            if end >= s.len() {
                return false;
            }
            end += 1;
        }
    }

    /// Deny globs as ripgrep `--glob` arguments (`!pattern`); allow exceptions are not expressible.
    pub fn rg_globs(&self) -> Vec<String> {
        self.deny_patterns.iter().map(|p| format!("!{p}")).collect()
    }

    /// Deny globs that are safe to hand to ripgrep: none when an allow list exists, since rg cannot
    /// express the exceptions and the caller's post-filter applies them.
    pub fn rg_globs_safe(&self) -> Vec<String> {
        if self.has_allow {
            Vec::new()
        } else {
            self.rg_globs()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RepoPath {
        RepoPath::parse(s).expect("valid path")
    }

    fn defaults() -> DenyList {
        DenyList::new(true, &[], &[]).expect("defaults compile")
    }

    #[test]
    fn parse_normalizes() {
        assert_eq!(p("a//b/./c/").as_str(), "a/b/c");
        assert_eq!(p("./a").as_str(), "a");
        assert!(p("").is_root());
        assert!(p(".").is_root());
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(RepoPath::parse("/etc/passwd"), Err(PathError::Absolute));
        assert_eq!(RepoPath::parse("a/../b"), Err(PathError::ParentSegment));
        assert_eq!(RepoPath::parse(".."), Err(PathError::ParentSegment));
        assert_eq!(RepoPath::parse("a\\b"), Err(PathError::Backslash));
        assert_eq!(RepoPath::parse("a\0b"), Err(PathError::Nul));
        assert_eq!(RepoPath::parse(&"a".repeat(1025)), Err(PathError::TooLong));
        assert!(RepoPath::parse(&"a".repeat(1024)).is_ok());
        assert_eq!(RepoPath::parse(".git/config"), Err(PathError::GitDir));
        assert_eq!(RepoPath::parse("x/.GIT/hooks"), Err(PathError::GitDir));
        assert!(RepoPath::parse(".github/workflows/ci.yml").is_ok());
        assert!(RepoPath::parse("a/.gitignore").is_ok());
    }

    #[test]
    fn path_helpers() {
        let x = p("src/lib/mod.rs");
        assert_eq!(x.file_name(), Some("mod.rs"));
        assert_eq!(x.parent(), Some(p("src/lib")));
        assert_eq!(p("top").parent(), Some(RepoPath::root()));
        assert_eq!(RepoPath::root().parent(), None);
        assert_eq!(RepoPath::root().file_name(), None);
        assert_eq!(RepoPath::root().join("a"), p("a"));
        assert_eq!(p("a").join("b"), p("a/b"));
        assert!(x.starts_with(&p("src")));
        assert!(x.starts_with(&x));
        assert!(x.starts_with(&RepoPath::root()));
        assert!(!x.starts_with(&p("sr")));
        assert!(!p("src").starts_with(&x));
        assert_eq!(x.to_string(), "src/lib/mod.rs");
        assert_eq!(x.as_ref(), "src/lib/mod.rs");
    }

    #[test]
    fn default_deny_matches_spec_cases() {
        let d = defaults();
        for denied in [
            ".env",
            ".ENV",
            "a/b/.env",
            "a/B/.Env.local",
            ".env.production",
            "keys/server.PEM",
            "x.key",
            "a/cert.p12",
            "cert.pfx",
            "a.jks",
            "a.keystore",
            "home/id_rsa",
            "home/id_rsa.pub",
            "id_ed25519",
            ".npmrc",
            "web/.pypirc",
            ".netrc",
            "infra/terraform.tfstate",
            "infra/terraform.tfstate.backup",
            "cfg/credentials.json",
            "cfg/credentials-prod.json",
            "cfg/secrets.yaml",
            "secrets.json",
            ".git/config",
            "home/.ssh/id_ecdsa",
            "id_dsa.pub",
            "keys/AuthKey_ABC123.p8",
            "web/.htpasswd",
            "home/.git-credentials",
            "home/.docker/config.json",
            "deploy/kubeconfig",
            "deploy/kubeconfig-prod.yaml",
            "vault/db.kdbx",
            "backup/secrets.GPG",
            "gcp/service-account.json",
            "gcp/service-account-prod.json",
        ] {
            assert!(
                d.is_denied(&p_unchecked(denied)),
                "{denied} should be denied"
            );
        }
        for allowed in [
            "src/main.rs",
            "README.md",
            "environment.rs",
            "a/.envrc",
            "docs/keyboard.md",
            ".github/workflows/ci.yml",
            "secretsanta.txt",
            "docs/.docker/readme.md",
            "gcp/service.json",
            "",
        ] {
            assert!(!d.is_denied(&p_unchecked(allowed)), "{allowed} should pass");
        }
    }

    fn p_unchecked(s: &str) -> RepoPath {
        RepoPath(s.to_string())
    }

    #[test]
    fn ancestor_directory_denial() {
        let d = defaults();
        assert!(d.is_denied(&p("a/secrets.d/file.txt")));
        assert!(d.is_denied(&p("a/.env/inner")));
        assert!(!d.is_denied(&p("a/public/file.txt")));
    }

    #[test]
    fn allow_carves_exception() {
        let d = DenyList::new(true, &[], &["**/.env.example".to_string()]).expect("compiles");
        assert!(!d.is_denied(&p(".env.example")));
        assert!(!d.is_denied(&p("app/.env.example")));
        assert!(!d.is_denied(&p("app/.ENV.EXAMPLE")));
        assert!(d.is_denied(&p(".env")));
        assert!(d.is_denied(&p("app/.env")));
        assert!(d.is_denied(&p(".env.local")));
    }

    #[test]
    fn extra_patterns_and_no_defaults() {
        let d = DenyList::new(false, &["private/**".to_string()], &[]).expect("compiles");
        assert!(d.is_denied(&p("private/x/y")));
        assert!(!d.is_denied(&p(".env")));
        let d = DenyList::new(false, &[], &[]).expect("compiles");
        assert!(!d.is_denied(&p(".env")));
        assert!(d.rg_globs().is_empty());
    }

    #[test]
    fn slashless_user_patterns_match_at_any_depth() {
        let d = DenyList::new(false, &["*.secret".to_string()], &[]).expect("compiles");
        assert!(d.is_denied(&p("x.secret")));
        assert!(d.is_denied(&p("a/b/x.secret")));
        assert!(!d.is_denied(&p("a/b/x.secrets")));
        let d =
            DenyList::new(true, &[], &["credentials-example.json".to_string()]).expect("compiles");
        assert!(!d.is_denied(&p("deep/dir/credentials-example.json")));
        assert!(d.is_denied(&p("deep/dir/credentials-prod.json")));
    }

    #[test]
    fn rg_globs_safe_is_empty_with_an_allow_list() {
        assert!(!defaults().rg_globs_safe().is_empty());
        let d = DenyList::new(true, &[], &["**/.env.example".to_string()]).expect("compiles");
        assert!(d.rg_globs_safe().is_empty());
        assert!(!d.rg_globs().is_empty());
    }

    #[test]
    fn single_star_does_not_cross_directories() {
        let d = DenyList::new(false, &["docs/*.md".to_string()], &[]).expect("compiles");
        assert!(d.is_denied(&p("docs/a.md")));
        assert!(!d.is_denied(&p("docs/sub/a.md")));
    }

    #[test]
    fn invalid_glob_is_reported() {
        let err = DenyList::new(true, &["[".to_string()], &[]).expect_err("must fail");
        assert_eq!(err.pattern, "[");
        assert!(err.to_string().contains("invalid glob"));
        let err = DenyList::new(true, &[], &["a{".to_string()]).expect_err("must fail");
        assert_eq!(err.pattern, "a{");
    }

    #[test]
    fn rg_globs_include_root_forms() {
        let g = defaults().rg_globs();
        assert!(g.contains(&"!**/.env".to_string()));
        assert!(g.contains(&"!.env".to_string()));
        assert!(g.contains(&"!.git/**".to_string()));
        assert!(g.contains(&"!*.pem".to_string()));
        assert!(g.iter().all(|s| s.starts_with('!')));
    }
}
