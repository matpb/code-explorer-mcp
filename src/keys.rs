//! Per-user API keys: format, hashed storage in keys.toml, verification cache and hot reload.

use arc_swap::ArcSwap;
use argon2::password_hash::PasswordHasher;
use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, PasswordVerifier, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KEY_PREFIX: &str = "cex_";
const ID_LEN: usize = 8;
const SECRET_LEN: usize = 43;
const CACHE_TTL: Duration = Duration::from_secs(600);
const DEBOUNCE: Duration = Duration::from_millis(300);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Modification time and length of the keys file, or None when unreadable.
fn file_stamp(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}
const ARGON_M_KIB: u32 = 19456;
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

/// One problem found while loading keys.toml.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProblem {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub key: String,
    pub message: String,
    pub fix: String,
}

impl fmt::Display for KeyProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        write!(f, ": {}: {}", self.key, self.message)?;
        if !self.fix.is_empty() {
            write!(f, " ({})", self.fix)?;
        }
        Ok(())
    }
}

/// Every problem found in one load attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<KeyProblem>);

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

/// One `[[key]]` entry of keys.toml.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub id: String,
    pub name: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repos: Option<Vec<String>>,
    #[serde(deserialize_with = "de_date")]
    pub created: NaiveDate,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_opt_date"
    )]
    pub expires: Option<NaiveDate>,
    #[serde(default)]
    pub disabled: bool,
}

struct TomlDate(NaiveDate);

impl<'de> Deserialize<'de> for TomlDate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, Visitor};

        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TomlDate;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a date such as 2026-12-31")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<TomlDate, E> {
                s.parse::<NaiveDate>().map(TomlDate).map_err(E::custom)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<TomlDate, A::Error> {
                let dt = toml::value::Datetime::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                if dt.time.is_some() || dt.offset.is_some() {
                    return Err(A::Error::custom("expected a date without a time"));
                }
                dt.to_string()
                    .parse::<NaiveDate>()
                    .map(TomlDate)
                    .map_err(A::Error::custom)
            }
        }
        d.deserialize_any(V)
    }
}

fn de_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<NaiveDate, D::Error> {
    TomlDate::deserialize(d).map(|d| d.0)
}

fn de_opt_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<NaiveDate>, D::Error> {
    Option::<TomlDate>::deserialize(d).map(|d| d.map(|d| d.0))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    #[serde(default)]
    key: Vec<KeyEntry>,
}

impl KeyEntry {
    /// Renders this entry as one `[[key]]` block; unset optional fields are omitted.
    pub fn to_toml_table(&self) -> String {
        let s = |v: &str| toml::Value::String(v.to_string()).to_string();
        let mut out = String::from("[[key]]\n");
        out.push_str(&format!("id = {}\n", s(&self.id)));
        out.push_str(&format!("name = {}\n", s(&self.name)));
        out.push_str(&format!("hash = {}\n", s(&self.hash)));
        if let Some(repos) = &self.repos {
            let items: Vec<String> = repos.iter().map(|r| s(r)).collect();
            out.push_str(&format!("repos = [{}]\n", items.join(", ")));
        }
        out.push_str(&format!("created = {}\n", self.created));
        if let Some(e) = self.expires {
            out.push_str(&format!("expires = {e}\n"));
        }
        if self.disabled {
            out.push_str("disabled = true\n");
        }
        out
    }

    fn expired_on(&self, today: NaiveDate) -> bool {
        self.expires.is_some_and(|e| today >= e)
    }
}

/// The parsed and validated contents of keys.toml.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    pub keys: Vec<Arc<KeyEntry>>,
}

fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn check_hash(hash: &str) -> Result<(), String> {
    let parsed = PasswordHash::new(hash).map_err(|e| format!("not a valid PHC string: {e}"))?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err(format!(
            "algorithm '{}' is not supported, expected argon2id",
            parsed.algorithm.as_str()
        ));
    }
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err("PHC string lacks a salt or hash output".to_string());
    }
    Ok(())
}

impl KeySet {
    /// Reads and validates keys.toml; an empty file or a file with no keys is valid.
    pub fn load(path: &Path, known_repo_ids: &[String]) -> Result<KeySet, Problems> {
        let problem = |line: Option<usize>, key: &str, message: String, fix: &str| {
            Problems(vec![KeyProblem {
                file: path.to_path_buf(),
                line,
                key: key.to_string(),
                message,
                fix: fix.to_string(),
            }])
        };
        let text = std::fs::read_to_string(path).map_err(|e| {
            problem(
                None,
                "file",
                format!("cannot read keys file: {e}"),
                "create it with `code-explorer keygen` or fix its permissions",
            )
        })?;
        let file: KeyFile = toml::from_str(&text).map_err(|e| {
            let line = e.span().map(|s| line_of(&text, s.start));
            problem(
                line,
                "syntax",
                e.message().to_string(),
                "fix the TOML syntax or remove unknown fields",
            )
        })?;
        let lines = entry_lines(&text);
        let mut problems = Vec::new();
        let mut add = |idx: usize, key: &str, message: String, fix: &str| {
            problems.push(KeyProblem {
                file: path.to_path_buf(),
                line: lines.get(idx).copied(),
                key: key.to_string(),
                message,
                fix: fix.to_string(),
            });
        };
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for (i, k) in file.key.iter().enumerate() {
            if !valid_id(&k.id) {
                add(
                    i,
                    "key.id",
                    format!("id '{}' must be 8 characters of [a-z2-7]", k.id),
                    "use the id printed by `code-explorer keygen`",
                );
            } else if !ids.insert(k.id.as_str()) {
                add(
                    i,
                    "key.id",
                    format!("duplicate id '{}'", k.id),
                    "remove one of the entries",
                );
            }
            if k.name.trim().is_empty() {
                add(
                    i,
                    "key.name",
                    "name is empty".to_string(),
                    "give the key a name",
                );
            } else if !names.insert(k.name.as_str()) {
                add(
                    i,
                    "key.name",
                    format!("duplicate name '{}'", k.name),
                    "names must be unique",
                );
            }
            if let Err(msg) = check_hash(&k.hash) {
                add(
                    i,
                    "key.hash",
                    msg,
                    "paste the hash printed by `code-explorer keygen`",
                );
            }
            if let Some(repos) = &k.repos
                && !known_repo_ids.is_empty()
            {
                for r in repos {
                    if !known_repo_ids.contains(r) {
                        add(
                            i,
                            "key.repos",
                            format!("unknown repo id '{r}'"),
                            "use an id defined in [[repo]] of config.toml",
                        );
                    }
                }
            }
            if let Some(e) = k.expires
                && e <= k.created
            {
                add(
                    i,
                    "key.expires",
                    format!("expires {e} is not after created {}", k.created),
                    "set a later expiry date",
                );
            }
        }
        if problems.is_empty() {
            Ok(KeySet {
                keys: file.key.into_iter().map(Arc::new).collect(),
            })
        } else {
            Err(Problems(problems))
        }
    }

    /// Finds an entry by its 8 character id.
    pub fn get(&self, id: &str) -> Option<&Arc<KeyEntry>> {
        self.keys.iter().find(|k| k.id == id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Line numbers of each `[[key]]` header, in file order (best effort).
fn entry_lines(text: &str) -> Vec<usize> {
    let Ok(doc) = toml_edit::Document::parse(text) else {
        return Vec::new();
    };
    let Some(tables) = doc.get("key").and_then(|i| i.as_array_of_tables()) else {
        return Vec::new();
    };
    tables
        .iter()
        .map(|t| t.span().map_or(1, |s| line_of(text, s.start)))
        .collect()
}

/// The routing part of a presented key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKey {
    pub id: String,
}

/// Strictly parses `cex_<id>_<secret>` (the secret may itself contain `_`); `None` for anything else.
pub fn parse_key(s: &str) -> Option<ParsedKey> {
    let rest = s.strip_prefix(KEY_PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    let secret_ok = secret.len() == SECRET_LEN
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (valid_id(id) && secret_ok).then(|| ParsedKey { id: id.to_string() })
}

/// Why a presented key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Malformed,
    UnknownId,
    WrongSecret,
    Expired,
    Disabled,
}

impl fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthFailure::Malformed => "malformed",
            AuthFailure::UnknownId => "unknown_id",
            AuthFailure::WrongSecret => "wrong_secret",
            AuthFailure::Expired => "expired",
            AuthFailure::Disabled => "disabled",
        })
    }
}

impl std::error::Error for AuthFailure {}

#[derive(Debug)]
struct CacheEntry {
    key_id: String,
    verified_at: Instant,
}

/// Live key set with a verification cache and hot reload.
#[derive(Debug)]
pub struct KeyStore {
    path: PathBuf,
    known_repo_ids: Vec<String>,
    set: ArcSwap<KeySet>,
    cache: Mutex<HashMap<[u8; 32], CacheEntry>>,
    reload_error: Mutex<Option<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl KeyStore {
    /// Loads keys.toml once; failure means the server must not start.
    pub fn new(path: PathBuf, known_repo_ids: Vec<String>) -> Result<Arc<KeyStore>, Problems> {
        let set = KeySet::load(&path, &known_repo_ids)?;
        Ok(Arc::new(KeyStore {
            path,
            known_repo_ids,
            set: ArcSwap::from_pointee(set),
            cache: Mutex::new(HashMap::new()),
            reload_error: Mutex::new(None),
        }))
    }

    /// Checks a presented key. Argon2 runs on a cache miss (tens of milliseconds), so call from a blocking context.
    pub fn verify(&self, presented: &str) -> Result<Arc<KeyEntry>, AuthFailure> {
        let parsed = parse_key(presented).ok_or(AuthFailure::Malformed)?;
        let set = self.set.load_full();
        let entry = set.get(&parsed.id).ok_or(AuthFailure::UnknownId)?.clone();
        let today = Utc::now().date_naive();
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();

        let cached = {
            let mut cache = lock(&self.cache);
            match cache.get(&digest) {
                Some(c) if c.verified_at.elapsed() < CACHE_TTL && c.key_id == entry.id => true,
                Some(_) => {
                    cache.remove(&digest);
                    false
                }
                None => false,
            }
        };
        if cached {
            return Self::check_state(entry, today);
        }

        let parsed_hash = PasswordHash::new(&entry.hash).map_err(|_| AuthFailure::WrongSecret)?;
        Argon2::default()
            .verify_password(presented.as_bytes(), &parsed_hash)
            .map_err(|_| AuthFailure::WrongSecret)?;
        let entry = Self::check_state(entry, today)?;

        if Arc::ptr_eq(&set, &self.set.load_full()) {
            lock(&self.cache).insert(
                digest,
                CacheEntry {
                    key_id: entry.id.clone(),
                    verified_at: Instant::now(),
                },
            );
        }
        Ok(entry)
    }

    fn check_state(entry: Arc<KeyEntry>, today: NaiveDate) -> Result<Arc<KeyEntry>, AuthFailure> {
        if entry.disabled {
            Err(AuthFailure::Disabled)
        } else if entry.expired_on(today) {
            Err(AuthFailure::Expired)
        } else {
            Ok(entry)
        }
    }

    /// Re-reads keys.toml; on failure keeps the previous set and records the error.
    pub fn reload(&self) -> Result<(), Problems> {
        match KeySet::load(&self.path, &self.known_repo_ids) {
            Ok(set) => {
                self.set.store(Arc::new(set));
                lock(&self.cache).clear();
                *lock(&self.reload_error) = None;
                Ok(())
            }
            Err(problems) => {
                *lock(&self.reload_error) = Some(problems.to_string());
                Err(problems)
            }
        }
    }

    /// The last reload failure, cleared by the next successful reload.
    pub fn reload_error(&self) -> Option<String> {
        lock(&self.reload_error).clone()
    }

    pub fn count(&self) -> usize {
        self.set.load().len()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn current(&self) -> Arc<KeySet> {
        self.set.load_full()
    }

    fn reload_and_log(&self, trigger: &str) {
        match self.reload() {
            Ok(()) => tracing::info!(trigger, keys = self.count(), "keys reloaded"),
            Err(problems) => {
                tracing::warn!(trigger, error = %problems, "keys reload failed, keeping previous set");
            }
        }
    }

    /// Spawns the file watcher (parent directory, 300ms debounce), a 2s mtime poll for bind mounts
    /// that inotify cannot see, and the SIGHUP listener; all call `reload`.
    pub fn watch(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        use notify::{RecursiveMode, Watcher};
        use tokio::signal::unix::{SignalKind, signal};

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let file_name = self.path.file_name().map(|n| n.to_os_string());
        let dir = match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        tokio::spawn(async move {
            let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res
                    && !ev.kind.is_access()
                    && ev
                        .paths
                        .iter()
                        .any(|p| p.file_name() == file_name.as_deref())
                {
                    let _ = tx.send(());
                }
            })
            .and_then(|mut w| w.watch(&dir, RecursiveMode::NonRecursive).map(|()| w));
            let _watcher = match watcher {
                Ok(w) => Some(w),
                Err(err) => {
                    tracing::error!(error = %err, "keys file watcher failed to start, SIGHUP only");
                    None
                }
            };
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => Some(s),
                Err(err) => {
                    tracing::error!(error = %err, "SIGHUP handler failed to install");
                    None
                }
            };
            let mut poll = tokio::time::interval(POLL_INTERVAL);
            let mut last_stamp = file_stamp(&self.path);
            loop {
                tokio::select! {
                    ev = rx.recv() => {
                        if ev.is_none() {
                            return;
                        }
                        while let Ok(Some(())) = tokio::time::timeout(DEBOUNCE, rx.recv()).await {}
                        last_stamp = file_stamp(&self.path);
                        self.reload_and_log("file_change");
                    }
                    _ = poll.tick() => {
                        let stamp = file_stamp(&self.path);
                        if stamp != last_stamp {
                            last_stamp = stamp;
                            self.reload_and_log("poll");
                        }
                    }
                    _ = async {
                        match hup.as_mut() {
                            Some(s) => { s.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        self.reload_and_log("sighup");
                    }
                }
            }
        })
    }
}

/// Generates a key and its stored entry. The plaintext key is shown once and never stored.
pub fn keygen(
    name: &str,
    repos: Option<Vec<String>>,
    expires: Option<NaiveDate>,
) -> (String, KeyEntry) {
    let mut id_bytes = [0u8; 5];
    let mut secret_bytes = [0u8; 32];
    rand::fill(&mut id_bytes[..]);
    rand::fill(&mut secret_bytes[..]);
    let id = data_encoding::BASE32_NOPAD
        .encode(&id_bytes)
        .to_ascii_lowercase();
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let key = format!("{KEY_PREFIX}{id}_{secret}");
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, None)
        .expect("argon2 params are constant and valid");
    let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(key.as_bytes())
        .expect("system RNG available for salt")
        .to_string();
    let entry = KeyEntry {
        id,
        name: name.to_string(),
        hash,
        repos,
        created: Utc::now().date_naive(),
        expires,
        disabled: false,
    };
    (key, entry)
}

/// Appends an entry to keys.toml, creating the file with mode 0600 when missing.
pub fn append_entry(path: &Path, entry: &KeyEntry) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut block = String::new();
    if !existing.is_empty() {
        if !existing.ends_with('\n') {
            block.push('\n');
        }
        if !existing.ends_with("\n\n") {
            block.push('\n');
        }
    }
    block.push_str(&entry.to_toml_table());
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(block.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_keys(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys.toml");
        std::fs::write(&path, content).expect("write");
        (dir, path)
    }

    fn repos(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn flip_secret(key: &str) -> String {
        let mut chars: Vec<char> = key.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }

    #[test]
    fn keygen_format_and_parse() {
        for _ in 0..50 {
            let (key, entry) = keygen("ci", None, None);
            let parsed = parse_key(&key).expect("generated key parses");
            assert_eq!(parsed.id, entry.id);
            assert!(valid_id(&entry.id));
            assert_eq!(key.len(), 4 + 8 + 1 + 43);
            assert!(entry.hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        }
    }

    #[test]
    fn parse_key_is_strict() {
        let secret = "A".repeat(43);
        assert!(parse_key(&format!("cex_abcdefg2_{secret}")).is_some());
        assert!(parse_key(&format!("cex_abcdefg2_{}_{}", &secret[..21], &secret[..21])).is_some());
        for bad in [
            String::new(),
            "cex_".to_string(),
            format!("xxx_abcdefg2_{secret}"),
            format!("cex_abcdefg_{secret}"),
            format!("cex_abcdefg22_{secret}"),
            format!("cex_ABCDEFG2_{secret}"),
            format!("cex_abcdefg1_{secret}"),
            format!("cex_abcdefg2_{}", &secret[..42]),
            format!("cex_abcdefg2_{secret}A"),
            format!("cex_abcdefg2_{}+", &secret[..42]),
            format!("cex_abcdefg2_{}=", &secret[..42]),
            format!(" cex_abcdefg2_{secret}"),
            format!("cex_abcdefg2_{secret}\n"),
            format!("cex_abcdefg2{secret}"),
        ] {
            assert!(parse_key(&bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn toml_rendering_round_trips() {
        let (_, mut entry) = keygen(
            "Name \"quoted\"",
            Some(repos(&["a", "b"])),
            NaiveDate::from_ymd_opt(2999, 1, 1),
        );
        entry.disabled = true;
        let text = entry.to_toml_table();
        let file: KeyFile = toml::from_str(&text).expect("parses");
        assert_eq!(file.key, vec![entry]);
        let (_, plain) = keygen("plain", None, None);
        let text = plain.to_toml_table();
        assert!(!text.contains("repos") && !text.contains("expires") && !text.contains("disabled"));
        let file: KeyFile = toml::from_str(&text).expect("parses");
        assert_eq!(file.key, vec![plain]);
    }

    #[test]
    fn round_trip_verify_reload_and_cache() {
        let (_dir, path) = tmp_keys("");
        let (key, entry) = keygen("alice", Some(repos(&["web"])), None);
        append_entry(&path, &entry).expect("append");
        let store = KeyStore::new(path.clone(), repos(&["web", "api"])).expect("loads");
        assert_eq!(store.count(), 1);

        let ok = store.verify(&key).expect("valid key verifies");
        assert_eq!(ok.name, "alice");
        assert_eq!(lock(&store.cache).len(), 1);
        assert_eq!(store.verify(&key).expect("cache hit").id, entry.id);

        assert_eq!(
            store.verify(&flip_secret(&key)).expect_err("must fail"),
            AuthFailure::WrongSecret
        );
        let unknown = format!("cex_{}_{}", "aaaaaaaa", "A".repeat(43));
        assert_eq!(
            store.verify(&unknown).expect_err("must fail"),
            AuthFailure::UnknownId
        );
        assert_eq!(
            store.verify("nonsense").expect_err("must fail"),
            AuthFailure::Malformed
        );

        let mut disabled = entry.clone();
        disabled.disabled = true;
        std::fs::write(&path, disabled.to_toml_table()).expect("write");
        assert_eq!(lock(&store.cache).len(), 1);
        store.reload().expect("reload ok");
        assert!(lock(&store.cache).is_empty());
        assert_eq!(
            store.verify(&key).expect_err("must fail"),
            AuthFailure::Disabled
        );
        assert_eq!(store.reload_error(), None);
    }

    #[test]
    fn expiry_is_checked_on_miss_and_hit() {
        let (_dir, path) = tmp_keys("");
        let today = Utc::now().date_naive();
        let (key, mut entry) = keygen("exp", None, None);
        entry.created = today - chrono::Days::new(10);
        entry.expires = Some(today);
        std::fs::write(&path, entry.to_toml_table()).expect("write");
        let store = KeyStore::new(path.clone(), vec![]).expect("loads");
        assert_eq!(
            store.verify(&key).expect_err("must fail"),
            AuthFailure::Expired
        );

        entry.expires = Some(today + chrono::Days::new(1));
        std::fs::write(&path, entry.to_toml_table()).expect("write");
        store.reload().expect("reload");
        store.verify(&key).expect("valid until tomorrow");
        store.verify(&key).expect("cache hit still valid");
        assert!(entry.expired_on(today + chrono::Days::new(1)));
        assert!(!entry.expired_on(today));
    }

    #[test]
    fn failed_reload_keeps_old_set() {
        let (_dir, path) = tmp_keys("");
        let (key, entry) = keygen("bob", None, None);
        std::fs::write(&path, entry.to_toml_table()).expect("write");
        let store = KeyStore::new(path.clone(), vec![]).expect("loads");
        std::fs::write(&path, "[[key]]\nid = \n").expect("write");
        let err = store.reload().expect_err("must fail");
        assert!(err.0[0].line.is_some());
        assert!(store.reload_error().is_some());
        assert_eq!(store.count(), 1);
        store.verify(&key).expect("old set still serves");
        std::fs::write(&path, entry.to_toml_table()).expect("write");
        store.reload().expect("recovers");
        assert_eq!(store.reload_error(), None);
    }

    #[test]
    fn empty_file_is_valid_and_rejects_everything() {
        let (_dir, path) = tmp_keys("");
        let store = KeyStore::new(path, vec![]).expect("empty ok");
        assert_eq!(store.count(), 0);
        let (key, _) = keygen("x", None, None);
        assert_eq!(
            store.verify(&key).expect_err("must fail"),
            AuthFailure::UnknownId
        );
        let (_d2, p2) = tmp_keys("# only a comment\n");
        assert_eq!(KeyStore::new(p2, vec![]).expect("ok").count(), 0);
    }

    fn load_err(content: &str, known: &[String]) -> Problems {
        let (_dir, path) = tmp_keys(content);
        KeySet::load(&path, known).expect_err("must fail")
    }

    #[test]
    fn validation_problems() {
        let (_, a) = keygen("a", None, None);
        let (_, b) = keygen("b", None, None);

        let mut dup_id = b.clone();
        dup_id.id = a.id.clone();
        let p = load_err(
            &format!("{}\n{}", a.to_toml_table(), dup_id.to_toml_table()),
            &[],
        );
        assert!(p.0.iter().any(|x| x.message.contains("duplicate id")));

        let mut dup_name = b.clone();
        dup_name.name = a.name.clone();
        let p = load_err(
            &format!("{}\n{}", a.to_toml_table(), dup_name.to_toml_table()),
            &[],
        );
        assert!(p.0.iter().any(|x| x.message.contains("duplicate name")));

        let mut empty_name = a.clone();
        empty_name.name = "  ".to_string();
        assert!(
            load_err(&empty_name.to_toml_table(), &[]).0[0]
                .message
                .contains("empty")
        );

        let mut bad_id = a.clone();
        bad_id.id = "ABCDEFGH".to_string();
        assert_eq!(load_err(&bad_id.to_toml_table(), &[]).0[0].key, "key.id");

        let mut bad_hash = a.clone();
        bad_hash.hash = "plaintext".to_string();
        assert_eq!(
            load_err(&bad_hash.to_toml_table(), &[]).0[0].key,
            "key.hash"
        );

        let mut wrong_alg = a.clone();
        wrong_alg.hash = "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy".to_string();
        let p = load_err(&wrong_alg.to_toml_table(), &[]);
        assert!(p.0[0].message.contains("argon2id"), "{}", p.0[0].message);

        let mut bad_repo = a.clone();
        bad_repo.repos = Some(repos(&["nope"]));
        let p = load_err(&bad_repo.to_toml_table(), &repos(&["web"]));
        assert!(p.0[0].message.contains("unknown repo id"));
        let (_d, path) = tmp_keys(&bad_repo.to_toml_table());
        assert!(KeySet::load(&path, &[]).is_ok());

        let mut bad_exp = a.clone();
        bad_exp.expires = Some(a.created);
        assert_eq!(
            load_err(&bad_exp.to_toml_table(), &[]).0[0].key,
            "key.expires"
        );
    }

    #[test]
    fn syntax_and_unknown_fields() {
        let p = load_err("[[key]]\nid = \"x\"\nbogus = 1\n", &[]);
        assert_eq!(p.0.len(), 1);
        assert_eq!(p.0[0].key, "syntax");
        assert!(p.0[0].message.contains("bogus"), "{}", p.0[0].message);
        assert_eq!(p.0[0].line, Some(3));
        let p = load_err("a = [\n", &[]);
        assert_eq!(p.0.len(), 1);
        assert!(p.0[0].line.is_some());
        let p = load_err("[server]\nx = 1\n", &[]);
        assert_eq!(p.0[0].key, "syntax");
        let missing =
            KeySet::load(Path::new("/nonexistent/keys.toml"), &[]).expect_err("must fail");
        assert!(missing.to_string().contains("cannot read"));
    }

    #[test]
    fn problem_lines_point_at_entry() {
        let (_, a) = keygen("a", None, None);
        let mut bad = a.clone();
        bad.id = "zz".to_string();
        let text = format!("{}\n{}", a.to_toml_table(), bad.to_toml_table());
        let p = load_err(&text, &[]);
        let expected = text
            .lines()
            .enumerate()
            .filter(|(_, l)| *l == "[[key]]")
            .nth(1)
            .map(|(i, _)| i + 1);
        assert_eq!(p.0[0].line, expected);
    }

    #[test]
    fn append_entry_creates_0600_and_spaces_blocks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys.toml");
        let (_, a) = keygen("a", None, None);
        let (_, b) = keygen("b", None, None);
        append_entry(&path, &a).expect("append");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        append_entry(&path, &b).expect("append");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("\n\n[[key]]"));
        assert!(!text.starts_with('\n'));
        let set = KeySet::load(&path, &[]).expect("valid");
        assert_eq!(set.len(), 2);

        std::fs::write(&path, "# header").expect("write");
        append_entry(&path, &a).expect("append");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.starts_with("# header\n\n[[key]]"));
    }

    #[tokio::test]
    async fn watch_reloads_on_file_change() {
        let (_dir, path) = tmp_keys("");
        let store = KeyStore::new(path.clone(), vec![]).expect("loads");
        let handle = store.clone().watch();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (_, entry) = keygen("watched", None, None);
        let tmp = path.with_extension("new");
        std::fs::write(&tmp, entry.to_toml_table()).expect("write");
        std::fs::rename(&tmp, &path).expect("atomic replace");
        let mut seen = false;
        for _ in 0..40 {
            if store.count() == 1 {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        handle.abort();
        assert!(seen, "watcher did not reload the replaced file");
    }
}
