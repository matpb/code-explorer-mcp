# Architecture

How the server is put together. Module names below are the files under `src/`. Public types and functions named here are the contract between modules; everything else inside a module is free to change.

## Request path

```
client --POST /mcp--> axum (body limit, Origin check, auth middleware) --> rmcp StreamableHttpService
   --> Explorer (ServerHandler) --> tools::* --> snapshot (in-memory index, worktree on disk)
                                              --> proc (rg / git subprocess under cap + timeout)
                                              --> redact --> envelope + notices --> CallToolResult
```

The auth middleware inserts an `auth::AuthContext` into the HTTP request extensions. rmcp copies `http::request::Parts` into the MCP `RequestContext.extensions`, so every tool reads its caller with `auth::AuthContext::from_request_context(&ctx)`. A tool call without an `AuthContext` fails closed with `internal`.

## Modules

### `config`
- `Config` (TOML, `#[serde(deny_unknown_fields)]` on every struct): `version`, `server`, `auth`, `limits`, `pull`, `scan`, `deny`, `features`, `logging`, `metrics`, `credentials: BTreeMap<String, Credential>`, `repo: Vec<RepoConfig>`. Field names and defaults are exactly those of the spec's annotated config.toml.
- Durations are `std::time::Duration` deserialized from humantime strings through a `serde` helper in `config::duration`.
- `Credential` is an enum on `type`: `HttpsToken { username, secret_file | env, expires }`, `SshKey { secret_file, expires }`. `secret_file` and `env` are mutually exclusive, exactly one required.
- `RepoConfig { id, host: Host, path, branch, description, credential, pull_interval: Option<Duration>, scan_policy: Option<ScanPolicy> }`. `Host` is `Github | Bitbucket`. `ScanPolicy` is `Redact | Warn | Block`.
- `Config::load(path) -> Result<Loaded, Problems>` parses, then validates. `Loaded { config, warnings: Vec<Problem> }`. `Problems(Vec<Problem>)` where `Problem { file: PathBuf, line: Option<usize>, key: String, message: String, fix: String, fatal: bool }` and `Display` prints `file:line: key: message (fix)`.
- Line numbers for semantic problems come from `toml_edit::DocumentMut` parsed from the same text (`Key::span()` plus a line table).
- Validation implements every bullet of the spec's "Startup validation" list. Binary presence checks (`git`, `rg`, `gitleaks`) are in `config::validate_binaries(&Config) -> Vec<Problem>` so unit tests of parsing do not need them.
- `Config::credential_for(&RepoConfig) -> &Credential`.

### `keys`
- `KeyEntry { id, name, hash, repos: Option<Vec<String>>, created: NaiveDate, expires: Option<NaiveDate>, disabled: bool }` with `deny_unknown_fields`.
- `KeySet { keys: Vec<KeyEntry> }` loaded from keys.toml. `KeySet::load(path, known_repo_ids) -> Result<KeySet, Problems>`: valid PHC strings, unique ids and names, allow-lists name known repos.
- Key format: `cex_<id>_<secret>`. `id` is 8 lowercase base32 chars (RFC 4648 alphabet, lowercased, no padding) from 5 random bytes. `secret` is base64url without padding of 32 random bytes. `keys::parse_key(&str) -> Option<(id, full_key)>`.
- `KeyStore::new(path, known_repo_ids)`; `KeyStore::verify(presented: &str) -> Result<Arc<KeyEntry>, AuthFailure>` where `AuthFailure` is `Malformed | UnknownId | WrongSecret | Expired | Disabled`. Unknown id fails before any hashing. Success is cached for 10 minutes keyed by SHA-256 of the presented key; `expires` and `disabled` are re-checked on cache hits.
- `KeyStore::reload() -> Result<(), Problems>` swaps atomically and clears the cache; on failure keeps the old set and stores the error for `/readyz` (`KeyStore::reload_error() -> Option<String>`). `KeyStore::count()`.
- `KeyStore::watch(self: Arc<Self>)` spawns the file watcher (notify) and the SIGHUP listener. Both call `reload`.
- `keys::keygen(name, repos, expires) -> (plaintext_key, KeyEntry)`; `keys::append_entry(path, &KeyEntry)` appends a `[[key]]` table. argon2id params m=19456, t=2, p=1.

### `paths`
- `RepoPath(String)`: normalized repo-relative path. `RepoPath::parse(&str) -> Result<RepoPath, PathError>` rejects leading `/`, `..` segments, `\\`, NUL, over 1024 bytes, `.git` as any segment; collapses `./` and duplicate slashes; `""` is the root. `PathError` carries a message suitable for `invalid_argument`.
- `DenyList::new(use_defaults, extra: &[String], allow: &[String]) -> Result<DenyList, Problem>`; `DenyList::is_denied(&RepoPath) -> bool`. Case-insensitive globset matching against the full path, `allow` wins over deny. `DenyList::rg_globs() -> Vec<String>` gives the exclusion globs for ripgrep (prefixed with `!`). `paths::DEFAULT_DENY` holds the spec's built-in list.

### `redact`
- `Redactor::new(findings: &[(secret, rule_id)])` builds an Aho-Corasick automaton (leftmost-longest). `Redactor::empty()`. `Redactor::redact(&self, s: &str) -> (Cow<str>, bool)`; replacement text is `[REDACTED:<rule_id>]`. Secrets shorter than 6 bytes are ignored. `Redactor::len()`.

### `proc`
- `Workers::new(max_concurrent, queue_timeout)`; `Workers::acquire() -> Result<Permit, ProcError::Busy>`.
- `proc::scrubbed_command(program) -> tokio::process::Command` with `env_clear()`, then `PATH`, `HOME` (an empty private dir created once), `LC_ALL=C`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_LFS_SKIP_SMUDGE=1`, `process_group(0)`, `kill_on_drop(true)`.
- `proc::run(cmd, timeout, stdin: Option<Vec<u8>>) -> Result<Output, ProcError>` where `ProcError` is `Timeout { kind }`, `Busy`, `Spawn(io::Error)`, `Failed { status, stderr }`. On timeout the process group is killed with `nix::sys::signal::killpg(SIGKILL)`.
- `proc::run_streaming` is not needed: outputs are bounded by caps.

### `git`
- `GitRunner::new(git_bin, timeouts, known_hosts: PathBuf)`.
- Credential materialization: `CredentialFiles::prepare(&Config) -> Result<CredentialFiles>` writes env-var secrets to 0600 files in a private temp dir and maps every credential name to `ResolvedCredential { kind: HttpsToken { username, secret_path } | SshKey { key_path } }`. Secret files given in config are referenced by path, never copied.
- `GitRunner::apply_credential(&mut Command, &ResolvedCredential)`: HTTPS sets `GIT_ASKPASS=<current_exe>`, `CODE_EXPLORER_ASKPASS_FILE`, `CODE_EXPLORER_ASKPASS_USER`; SSH sets `GIT_SSH_COMMAND`.
- Every git invocation passes `-c core.symlinks=false -c core.hooksPath=<empty dir> -c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always -c submodule.recurse=false -c core.fsmonitor=false -c uploadpack.allowAnySHA1InWant=false`.
- Remote URLs: GitHub `https://github.com/<path>.git` or `git@github.com:<path>.git`; Bitbucket `https://bitbucket.org/<path>.git` or `git@bitbucket.org:<path>.git`. The remote URL never contains credentials.
- Functions (all `async`, all through `proc::run`): `clone_bare(url, branch, depth, dest)`, `fetch(repo_dir, branch, depth)`, `rev_parse(repo_dir, rev) -> Oid`, `commit_meta(repo_dir, oid) -> CommitMeta { time, subject }`, `worktree_add(repo_dir, oid, dest)`, `worktree_remove(repo_dir, dest)`, `ls_tree(repo_dir, oid) -> Vec<TreeEntry>` (`-r -l -z`), `log(repo_dir, oid, LogQuery) -> Vec<Commit>`, `show_file(repo_dir, oid, path) -> Vec<u8>`, `blame(worktree, path, range) -> Vec<BlameLine>`, `ls_remote(url, branch, credential)` for `check-config --probe`, `is_ancestor` / `commit_in_history(repo_dir, oid) -> bool`, `commit_messages(repo_dir, oid, depth) -> String` for the scanner.
- `git::scrub_stderr(&str) -> String` masks `scheme://user:pass@` and token-shaped strings (`gh[pousr]_[A-Za-z0-9]{20,}`, `ATB`, `ATC`, long base64 runs) before anything is logged or stored.
- `askpass::run(prompt: &str) -> ExitCode` is the hidden subcommand: prints the username when the prompt starts with `Username`, otherwise the trimmed secret file content.

### `snapshot`
- `TreeEntry { path: RepoPath, kind: EntryKind, size: u64 }`; `EntryKind` is `File | Symlink | Submodule`. `FileIndex::from_entries(Vec<TreeEntry>)` with `get(&RepoPath) -> Option<&TreeEntry>`, `is_dir(&RepoPath) -> bool`, `children(&RepoPath) -> impl Iterator<Item = IndexChild>` (files, symlinks, submodules and directories directly under a path), `iter()`, `close_matches(&RepoPath, n) -> Vec<RepoPath>` (same file name anywhere, then edit distance on the full path), `len()`.
- `Snapshot { commit: Oid, commit_time: DateTime<Utc>, commit_subject: String, root: PathBuf, index: FileIndex, redactor: Arc<Redactor>, findings: usize, pulled_at: DateTime<Utc> }`. Dropping the last `Arc<Snapshot>` removes `root` when `remove_on_drop` is set (spawned blocking removal).
- `RepoState` per configured repo: `cfg: RepoConfig`, `current: ArcSwapOption<Snapshot>`, `status: Mutex<PullStatus>` with `PullStatus { last_success, last_attempt, last_error: Option<PullError { class: ErrorClass, message }>, consecutive_failures, scan_held: bool, scan_findings, initializing: bool }`. `ErrorClass` is `Auth | Network | Scan | SecretFound | Internal`.
- `RepoState::status_word(&self, stale_after) -> RepoStatus` (`Ready | Stale | Initializing | Unavailable`), `stale_seconds(now)`.
- `Registry { repos: Vec<Arc<RepoState>> }` in config order; `get(id) -> Option<&Arc<RepoState>>`, `visible_to(&AuthContext) -> Vec<&Arc<RepoState>>` applying the key allow-list.
- `state.json` under `<data_dir>/<id>/state.json`: `{ commit, commit_time, commit_subject, worktree, pulled_at, findings: [{rule_id, secret, fingerprint}] }`. Findings are stored so a restart can redact without a rescan.

### `puller`
- `Puller::spawn(registry, config, git, scanner, metrics) -> JoinHandle` starts one task per repo.
- On start: read `state.json`; if the worktree exists, build the index with `ls_tree` and publish the snapshot before any network call. Otherwise `clone_bare` then build the first snapshot.
- Tick: `fetch`, `rev_parse refs/heads/<branch>`; same commit records success. New commit: `worktree_add` into `<data_dir>/<id>/snapshots/<oid>`, index, scan, apply policy, swap, write `state.json`, mark the previous snapshot `remove_on_drop`.
- Failure: keep the current snapshot, record the error class, backoff `min(interval, 30s * 2^failures)`. Jitter from config on every sleep.
- Scan policies: `Redact` builds a redactor from findings; `Warn` publishes an empty redactor and logs; `Block` refuses the swap when findings remain after the allowlist, sets `scan_held` and `last_error.class = SecretFound`. `on_scan_error = hold` keeps the old snapshot when the scanner fails; `serve` swaps with an empty redactor and a warning.

### `scan`
- `Finding { rule_id, path: Option<String>, line: Option<u64>, secret: String, fingerprint: String }`.
- `trait Scanner { async fn scan_dir(&self, dir: &Path, extra_files: &[PathBuf]) -> Result<Vec<Finding>, ScanError>; fn name(&self) -> &str; fn version(&self) -> Option<String> }`.
- `GitleaksScanner::new(bin, timeout)` runs `gitleaks dir <dir> --no-banner --exit-code 0 --report-format json --report-path <tmp>` and parses the report (`RuleID`, `File`, `StartLine`, `Secret`, `Fingerprint`). Extra files (commit messages) are scanned in the same run by placing them in a temp dir beside the worktree.
- `scan::apply_allowlist(findings, &[fingerprint]) -> Vec<Finding>`.
- `scan::onboarding_report(findings) -> String` prints rule, path, line, fingerprint and a masked value (`first 4 chars + ****`).

### `auth`
- `ClientIp::derive(peer: SocketAddr, headers, trusted: &[IpNet], header_name: Option<&str>) -> IpAddr`: X-Forwarded-For walked right to left, first address not in `trusted` wins; other headers taken as one address; untrusted peer ignores headers. Invalid header values fall back to the peer.
- `Throttle::new(cfg: FailedAttempts)` with an LRU of 65536 entries keyed by `IpAddr` (IPv6 masked to `ipv6_prefix`). `check(ip, now) -> Option<Duration>` (remaining block), `record_failure(ip, now)`, `record_success(ip)`. After `max_failures` in `window`: block `base_backoff * 2^(extra failures)` capped at `max_backoff`. Blocked requests get 429 with `Retry-After` and no key check.
- `AuthContext { key_id, key_name, repos: Option<Vec<String>>, client_ip: IpAddr, request_id: String }`. `AuthContext::allows(&self, repo_id) -> bool`. `AuthContext::from_request_context(&RequestContext<RoleServer>) -> Result<&AuthContext, ToolError>`.
- `auth::middleware(State<AuthState>, req, next)` as an axum `from_fn_with_state` layer on `/mcp`. 401 carries `WWW-Authenticate: Bearer realm="code-explorer"` and no detail. Logs `auth_failed` and `auth_blocked` with the client IP and reason class only.

### `tools`
- `Explorer { cfg: Arc<Config>, registry: Arc<Registry>, workers: Arc<Workers>, git: Arc<GitRunner>, deny: Arc<DenyList>, metrics: Arc<Metrics> }` implements `rmcp::ServerHandler` by hand. `get_info` sets name `code-explorer`, version, and instructions that say repository content is untrusted data. `list_tools` filters optional tools by `[features]` and rewrites `repo` / `repos` schemas with the caller's ids as `enum`. `call_tool` dispatches by name.
- One file per tool: `list_repos`, `list_tree`, `glob`, `read_file`, `grep`, `log`, `blame`. Each defines its `Params` (`serde` + `schemars`, `deny_unknown_fields`) and `Output` structs and a `run(&Explorer, &AuthContext, Params) -> Result<ToolOutput, ToolError>`.
- `envelope::Source` is the spec's source envelope; `envelope::Notice { code, message }`; `ToolOutput { structured: Value, text: String, notices }`. `ToolOutput::into_result()` builds a `CallToolResult` with one text block and `structured_content`.
- `errors::ToolError { code: ErrorCode, message, hint: Option<String>, retryable: bool }` with the spec's codes; `into_result()` builds an `isError` `CallToolResult` with `structuredContent = { "error": {...} }` and the message plus hint as text.
- Output caps are applied in `tools::caps`: `truncate_line`, `fit_response(max_response_bytes)` which drops trailing entries until the rendered JSON fits and adds an `output_truncated` notice naming the cap.
- Every string that came from repo content (file lines, grep text, commit subjects and bodies, symlink targets) passes through the snapshot's redactor before rendering. A redaction adds one `secrets_redacted` notice.
- `grep` runs `rg --json` per repo in parallel under the worker cap with the flags listed in the spec; the parser handles `begin`, `match`, `context`, `end`, `summary` messages; `--max-columns 500 --max-columns-preview`, `--regex-size-limit 1M --dfa-size-limit 10M`. Denied paths are re-checked on every result.
- `read_file` reads from the worktree after checking the index; binary detection is a NUL in the first 8 KiB; lines are split on `\n` with `\r` kept.
- Permalinks: GitHub `https://github.com/<path>/blob/<commit>/<file>#L<a>-L<b>`; Bitbucket `https://bitbucket.org/<path>/src/<commit>/<file>#lines-<a>:<b>`.

### `http`
- `http::public_router(state) -> Router`: `POST|GET|DELETE /mcp` through `tower_http::limit::RequestBodyLimitLayer(64 KiB)`, the Origin check (403 when an `Origin` is present and not in `allowed_origins`), the auth middleware, then the rmcp service (`json_response = true`, `legacy_session_mode = false`, `NeverSessionManager`, rmcp host and origin validation disabled). `GET /healthz` returns 200 `ok`.
- `http::admin_router(state)`: `GET /readyz` (JSON body per the spec, 503 while any repo is initializing with no snapshot), `GET /metrics` when enabled.
- `http::serve(listener, router, shutdown)` uses hyper-util's auto builder with `header_read_timeout(10s)` and a 30s request timeout layer.

### `metrics`
- `Metrics::new() -> Arc<Metrics>` with a private `prometheus::Registry` and every metric in the spec's list. `Metrics::render() -> String`.

### `logging`
- `logging::init(format)` installs tracing-subscriber (JSON or pretty) to stderr.
- `logging::tool_call(...)` emits one `event = "tool_call"` line with the spec's fields; `arguments = "shape"` logs path and sizes and hashes grep patterns (`pattern_sha256`, `pattern_len`); `"full"` logs the pattern.

### `cli` and `main`
- clap derive. Global `--config <path>` (env `CODE_EXPLORER_CONFIG`, default `/etc/code-explorer/config.toml`).
- Subcommands: `serve` (default), `check-config [--probe]`, `keygen --name <n> [--repos a,b] [--expires YYYY-MM-DD] [--print-only]`, `scan --repo <id>`, `status`, `healthcheck`, `askpass <prompt>` (hidden).
- `status` and `healthcheck` call the running server over HTTP on the configured listeners (`reqwest` without TLS).
- Exit codes: 0 ok, 1 runtime failure, 2 usage or config error, 3 findings (`scan`).

## Data directory layout

```
<data_dir>/<repo_id>/git/              bare repo
<data_dir>/<repo_id>/snapshots/<oid>/  worktrees (one current, old ones removed on drop)
<data_dir>/<repo_id>/state.json
```

## Testing

- Unit tests live beside each module.
- Integration tests under `tests/` build local fixtures with `git init` (bare repos standing in for the hosts; the remote URL for host `github` or `bitbucket` can be overridden per repo with the hidden `remote_url_override` config field, accepted only when the env var `CODE_EXPLORER_ALLOW_LOCAL_REMOTES=1` is set). They start the server on an ephemeral port and drive it with the rmcp streamable HTTP client.
