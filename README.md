# Code Explorer MCP

A read-only [MCP](https://modelcontextprotocol.io) server that lets AI agents explore a curated set of GitHub and Bitbucket repositories the way a coding agent explores a local checkout: list, browse, glob, read line ranges, regex search, recent history.

- One Rust binary, one container, one config file, one keys file. No database, no admin API.
- Every repo is a shallow, single-branch clone refreshed on a timer. Search is ripgrep over the local snapshot, never a per-request host API call.
- Every result is stamped with the commit it came from, so an answer or a mockup can cite exactly what it read.
- Safe by default for a public project: per-user hashed keys, failed-auth throttling, secret scanning with redaction, a path deny-list, output caps, timeouts, typed errors, attributable JSON logs.
- Strictly read-only toward the repos and the hosts. There is no write tool of any kind.

## Tools

| Tool | What it does |
|---|---|
| `list_repos` | The repos this key may see, with description, branch, commit, freshness and status. `secrets_redacted` counts the values masked in served content (0 unless the `redact` policy applies) and `secret_findings` counts what the scanner found under any policy. |
| `list_tree` | Directory listing from a path, breadth-first to a depth, from the in-memory index. |
| `glob` | Find files by gitignore-style pattern (`src/**/*.tsx`). |
| `read_file` | Exact text of a line range, with a permalink to the host at that commit. |
| `grep` | ripgrep across one or many repos: regex or literal, globs, file types, context lines. Each match carries `before` and `after` arrays of `{line, text}` objects; a neighboring match is context of the match next to it. A repo that cannot get a worker slot is listed in `repos_skipped` with reason `busy`. |
| `log` | Recent commits, optionally for one path, with changed files. |
| `blame` | Optional, off by default. Line attribution within the kept history. |

Every result carries a `source` envelope (`repo`, `host`, `path`, `branch`, `commit`, `commit_time`, `pulled_at`, `stale`) and a `notices` list (`output_truncated`, `stale_snapshot`, `secrets_redacted`, `history_truncated`). Errors are tool results with `isError` and a stable code (`unknown_repo`, `path_not_found`, `path_denied`, `binary_file`, `file_too_large`, `invalid_pattern`, `repo_not_ready`, `timeout`, `busy`, and so on), a message and a hint the model can act on.

Repository content returned by the tools is untrusted data. The server instructions and every tool description say so.

## Quick start

Requirements on the host: Docker with Compose, a DNS name pointing at the host (for automatic TLS), and a read-only credential per repo.

```sh
git clone https://github.com/matpb/code-explorer-mcp.git
cd code-explorer-mcp/deploy
cp .env.example .env            # set DOMAIN; change EDGE_SUBNET, EDGE_IP_RANGE and CADDY_IP if 172.30.0.0/24 is taken on this host
cp ../config.example.toml config.toml
mkdir -p secrets && touch keys.toml
# put each repo's SSH private key (or token) in secrets/, see "Onboarding a repo"
$EDITOR config.toml             # server.trusted_proxies must be Caddy's address (CADDY_IP as a /32)
docker compose build
docker compose run --rm explorer check-config --probe
docker compose run --rm explorer keygen --name my-agent --print-only >> keys.toml
docker compose up -d
```

`keygen --print-only` writes the hashed `[[key]]` entry to stdout (appended to `keys.toml` here) and prints the key itself once on stderr, in the form `cex_<id>_<secret>`. The server never writes `keys.toml`: it is mounted read-only, owned by the operator, and the running server picks up your edits within a few seconds. Give the key to the client as a Bearer token:

```json
{
  "mcpServers": {
    "code-explorer": {
      "type": "http",
      "url": "https://explorer.example.com/mcp",
      "headers": { "Authorization": "Bearer cex_xxxxxxxx_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" }
    }
  }
}
```

Check readiness from inside the container with `docker compose exec explorer code-explorer status`.

## Configuration

Two TOML files, both server-side and never committed:

- `config.toml`: server, limits, pull schedule, scanning, deny-list, credentials and the repo list. Fixed per process.
- `keys.toml`: client keys as argon2id hashes, maintained by the operator with `keygen --print-only`, read-only to the server, reloaded on change and on `SIGHUP`.

`config.example.toml` documents every field with its default. Unknown fields are errors, every problem is reported at once with file and line, and `check-config` runs the same validation without starting the server.

### Server

| Key | Default | Meaning |
|---|---|---|
| `server.listen` | `0.0.0.0:8080` | Public listener: `/mcp` and `/healthz`. |
| `server.admin_listen` | `0.0.0.0:9090` | `/readyz` and `/metrics`. Never publish this port. |
| `server.public_url` | | The URL clients use. Informational. |
| `server.allowed_origins` | `[]` | Browser origins allowed. A present `Origin` not listed gets 403. |
| `server.trusted_proxies` | `[]` | Only these peers may set the client IP header. In the compose setup this is Caddy's fixed address, `172.30.0.2/32`. Never a whole Docker subnet: its gateway address is how host-local clients appear. |
| `server.client_ip_header` | `X-Forwarded-For` | Header the proxy sets. Empty string disables it. |
| `server.data_dir` | `/data` | Clones and snapshots. A cache: safe to delete. |
| `server.max_connections` | `1024` | Open connections on the public listener. Beyond it, new connections are closed at once. Idle connections close after 60 s. |

### Auth and throttling

| Key | Default | Meaning |
|---|---|---|
| `auth.keys_file` | `/etc/code-explorer/keys.toml` | Watched and reloaded. |
| `auth.failed_attempts.max_failures` | `5` | Failures per client IP in `window` before a block. |
| `auth.failed_attempts.window` | `10m` | |
| `auth.failed_attempts.base_backoff` | `2s` | Doubles per further failure, up to `max_backoff` (`15m`). |
| `auth.failed_attempts.ipv6_prefix` | `64` | IPv6 clients are grouped by prefix. |
| `auth.max_concurrent_verifications` | `4` | argon2 verifications in flight. Beyond it a request waits 2 s, then gets 503 with `Retry-After`. Cached keys never need a slot. |

Authenticated traffic is never rate limited. A global worker cap bounds subprocesses for everyone at once.

### Limits

| Key | Default | Meaning |
|---|---|---|
| `limits.max_response_bytes` | `262144` | Per tool result, after rendering. Truncation is a notice. |
| `limits.max_file_bytes` | `4194304` | `read_file` refuses larger files. |
| `limits.max_line_chars` | `2000` | Longer lines are cut with a marker. |
| `limits.max_concurrent_workers` | `16` | `rg` and `git` subprocesses at once. |
| `limits.queue_timeout` | `5s` | Wait for a worker slot, then the error `busy`. |
| `limits.rg_timeout`, `limits.git_timeout` | `10s` | Subprocess timeouts; the process group is killed on expiry. |

### Pull

| Key | Default | Meaning |
|---|---|---|
| `pull.interval` | `5m` | Per-repo override with `pull_interval`. Minimum `30s`. |
| `pull.jitter` | `30s` | Random extra delay per tick. |
| `pull.depth` | `200` | Commits of history kept; bounds `log` and `blame`. |
| `pull.fetch_timeout`, `pull.clone_timeout` | `2m`, `10m` | |
| `pull.stale_after` | `30m` | No successful pull for this long: results carry `stale_snapshot`. |
| `pull.known_hosts_file` | `/etc/code-explorer/known_hosts` | Pinned host keys for SSH. The image ships github.com, bitbucket.org and ssh.bitbucket.org (Bitbucket Cloud's SSH host from November 12, 2026). |

### Scan, deny-list, features, logging, metrics

| Key | Default | Meaning |
|---|---|---|
| `scan.policy` | `redact` | `redact`, `warn` or `block`. Per-repo override with `scan_policy`. |
| `scan.on_scan_error` | `hold` | `hold` keeps the previous snapshot when the scanner fails; `serve` swaps with a warning. |
| `scan.allowlist` | `[]` | gitleaks fingerprints judged false positives. |
| `deny.use_defaults` | `true` | Built-in list below. |
| `deny.paths`, `deny.allow` | `[]` | Extra globs and exceptions, matched case-insensitively. A pattern without a `/` matches at any depth, like `.gitignore`. |
| `features.file_at_commit`, `features.blame` | `false` | Optional tools. |
| `logging.format` | `json` | Or `pretty`. |
| `logging.arguments` | `shape` | `shape` logs paths and sizes and hashes grep patterns; `full` logs patterns. |
| `logging.author_emails` | `false` | `log` returns author names only unless true. |
| `metrics.enabled` | `true` | Prometheus text on the admin listener. |

Built-in deny-list: `.git/**`, `**/.env`, `**/.env.*`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.pfx`, `**/*.jks`, `**/*.keystore`, `**/id_rsa*`, `**/id_ed25519*`, `**/.npmrc`, `**/.pypirc`, `**/.netrc`, `**/*.tfstate`, `**/*.tfstate.*`, `**/credentials*.json`, `**/secrets.*`, `**/id_ecdsa*`, `**/id_dsa*`, `**/*.p8`, `**/.htpasswd`, `**/.git-credentials`, `**/.docker/config.json`, `**/kubeconfig*`, `**/*.kdbx`, `**/*.gpg`, `**/service-account*.json`. Templates such as `.env.example` are denied too; carve exceptions with `deny.allow`.

### Credentials and repos

```toml
[credentials.web-ui-key]
type        = "ssh_key"                      # GitHub deploy key or Bitbucket access key
secret_file = "/run/secrets/web_ui_key"      # re-read on every fetch

[[repo]]
id          = "web-ui"
host        = "github"                       # github | bitbucket
path        = "example-org/web-ui"           # owner/name or workspace/name
branch      = "main"                         # exactly one branch per entry
description = "Customer web app (React). Shared UI components in src/components."
credential  = "web-ui-key"
```

Credentials are referenced by name and resolved from a secret file or an environment variable. Values never live in the config. A second branch of the same repo is a second entry with its own id. A public repo may omit `credential` and is read anonymously over HTTPS.

## Onboarding a repo

1. Create a read-only credential on the host, scoped to this one repo:
   - GitHub: a deploy key (Settings, Deploy keys, leave "Allow write access" unchecked). Recommended.
   - Bitbucket: a repository access key (Repository settings, Access keys). Read-only by design. Recommended.
   - GitHub, alternative: a fine-grained personal access token limited to the one repository with Contents read-only. Needs an expiry.
   - Bitbucket, alternative: a repository access token with Repository Read only. Availability depends on the workspace plan.
2. Store it as a secret file (preferred, rotates without restart) or an environment variable (read at start).
3. Add a `[credentials.<name>]` block and a `[[repo]]` block with a description written for agents: what the repo is, where the important parts live.
4. `code-explorer check-config --probe` and fix everything it reports.
5. `code-explorer scan --repo <id>`. For each finding: rotate real secrets at their source, add fingerprints of false positives to `scan.allowlist`, choose the repo's policy.
6. Restart the server. Watch `status` until the repo is `ready`.
7. Smoke test from a client: `list_repos` shows the expected commit, `grep` finds a known string, `read_file` on `.env` returns `path_denied`.
8. Add the repo id to the allow-lists of the keys that need it. Keys reload without a restart.

## Keys and rotation

- `code-explorer keygen --name <who> [--repos a,b] [--expires YYYY-MM-DD] --print-only` prints the hashed `[[key]]` entry on stdout and the key once on stderr. Append the entry to `keys.toml` yourself (`>> keys.toml`). Without `--print-only`, `keygen` appends to the keys file directly, which only works where the file is writable, such as a host install.
- `keys.toml` belongs to the operator and is mounted read-only in the container. The server only reads it, so a compromised server cannot mint itself a key.
- The running server picks up changes to `keys.toml` within a few seconds (inotify plus a 2 second poll, so Docker bind mounts work) and on `SIGHUP`.
- Rotate a client key: `keygen` a new one, hand it out, and once the logs show the new name delete the old entry or set `disabled = true`. Reload is automatic and clears the verify cache, so revocation is immediate.
- Rotate a repo credential: create the new key or token with the same scope, overwrite the secret file (next fetch uses it) or restart for an env var, confirm `status` shows `last_success` moving, then revoke the old one on the host.

## Security model

Trust boundaries: clients are authenticated but semi-trusted (an agent can be steered by what it reads), repository content is untrusted data, the hosts are trusted for transport only, the operator and the config files are trusted.

- **Keys** are stored only as argon2id hashes. A stolen `keys.toml` grants nothing. Keys carry 256 random bits and a `cex_` prefix that secret scanners can match.
- **Failed authentication** is throttled per client IP with exponential backoff. Blocked requests get 429 and no key is checked. Unknown ids, disabled and expired keys are rejected before any hashing, and argon2 verifications are bounded, so a flood of bad keys cannot exhaust memory. The client IP header is honored only from `trusted_proxies`.
- **Path traversal**: paths are normalized and checked against the in-memory file index before any disk access, then resolved beneath the snapshot root. `.git` and `..` are rejected outright.
- **Symlinks**: checkouts use `core.symlinks=false`, so links become small plain files holding the link text. ripgrep never follows links.
- **Secrets in repos**: gitleaks scans every new snapshot with the server's own ruleset (a repo cannot ship a `.gitleaks.toml` or `gitleaks:allow` comment to hide findings, and the default path allowlist is disabled so `node_modules`, images and lock files are scanned too). Under the `redact` policy the found values are replaced in the snapshot files themselves before anything is served, so `grep` cannot be used to guess a value by bisection, and an in-memory matcher masks them again in commit messages and anything not on disk. Under `block` the snapshot is held. With `file_at_commit` on, the kept history is scanned as well. The server cannot remove a secret from Git history: rotate it at the source.
- **Credentials** reach git through an askpass helper or `GIT_SSH_COMMAND`, never a URL, an argument or `.git/config`. Git stderr is scrubbed before it is logged.
- **Subprocesses** run with a cleared environment, hooks disabled, LFS smudge off, protocols limited to https and ssh, each in its own process group with a timeout and a kill on expiry, under a global concurrency cap.
- **Regex**: ripgrep's default linear-time engine only, size limits on the compiled regex, pattern length caps.
- **Container**: non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`.
- **Prompt injection**: the server has no write or outbound tools, so injected text cannot act through it. Clients should keep a human in the loop for actions with side effects.

See `SECURITY.md` for how to report a vulnerability.

## Deployment

One image (`Dockerfile`), one compose file (`deploy/compose.yaml`) with two profiles.

**Caddy mode (default).** `COMPOSE_PROFILES=caddy` in `.env` starts Caddy, which obtains and renews a certificate for `DOMAIN`, sets `X-Forwarded-For` and proxies to the explorer. The explorer port stays bound to `127.0.0.1` on the host.

**Gateway mode.** Set `COMPOSE_PROFILES=` (empty) so Caddy does not start, set `EXPLORER_BIND` to an address your gateway can reach, put the gateway's egress addresses in `server.trusted_proxies`, and set `server.client_ip_header` to what it sends. Make sure the gateway forwards `Authorization` untouched and allows request bodies up to 64 KiB.

The admin port `9090` is never published or proxied. Scrape `/metrics` and read `/readyz` from the compose network.

Local run without Docker: build with `cargo build --release`, have `git`, `rg` and `gitleaks` on `PATH`, write a config, then `code-explorer --config ./config.toml serve`.

## Operations

| Command | Does |
|---|---|
| `serve` | Run the server (default). |
| `check-config [--probe]` | Full validation of config and keys. `--probe` runs `git ls-remote` per repo. |
| `keygen --name <n> [--repos a,b] [--expires YYYY-MM-DD] [--print-only]` | Mint a client key. |
| `scan --repo <id>` | Temp clone plus secret scan; masked report; exit 3 on findings. |
| `status` | Print `/readyz` of the running server. |
| `healthcheck` | Exit 0 if `/healthz` answers. Used by the image's `HEALTHCHECK`. |

Endpoints: `/healthz` (public, liveness only), `/readyz` (admin, JSON per repo: status, commit, last success, last error, failures, staleness, scan state, credential expiry), `/metrics` (admin, Prometheus).

Logs are JSON on stderr, one line per tool call with the key name, client IP, tool, repos, argument shape, duration, bytes, result and commit. Also logged: `auth_failed`, `auth_blocked`, `pull`, `scan`, `keys_reloaded`. The presented key is never logged.

Upgrading: read the release notes, pull the new image, run `docker compose run --rm explorer check-config`, restart. Snapshots in `/data` are a cache and can always be deleted.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `check-config` lists problems | Each line names the file, line and key. Fix them all; the server refuses to start otherwise. |
| `/readyz` stays 503 | A first clone is still running or failing. The body shows `last_error` per repo: `auth` means the credential is wrong or lacks access, `network` means the host is unreachable or the path is wrong. |
| 503 `busy` from `/mcp` | More than `auth.max_concurrent_verifications` uncached keys are being verified at once. Legitimate clients are cached after their first call, so this means a flood of bad keys. |
| `repo_not_ready` in tool results | Same as above, from the client's side. Retry after the clone finishes. |
| `stale_snapshot` notices | Pulls have failed for longer than `pull.stale_after`. The notice carries the error class. Check `status`. |
| A repo is `scan_held` | Policy `block` found a secret. Rotate it, or allowlist the fingerprint if it is a false positive, then wait for the next pull. |
| 401 from `/mcp` | Missing or wrong key, expired or disabled entry, or a keys file that failed to reload (see `keys.reload_error` in `/readyz`). |
| 429 from `/mcp` | Too many failed attempts from that client IP. Wait for `Retry-After`. If every client shows the same IP, your proxy is not in `trusted_proxies`. |
| 403 from `/mcp` | A browser `Origin` not in `server.allowed_origins`. |
| `keygen` fails with permission denied | The keys file is read-only to the server on purpose. Use `keygen --print-only >> keys.toml` on the host instead. |
| `docker compose up` says the pool overlaps | Another network already uses `172.30.0.0/24`. Set `EDGE_SUBNET`, `EDGE_IP_RANGE` and `CADDY_IP` in `.env` to a free range, and `server.trusted_proxies` to the new `CADDY_IP/32`. |
| `busy` or `timeout` | The worker cap or a subprocess timeout. Narrow the search with `path`, `glob` or `type`, or raise the limits. |
| SSH fetch fails with a host key error | The host's key is not in `pull.known_hosts_file`. The image ships github.com, bitbucket.org and ssh.bitbucket.org; mount your own file for others. |

## Development

```sh
scripts/check.sh
```

That runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny` (advisories and licenses) and gitleaks over the tree and the full history. Tests build real local Git repositories as fixtures and need `git`, `rg` and `gitleaks` on `PATH`. The integration suite starts the server on ephemeral ports and drives it with a real MCP client. See `docs/ARCHITECTURE.md` for the module layout, `docs/DECISIONS.md` for the design choices and `docs/REVIEW.md` for the review findings and their outcomes.

## License

MIT. See `LICENSE`.
