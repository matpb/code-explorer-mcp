# Review log

Findings from reviews of this codebase and what was done about them. Three reviews ran on the complete v1 tree before publication: an independent correctness review, an independent security review (both by reviewers briefed only with the code and the design spec) and an automated code review. Duplicates across the three are merged. Severity is the reviewers' call. Newest first.

## Pre-publication reviews of v1

### High

| Finding | Outcome |
|---|---|
| Multi-line secrets (PEM private keys) were never redacted: the matcher held the whole block, callers redacted one line at a time, so no line matched. | Fixed. Under `redact`, secret values are now replaced in the snapshot files themselves at build time, matched over the whole file. The in-memory matcher also holds each line of a multi-line secret (PEM header and footer lines excluded). `read_file` at a commit redacts the whole buffer before splitting lines. |
| `grep` was a bisection oracle for redacted secrets: ripgrep searched the raw worktree, so match presence, `total_matches_seen`, `files` and `count` modes revealed a value one character at a time. | Fixed by the same change: ripgrep now searches files that no longer contain the secret. |
| Denied files with different-case names (`.ENV`, `Secrets.yaml`) leaked content through `total_matches_seen`: the ripgrep exclusions were case-sensitive and matches were counted before the deny post-filter. | Fixed. Exclusions go to ripgrep as `--iglob`; every count is computed after the post-filter, which also drops paths that fail normalization. Integration test covers all three output modes. |
| With `file_at_commit` on, the kept history was never scanned, so a secret deleted at the tip was served in clear from an older commit. | Fixed. The scanner runs in git mode over the kept range (first-parent, so secrets inside merge commits are seen) when the feature is on. Findings feed the matcher and the `block` policy. |

### Medium

| Finding | Outcome |
|---|---|
| Concurrent requests with a known key id and wrong secrets each ran an argon2 verification (19 MiB, up to 512 blocking threads), and failures were recorded only after hashing, so the throttle never engaged. Disabled keys were hashed too. | Fixed. Disabled, expired, malformed and unknown-id keys are rejected before any hashing and count as failures at once. Verifications run under a semaphore (`auth.max_concurrent_verifications`, default 4); a request that cannot get a slot within 2 s gets 503 with `Retry-After`. |
| One successful authentication cleared the throttle record for that client IP, so a key holder behind a shared address could probe other keys forever. | Fixed. Only a success after an expired block resets the record. |
| gitleaks' built-in path allowlist skipped `node_modules`, `*.svg`, `*.pdf`, minified and lock files, while ripgrep and `read_file` served them. UTF-16 files were transcoded by ripgrep but never scanned. | Fixed. The scanner uses a vendored copy of the gitleaks default ruleset with the global path allowlist removed (gitleaks has no override for an inherited allowlist). ripgrep runs with `--encoding none` and UTF-16 files are skipped. |
| Silent TCP connections and idle HTTP/2 connections never timed out, and there was no connection cap. | Fixed. 60 s idle timeout per connection, HTTP/2 keep-alive 20 s, `server.max_connections` (default 1024). |
| A `block` hold did not mark the repo stale, so results looked current for up to `stale_after`. | Fixed. A held repo reports `stale` with the `secret_found` reason, and results carry the stale notice. |
| `grep` context line numbers were wrong when adjacent lines were themselves matches. | Fixed. Context is built from every reported line by number; `before` and `after` entries are now `{line, text}`. |
| One cross-repo `grep` could fail `busy` on an idle server when it asked for more worker slots than exist. | Fixed. Repos are searched through a bounded stream; a repo that gets no slot is reported under `repos_skipped` and the call fails `busy` only when none ran. |
| Configuration type errors (bad duration, CIDR, port) were reported one at a time, against the spec's "every problem at once". | Fixed. After a typed parse failure a recovery pass checks every section and entry separately and reports each with its line. Semantic validation still waits for the types to be right. |
| `state.json` stored the found secret values in plain text on the data volume. | Fixed. It stores rule ids and fingerprints only. On restore the matcher is rebuilt by rescanning commit messages (and history when enabled); the files are already redacted at rest. |
| The documented `trusted_proxies` default covered the whole compose subnet, whose gateway address is how host-local clients appear, so they could set `X-Forwarded-For`. | Fixed. The default is now empty, Caddy has a fixed address (`CADDY_IP`) and the example trusts only that `/32`. |
| Making `keys.toml` writable by the server's uid so `keygen` could run in the container would let a compromised server mint itself a key. | Fixed. `keys.toml` is mounted read-only, the server never writes it, and `keygen --print-only >> keys.toml` on the host is the documented flow. |

### Low

| Finding | Outcome |
|---|---|
| If the inotify watcher failed to start, the whole key reload task exited, taking the SIGHUP and poll paths with it. | Fixed. The sender stays alive; the other triggers keep running. |
| The auth hook computed the blocked-IP gauge by scanning the throttle table under its lock on every failure. | Fixed. The gauge is refreshed on scrape only. |
| User deny patterns without a slash matched only at the repo root, unlike gitignore. | Fixed. Slash-less deny and allow patterns expand to `**/pattern` plus the root form. |
| The built-in deny list lacked `id_ecdsa`, `id_dsa`, `*.p8`, `.htpasswd`, `.git-credentials`, `.docker/config.json`, `kubeconfig*`, `*.kdbx`, `*.gpg`, `service-account*.json`. | Fixed. Added. |
| Files re-allowed with `deny.allow` were invisible to `grep` because every deny glob went to ripgrep as an exclusion. | Fixed. With a non-empty allow list the exclusions are left to the post-filter. |
| `read_file` at a commit buffered the blob before checking its size, and an oversized blob surfaced as `internal`. | Fixed. Size is checked with `cat-file -s` first; oversize maps to `file_too_large`. |
| `blame` ran on the rewritten worktree, so redacted lines showed as uncommitted. | Fixed. `blame` runs against the snapshot commit and redacts per line. |
| Dropping a request future (HTTP timeout, client disconnect) killed only the child process, not its process group. | Fixed. A drop guard kills the process group. |
| `grep` buffered up to 64 MiB of ripgrep output per repo before truncating. | Fixed. 16 MiB cap per search with an `output_truncated` notice, and only `max_results` matches are kept while all are counted. |
| `secrets_redacted` in `list_repos` reported the finding count under every policy, including `warn` where nothing is masked. | Fixed. `secrets_redacted` counts under `redact` only; `secret_findings` carries the raw count. |
| The envelope's `pulled_at` was the snapshot build time, not the last successful pull. | Fixed. |
| Three advertised metrics (queue rejections, last success, pull failures) were never updated. | Fixed. Wired in the puller and the worker pool. |
| Error results omitted fields the output schemas marked as required. | Fixed. Output schemas no longer mark top-level fields as required. |
| Git error classification matched bare `401`, `403`, `404` substrings, so ports and hashes could be classified as auth errors. | Fixed. Phrase matching. |
| The onboarding `scan` command duplicated the puller's scan preparation and could drift from it. | Fixed. Both call the same preparation and scan functions. |
| Held pulls rebuilt the worktree and rescanned on every tick. | Fixed. The held tip is remembered and skipped until the branch moves. |
| Supply chain: builder image not pinned by digest, no dependency audit or license check. | Fixed. Builder image pinned by digest; `scripts/check.sh` runs `cargo audit` and `cargo deny`. |
| Backoff after a pull failure retries sooner than the regular interval (30 s doubling, capped at the interval). | Kept. This is what the spec asks for ("retry with backoff capped at the interval"); held tips no longer rebuild, which removes the costly case. |
| `admin_listen` defaults to all interfaces. | Kept for container use, where the port is simply not published. `check-config` now warns whenever the admin listener is not loopback. |
| A trusted proxy that sends no client address makes every client share one throttle bucket. | Mitigated. Rate-limited warning in the logs and a configuration warning when the header is unset while proxies are trusted. |
| A test fixture in the stderr scrubbing test looked like an API token to the leak scanner. | Fixed. Fixture changed; the historical fingerprint is listed in `.gitleaksignore`. |

### Verified correct by the reviewers

Path normalization and traversal defenses (`..`, leading `/`, `.git`, backslash, NUL, percent-encoded forms, index check before disk, resolution beneath the root), symlink handling with `core.symlinks=false`, pathspec and option-injection guards on every git and ripgrep argument, repo enumeration (same error for unknown and disallowed ids, per-key tool enums), key verification order and cache invalidation, 401 without detail, `X-Forwarded-For` walk, IPv6 grouping and the bounded throttle table, Origin check before auth, credential handling (askpass file, 0600 materialization, `GIT_SSH_COMMAND` quoting, pinned `known_hosts`, scrubbed stderr, `credential.helper` cleared), subprocess hardening (cleared environment, hooks disabled, protocols limited, LFS off, process group kill, output caps, no zombies), chunked oversize bodies rejected, structured logs with hashed patterns, container settings (non-root, read-only root, capabilities dropped, admin port unpublished), snapshot swap safety and restore validation.
