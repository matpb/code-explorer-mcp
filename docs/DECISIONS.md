# Decisions

Answers to the spec's open questions, plus implementation choices made while building. Each entry says what was chosen and why. Entries are append-only.

## From the spec's open questions

1. **Name and license.** Crate `code-explorer-mcp` (the name `code-explorer` is taken on crates.io), binary `code-explorer`, GitHub repo `code-explorer-mcp`. License MIT.
2. **Worker cap vs per-key throttling.** v1 has a global concurrency cap only, as the spec recommends. No per-key limit, not even optional. Authenticated traffic is never rate limited.
3. **Key hashing.** argon2id kept (m=19456 KiB, t=2, p=1), with the 10 minute verified-key cache so the cost is paid once per key per window.
4. **History depth.** Default 200 commits.
5. **Author emails.** Off by default (`logging.author_emails = false`).
6. **Staleness.** A stale snapshot is a notice on results, never a refusal. No hard cutoff.
7. **Repo ids as an enum per key.** Kept. `tools/list` injects the caller's allowed repo ids as an enum on every `repo` and `repos` parameter.
8. **Legacy protocol window.** Clients on 2025-11-25 and earlier are served without sessions through rmcp's compatibility mode. No drop date in v1.
9. **Templates such as `.env.example`.** Denied by default. Operators carve exceptions with `[deny] allow`.
10. **Image distribution and signing.** v1 ships the Dockerfile and compose files. CI builds the image to prove it builds but does not push. Registry publishing, signing and SBOM are later work.
11. **Bitbucket plan check.** Operator responsibility, documented in the README: repository access tokens may be unavailable on some plans, in which case SSH access keys are the fallback.

## Implementation choices

- **MCP SDK.** rmcp 3.5 with `transport-streamable-http-server`, mounted in axum as a Tower service. Stateless (`NeverSessionManager`), `legacy_session_mode = false`, `json_response = true`. rmcp's own Host and Origin checks are disabled; the server enforces Origin itself so the rule lives in one place and applies before auth.
- **Authentication context.** The axum auth middleware inserts an `AuthContext` into the HTTP request extensions. rmcp copies `http::request::Parts` into the MCP request extensions, so every tool reads the key name and allow-list from `ctx.extensions`. A tool call without an `AuthContext` fails closed with an internal error.
- **Per-key tool list.** `ServerHandler::list_tools` is written by hand: it takes the router's tool list and rewrites the `repo` and `repos` schemas with the caller's repo ids as an enum.
- **Config error reporting.** Syntax and unknown-field errors come from `toml` with their span. Semantic problems are collected into a list and each is given a line number by looking the key path up in a `toml_edit` document parsed from the same text.
- **Credentials and git.** HTTPS tokens reach git through `GIT_ASKPASS` pointing at the server binary itself (`code-explorer askpass`, a hidden subcommand). The helper reads the secret from a file named in `CODE_EXPLORER_ASKPASS_FILE`. Credentials given by env var are written once at start to a 0600 file in a private temp dir so the same path is used. SSH keys use `GIT_SSH_COMMAND` with `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`, `BatchMode=yes` and a pinned `known_hosts` file.
- **Subprocess safety.** Every `git`, `rg` and `gitleaks` child runs with a cleared environment, in its own process group, under a timeout; on expiry the whole group is killed. A global semaphore caps concurrent children.
- **Snapshot cleanup.** A `Snapshot` removes its worktree directory when the last reference to it is dropped, so in-flight calls always finish on the snapshot they started with.
- **Scanner.** gitleaks `dir` mode over the new worktree plus a file holding the commit messages of the kept history. Secret values live only in memory, inside the redactor.
- **Durations.** `humantime` syntax in TOML (`"5m"`, `"30s"`, `"2h"`).
- **Metrics.** The `prometheus` crate with a dedicated registry served as text on the admin listener.
- **Scanner hardening.** gitleaks honours `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments found in the scanned tree, which would let a repo hide its own findings. The adapter always passes its own default ruleset with `--config`, an empty `--gitleaks-ignore-path` and `--ignore-gitleaks-allow`.
- **Scan runs.** gitleaks does not follow a symlinked directory, so the worktree and the commit-message file are scanned in two parallel runs and the findings merged. Commit-message fingerprints are `commit_messages:<rule>:<line>`.
- **Remote URL refresh.** The bare repo keeps the clone-time origin URL, so the puller runs `git remote set-url origin` before every fetch and a config change to path, host or credential type takes effect at the next tick.
- **Clone staging.** A clone lands in `git.clone/` and is renamed to `git/` on success, so a crash mid-clone leaves nothing a later fetch would trip on.
- **state.json trust.** On restore, a worktree path outside `snapshots/` or containing `..` is rejected. Stored findings go through the allowlist again, and a repo under the block policy is rescanned.
- **SSH first.** The owner's repos are reached over git SSH only. SSH deploy keys (GitHub) and repository access keys (Bitbucket) are the documented default in the example config, the compose secrets and the onboarding steps. HTTPS tokens stay supported as the second option because the project is generic.
- **Public repos.** A repo entry may omit `credential` for anonymous HTTPS access to a public repo. SSH always needs a key.
- **Keys file polling.** inotify on the parent directory does not see writes to a Docker bind-mounted file, and a watch on the file itself survives neither an atomic replace nor a mount of a new inode. The key store therefore also polls the file's mtime and length every 2 seconds. Found when `keygen` from a second container did not trigger a reload in the serving container.
- **Compose subnet.** The compose network subnet is `EDGE_SUBNET` in `.env` (default `172.30.0.0/24`) and must match `server.trusted_proxies`. Found when the default overlapped an existing network on the build machine.
- **keys.toml is read-only to the server.** The lead's review of milestone 3 rejected making the bind-mounted keys file writable by the server's uid: a compromised server could then mint itself a key that survives restarts. The compose file mounts it `:ro`, the server never writes it (only `keygen` does, as an operator command), and `keygen --print-only` writes the `[[key]]` entry to stdout and the key to stderr so `>> keys.toml` on the host is the documented flow.
