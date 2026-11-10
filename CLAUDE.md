# Code Explorer MCP: read-only MCP server that lets AI agents explore GitHub and Bitbucket repos from local shallow clones

This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

<!-- Keep under 120 lines. Every line must name a specific failure it prevents. -->

## Ground rules
- Read-only is the product. No tool, flag or config may write to a repo, run its code, or follow a remote the operator did not configure.
- Every subprocess goes through `proc::scrubbed_command` and `proc::run`: they clear the environment, kill the whole process group on timeout, and cap stdout. A bare `std::process::Command` leaks credentials from env and orphans `rg` and `git` helpers when a request is cancelled.
- Anything that can reach a log, an error or a tool result passes through redaction first: tool output through the snapshot's redactor, git stderr through `git::scrub_stderr`. The presented API key is never logged, not even hashed.
- No real credentials, hostnames, addresses or personal data anywhere in the tree, tests or docs: examples use `example.com` and documentation IP ranges, secrets come from `secret_file` or an env var named in the config.
- `scripts/check.sh` is the only proof of a green build. There is no CI, and `Cargo.toml` excludes `.github` on purpose.

## Commands
- Build and run: `cargo run -q -- --version`; the server is `code-explorer --config ./config.toml serve` and needs `git`, `rg` and `gitleaks` on `PATH`.
- Full suite: `cargo test --all-targets`. One integration test: `cargo test --test mcp permalink` (substring match on the test name).
- MCP suite on a heavily loaded host: `cargo test --test mcp -- --test-threads=1`. In parallel, tests spawn servers that clone fixtures and can miss the 30 s readiness window. The test client already retries the server's 503 busy answer on initialize, so a 503 in a failure means a real regression.
- Format and lint: `cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings`.
- Everything, as a release gate: `scripts/check.sh` (fmt, clippy, tests, `cargo audit`, `cargo deny`, gitleaks over the tree and the full history). It installs `cargo-audit` and `cargo-deny` if missing.
- Docker and both compose profiles: README, "Quick start" and "Deployment". Not covered by the test suite.

## Layout worth knowing
- `src/tools/mod.rs` holds the `ServerHandler` impl, tool registration and the dispatch match; one file per tool next to it. `src/http` is only the axum plumbing around rmcp (body limit, Origin check, auth middleware, `/readyz`).
- Config parsing is `src/config/mod.rs`, every semantic check is `src/config/validate.rs`, and binary presence checks are separate so parsing tests run without `git` installed.
- Key hashing, `keygen` and the hot-reloading `KeyStore` all live in `src/keys.rs`. The secret scanner and the gitleaks adapter live in `src/scan.rs`, with the gitleaks rules embedded from `src/gitleaks.toml`.
- Snapshot state on disk (`state.json`) stores rule ids and fingerprints only; the redactor is rebuilt from a scan on restore, never from persisted secrets.
- Integration tests build real local Git repos as fixtures (`tests/common/mod.rs`) and run the built `code-explorer` binary with `CODE_EXPLORER_ALLOW_LOCAL_REMOTES=1`. That env var is the only way `file://` remotes are accepted; production refuses them.

## Conventions
- Every config and keys struct is `#[serde(deny_unknown_fields)]`. A new config key is not done until `validate.rs`, `config.example.toml` and the README config reference all know it.
- Errors are typed enums (`thiserror`) per module and surface to clients as the spec's error codes; a tool call without an `AuthContext` fails closed with `internal`.
- `unsafe_code` is denied and `clippy::unwrap_used` warns: use `expect` with a reason, or propagate.
- Logs are JSON on stderr, one line per tool call, via `tracing`. The filter comes from `RUST_LOG`; the format from `logging.format` or `--log-format`.
- Test fixtures must not look like tokens. gitleaks runs over the full history, so a token-shaped string in a test is a permanent finding; the one historical fingerprint allowed is in `.gitleaksignore`.
- Docs, code and commit messages use no em or en dashes and never carry development time estimates.

## Landmines
- Do not set `server.trusted_proxies` to the Docker subnet: it must be the proxy's own address as a `/32`. A subnet lets any container on the network spoof `X-Forwarded-For` and bypass the failed-auth throttle.
- Do not make the server write `keys.toml`: it is mounted read-only on purpose. Minting a key is `keygen --print-only >> keys.toml` on the host; the watcher picks the edit up.
- Do not redact multi-line secrets as one block: PEM keys must also be registered line by line (`redact::secret_lines`), or per-line outputs such as grep matches and blame leak them.
- Do not pass deny-list globs to ripgrep as `--glob`: they are `--iglob` because the deny list is case-insensitive, and a case-variant file name would otherwise leak through grep counts.
- Do not strip the stale lock cleanup from the puller: a git killed on timeout leaves `index.lock` behind and every later pull of that repo fails forever.
- Bitbucket SSH remotes use `ssh.bitbucket.org` while HTTPS stays on `bitbucket.org`; the image ships both host keys plus GitHub's. Changing a remote host means changing `deploy/known_hosts` too.
- The admin port (`/readyz`, `/metrics`) is never published or proxied. Do not add it to the Caddyfile or bind it outside the compose network.

## Deeper context
- Module contract and request path -> `docs/ARCHITECTURE.md`
- Design choices and their reasons -> `docs/DECISIONS.md`
- Review findings and what was done about them -> `docs/REVIEW.md`
- Operator docs: config reference, onboarding, rotation, troubleshooting -> `README.md`
- Vulnerability reporting -> `SECURITY.md`
