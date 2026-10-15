# Progress

Checklist for the v1 build. Kept current so a restart loses nothing. Spec: the owner's design spec (local, not in this repo). Decisions: `docs/DECISIONS.md`.

## Phase 0: scaffold
- [x] Repo created, `main` branch, Cargo.toml with pinned dependency majors
- [x] docs/DECISIONS.md with the open-question answers
- [x] docs/ARCHITECTURE.md (module contract for the build)
- [x] First commit

## Phase 1: core leaf modules (no HTTP)
- [x] `config`: structs, deny_unknown_fields, humantime durations, load, full validation with file and line, warnings
- [x] `keys`: keys.toml model, key format, argon2id verify, verify cache, hot reload (notify + SIGHUP), keygen
- [x] `paths`: normalization, deny-list (defaults, extra, allow), case-insensitive glob matching
- [x] `redact`: Aho-Corasick redactor
- [x] `proc`: scrubbed env, process group, timeout kill, worker semaphore, busy
- [x] `git`: clone/fetch/worktree/ls-tree/log/show/blame/rev-parse wrappers, askpass, ssh command, stderr scrubbing
- [x] Unit tests for each, `cargo clippy -D warnings` clean

## Phase 2: snapshots, scan, auth
- [x] `snapshot`: FileIndex from ls-tree, Snapshot, RepoState, Registry, state.json
- [x] `puller`: first start, tick loop, backoff, atomic swap, cleanup
- [x] `scan`: Scanner trait, gitleaks adapter, policies redact/warn/block, allowlist, on_scan_error hold
- [x] `auth`: client IP derivation, failed-auth throttle (LRU, backoff, 429), bearer verify, AuthContext
- [x] Unit tests

## Phase 3: tools, HTTP, metrics, logging, CLI
- [x] `tools`: list_repos, list_tree, glob, read_file, grep, log (+ blame, file at commit behind features), envelope, notices, typed errors, text rendering, output caps, permalinks
- [x] per-key `list_tools` with repo enums
- [x] `http`: public /mcp + /healthz with Origin check, body limit, timeouts; admin /readyz + /metrics
- [x] `metrics`, `logging` (JSON tool_call events, shape vs full)
- [x] CLI: serve, check-config [--probe], keygen, scan --repo, status, healthcheck, askpass (hidden)

## Phase 4: integration tests
- [x] Fixture builder: local bare repos with known content, a planted fake secret, a symlink, a binary, a large file, denied paths
- [x] Every tool and every error code in the spec exercised over real MCP (streamable HTTP client)
- [x] Auth: 401, throttle 429, allow-list, revocation via reload
- [x] Puller: new commit swaps, failed fetch keeps serving, stale notice
- [x] Scan policies: redact masks, block holds, warn serves

## Phase 5: packaging
- [x] Dockerfile (multi-stage, non-root, pinned gitleaks with checksum, healthcheck via binary)
- [x] deploy/compose.yaml with caddy profile, Caddyfile, .env.example
- [ ] Both profiles up locally and answered by a real MCP client script
- [x] known_hosts for github.com and bitbucket.org

## Phase 6: docs and CI
- [x] README, CHANGELOG, LICENSE, SECURITY.md, config.example.toml, keys.example.toml
- [x] scripts/check.sh replaces GitHub CI (owner preference): fmt, clippy, test, audit, deny, gitleaks

## Phase 7: reviews
- [x] Correctness review (fresh subagent, diff + spec)
- [x] Security review (fresh subagent, diff + spec)
- [x] /code-review
- [x] Fixes applied, proof re-run, docs/REVIEW.md written

## Phase 8: leak scan and publish
- [x] gitleaks over the tree and the full history
- [x] grep for personal data, hostnames, IPs, local paths, machine names, client names
- [x] `gh repo create matpb/code-explorer-mcp --public`, push, local check script green
- [x] Final report to the owner
