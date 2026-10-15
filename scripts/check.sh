#!/usr/bin/env bash
# Full local proof: format, lint, tests, dependency audit, license check, leak scan.
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }
for t in cargo git rg gitleaks; do need "$t"; done
for t in cargo-audit cargo-deny; do
  command -v "$t" >/dev/null 2>&1 || cargo install "$t" --locked
done

echo "== cargo fmt";    cargo fmt --all -- --check
echo "== cargo clippy"; cargo clippy --all-targets -- -D warnings
echo "== cargo test";   cargo test --all-targets
echo "== cargo audit";  cargo audit
echo "== cargo deny";   cargo deny check advisories licenses
echo "== gitleaks tree (tracked files only)"
tree_dir="$(mktemp -d)"; trap 'rm -rf "$tree_dir"' EXIT
git archive HEAD | tar -x -C "$tree_dir"
git ls-files -m -o --exclude-standard -z | tar --null -T - -c 2>/dev/null | tar -x -C "$tree_dir" || true
gitleaks dir "$tree_dir" --no-banner --redact
echo "== gitleaks history"; gitleaks git . --no-banner --redact
echo "all checks passed"
