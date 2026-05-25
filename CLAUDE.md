# CLAUDE

This subproject is the Corgea developer CLI (Rust → npm + pip via maturin).
The repo-root `/Users/juan/Code/corgea/CLAUDE.md` covers cross-codebase
conventions; this file covers cli-only commands.

## Commands

- After edits: `./harness check` — clippy fix, format, tests, suppression report
- Pre-commit: `./harness pre-commit` — staged Rust files only (auto via git hook)
- CI: `./harness ci` — strict clippy (`-D warnings`), format check, dep audit, tests
- Audit: `./harness audit` — `cargo audit` for known dep vulnerabilities
- Lint: `./harness lint` — clippy + format check, no fixes
- Test: `./harness test` — `cargo test`
- Fix: `./harness fix` — clippy fix + format
- Setup: `./harness setup-hooks` — install `.git/hooks/pre-commit`
- Auto-format: `./harness post-edit` runs via Claude Code Stop hook

Add `--verbose` to stream raw command output instead of the quiet summary.

## Layer 2 (behavior contract)

Not wired. Commits, pushes, and arch-config edits are NOT gated by hooks
in this subproject — follow the conventions in the repo-root CLAUDE.md.
