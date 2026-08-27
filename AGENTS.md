# AGENTS.md

This subproject is the Corgea developer CLI (Rust → npm + pip via maturin).

## Commands

- After edits: `./harness check` — clippy fix, format, tests, suppression report
- Pre-commit: `./harness pre-commit` — staged Rust files only (auto via git hook)
- CI: `./harness ci` — strict clippy (`-D warnings`), format check, dep audit, tests + coverage gate (min 13%)
- Audit: `./harness audit` — `cargo audit` for known dep vulnerabilities
- Coverage: `./harness coverage [--min=N]` — cargo-llvm-cov; HTML report under `target/llvm-cov/`; fails if line coverage < N (default 13)
- Lint: `./harness lint` — clippy + format check, no fixes
- Test: `./harness test` — `cargo test`
- Fix: `./harness fix` — clippy fix + format
- Setup: `./harness setup-hooks` — install `.git/hooks/pre-commit`
- Auto-format: `./harness post-edit` — runs `cargo fmt` on changed Rust files (wire into your editor/agent's post-edit hook)

Add `--verbose` to stream raw command output instead of the quiet summary.

Coverage needs LLVM's `llvm-cov`/`llvm-profdata`. On a rustup toolchain, run
`rustup component add llvm-tools-preview`. On a non-rustup toolchain (e.g.
Homebrew Rust) those are missing, so point cargo-llvm-cov at a system LLVM:
`LLVM_COV="$(brew --prefix llvm)/bin/llvm-cov" LLVM_PROFDATA="$(brew --prefix llvm)/bin/llvm-profdata" ./harness coverage`.
CI uses its own toolchain and is unaffected.

## Vendored agent components

`.cursor/skills/` and `.cursor/agents/` are vendored from
[Corgea/agent-toolkit](https://github.com/Corgea/agent-toolkit) so Cursor Cloud Agents
working on this repository load them from the checkout. Do not hand-edit them; change
them upstream and re-run the installer from an `agent-toolkit` checkout:

```bash
python3 /path/to/agent-toolkit/scripts/install_project_skills.py --target "$(pwd)"
python3 /path/to/agent-toolkit/scripts/install_project_skills.py --target "$(pwd)" --check
```

`--check` exits non-zero when the vendored copy has drifted from upstream.
