# Corgea CLI

AI-powered security scanner CLI written in Rust. Communicates with the Corgea cloud platform (`https://www.corgea.app`) via REST API.

## Cursor Cloud specific instructions

### Project overview

Single-binary Rust CLI (no monorepo). No local backend services, databases, or Docker required. All scanning/analysis happens server-side via the Corgea SaaS API.

### Build, test, lint

- **Build:** `cargo build`
- **Test:** `cargo test` (7 unit tests, primarily in `src/authorize.rs`)
- **Lint:** `cargo clippy` (warnings only, no errors — existing warnings are pre-existing in the codebase)
- **Format check:** `cargo fmt --check` (existing formatting differences are pre-existing)
- **Run the binary:** `./target/debug/corgea --help`

### Key gotchas

- The pre-installed Rust toolchain (1.83.0) is too old; the `time` crate requires `edition2024`. The update script sets `rustup default stable` to use the latest stable (1.94.0+).
- `libssl-dev` and `pkg-config` are required system packages on Linux for the `openssl` crate (used with `vendored` feature on non-Windows).
- Most CLI commands (`scan`, `list`, `inspect`, `wait`) require authentication via `CORGEA_TOKEN` env var or `corgea login <token>`. Without a valid token, commands exit with "No token set" or "Invalid token provided" — this is expected behavior, not a build issue. The token is validated against `https://www.corgea.app/api/v1/verify`. Get a valid token from the Corgea web app dashboard.
- The `setup-hooks` command does **not** require authentication — useful for verifying the binary works end-to-end without a token.
- `config.rs` reads `CORGEA_TOKEN` and `CORGEA_URL` env vars at runtime, overriding the config file at `~/.corgea/config.toml`. Debug mode is enabled via `CORGEA_DEBUG=1`.
- The npm `package.json` at the repo root is for the npm distribution wrapper only (thin JS shim in `bin/corgea.js`). It is not needed for Rust development.
- Python/maturin setup (described in README) is only needed for the PyPI distribution path, not for core Rust development.
