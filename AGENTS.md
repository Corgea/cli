# AGENTS.md

## Cursor Cloud specific instructions

### Overview
Corgea CLI is a Rust-based command-line security scanning tool. It communicates with the Corgea SaaS platform (`https://www.corgea.app`) via REST API. There are no local databases or services to run — the CLI is a stateless client.

### Development commands
- **Build**: `cargo build`
- **Test**: `cargo test` (7 unit tests in `src/authorize.rs`)
- **Lint**: `cargo clippy` (warnings only, no errors expected)
- **Dev install** (Python wrapper): `source .venv/bin/activate && maturin develop` — builds the Rust binary and installs it as a Python package, making `corgea` available on PATH within the venv
- **Run directly**: `./target/debug/corgea` after `cargo build`

### Key caveats
- The Rust toolchain must be **stable latest** (>=1.85). The default VM ships with 1.83 which is too old for the `time-core` crate's `edition2024` feature. The update script handles `rustup default stable`.
- `python3.12-venv` system package is required for creating the `.venv` used by maturin.
- The CLI requires a `CORGEA_TOKEN` (or `corgea login <token>`) to interact with the Corgea API. Without it, commands like `corgea scan`, `corgea list`, etc. return 401. This is expected behavior — the CLI itself is still fully functional.
- Config is stored at `~/.corgea/config.toml`.
- Set `CORGEA_DEBUG=1` for verbose debug logging.
