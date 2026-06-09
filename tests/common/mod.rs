//! Shared helpers for the e2e CLI tests (standard Cargo `tests/common/mod.rs`
//! pattern — included via `mod common;` from each integration-test crate, so
//! items unused by one consumer are `#[allow(dead_code)]`).

use std::process::Command;
use tempfile::TempDir;

/// A `corgea` invocation isolated from the host environment: temp
/// HOME/USERPROFILE, no Corgea config/registry env vars, and no
/// agent-detection env vars leaking in.
#[allow(dead_code)]
pub fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("CORGEA_TOKEN")
        .env_remove("CORGEA_URL")
        .env_remove("CORGEA_NPM_REGISTRY")
        .env_remove("CORGEA_PYPI_REGISTRY")
        .env_remove("AI_AGENT")
        .env_remove("CODEX_SANDBOX")
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("CURSOR_TRACE_ID")
        .env_remove("GEMINI_CLI")
        .env_remove("PI_AGENT");
    (cmd, home)
}

#[allow(dead_code)]
pub fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}
