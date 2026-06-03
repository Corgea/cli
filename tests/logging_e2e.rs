//! End-to-end tests for the `eprintln!` -> `log` + `env_logger` migration.
//!
//! These exercise the only genuinely new behavior — the wiring at the process
//! boundary (default level, message-only format, `RUST_LOG`/`CORGEA_DEBUG`
//! filtering and precedence, exit code) — by running the real binary in a
//! separate process. The deterministic, no-network seam is the empty-token
//! guard in `verify_token_and_exit_when_fail`, which emits `error!("No token
//! set…")` and `exit(1)` before any HTTP call.
//!
//! In-process log capture is intentionally avoided: the global logger is
//! once-only and these run the real logger out-of-process instead.

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_corgea");

/// Run `corgea scan` with an isolated, empty `HOME` (no `config.toml`, so the
/// resolved token is empty) and a cleared environment so the developer's shell
/// can't make the token check pass or skew log levels. `HOME`/`PATH` are re-added
/// deliberately; `extra_env` layers on top.
fn run(extra_env: &[(&str, &str)]) -> Output {
    let home = tempfile::tempdir().unwrap(); // empty HOME -> no config.toml
    let mut cmd = Command::new(BIN);
    cmd.arg("scan") // a subcommand that reaches the token check before networking
        .env_clear() // drop developer CORGEA_TOKEN/RUST_LOG/CORGEA_DEBUG
        .env("HOME", home.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn corgea")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn default_emits_error_and_exits_one() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("No token set."), "stderr was: {err:?}");
    assert!(
        err.contains("https://docs.corgea.app/install_cli#login-with-the-cli"),
        "stderr was: {err:?}"
    );
}

#[test]
fn error_is_message_only_without_level_prefix() {
    let out = run(&[]);
    let err = stderr(&out);
    let first = err.lines().next().unwrap_or("");
    // The custom format writes `record.args()` only — no `[ERROR]`, level, or timestamp.
    assert_eq!(first, "No token set.", "stderr was: {err:?}");
    assert!(!err.contains("[ERROR]"), "stderr was: {err:?}");
    assert!(!err.contains("ERROR"), "stderr was: {err:?}");
}

#[test]
fn rust_log_off_silences_the_error() {
    let out = run(&[("RUST_LOG", "off")]);
    // Still exits 1 (control flow is independent of logging)...
    assert_eq!(out.status.code(), Some(1));
    // ...but the record is filtered out, proving the facade + filter routing.
    let err = stderr(&out);
    assert!(!err.contains("No token set."), "stderr was: {err:?}");
}

#[test]
fn rust_log_error_keeps_the_error() {
    let out = run(&[("RUST_LOG", "error")]);
    let err = stderr(&out);
    assert!(err.contains("No token set."), "stderr was: {err:?}");
}

#[test]
fn corgea_debug_keeps_the_error() {
    let out = run(&[("CORGEA_DEBUG", "1")]);
    let err = stderr(&out);
    assert!(err.contains("No token set."), "stderr was: {err:?}");
}

#[test]
fn rust_log_overrides_corgea_debug() {
    // RUST_LOG must win over the CORGEA_DEBUG-derived default filter.
    let out = run(&[("CORGEA_DEBUG", "1"), ("RUST_LOG", "off")]);
    let err = stderr(&out);
    assert!(!err.contains("No token set."), "stderr was: {err:?}");
}

#[test]
fn error_is_absent_from_stdout() {
    // Lock stream separation: diagnostics go to stderr, never stdout.
    let out = run(&[]);
    let so = stdout(&out);
    assert!(!so.contains("No token set."), "stdout was: {so:?}");
}
