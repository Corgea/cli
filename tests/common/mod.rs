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
        .env_remove("CORGEA_VULN_API_URL")
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

/// Canned 404 body for stub route tables.
#[allow(dead_code)]
pub const NOT_FOUND_JSON: &str = r#"{"message":"not found"}"#;

/// PyPI release JSON for `oldpkg` 1.0.0, published 2020 → never recent.
#[allow(dead_code)]
pub const OLDPKG_PYPI_JSON: &str = r#"{"info":{"name":"oldpkg"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]}}"#;

/// npm packument for `oldpkg` 1.0.0, published 2020 → never recent.
#[allow(dead_code)]
pub const OLDPKG_NPM_PACKUMENT: &str = r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}"#;

/// Spawn a one-response-per-connection HTTP stub on an ephemeral 127.0.0.1
/// port; `route` maps a request path to `(status line, body)`. Returns the
/// base URL. `Connection: close` is load-bearing — without it reqwest pools
/// the socket and a second request races the close and fails.
#[allow(dead_code)]
pub fn spawn_http_stub<F>(route: F) -> String
where
    F: Fn(&str) -> (&'static str, String) + Send + 'static,
{
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 1024];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let (status, body) = route(path);
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    base_url
}

/// Write `script` as the executable `dir/binary`.
#[cfg(unix)]
#[allow(dead_code)]
pub fn write_script(dir: &std::path::Path, binary: &str, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake script");
}

/// Shell loop that emits the file at `path` line by line via builtins —
/// works under the locked-down test PATH (no `cat`); the `|| [ -n "$line" ]`
/// guard keeps a final line with no trailing newline.
#[cfg(unix)]
#[allow(dead_code)]
pub fn emit(path: &std::path::Path) -> String {
    format!(
        "while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{}'",
        path.display()
    )
}

/// Write an executable fake package manager named `binary` into `dir`. It
/// records its argv to `marker` and exits `exit_code` — proving both "the
/// install ran (with these args)" and exit-code forwarding.
#[cfg(unix)]
#[allow(dead_code)]
pub fn write_fake_recorder(
    dir: &std::path::Path,
    binary: &str,
    marker: &std::path::Path,
    exit_code: i32,
) {
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$*\" > '{}'\nexit {}\n",
        marker.display(),
        exit_code
    );
    write_script(dir, binary, &script);
}

/// Write an executable fake `pip` that simulates an old pip with no
/// `--report`: the tree dry-run exits 2 *without* touching the marker, so
/// tests exercise the named-only fallback path. Any other invocation
/// records its argv to `marker` and exits `exit_code`.
#[cfg(unix)]
#[allow(dead_code)]
pub fn write_fake_pip_without_report(
    dir: &std::path::Path,
    marker: &std::path::Path,
    exit_code: i32,
) {
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) exit 2;; esac\nprintf '%s' \"$*\" > '{}'\nexit {}\n",
        marker.display(),
        exit_code
    );
    write_script(dir, "pip", &script);
}

/// Sentinel payload that makes a tree-aware fake manager exit non-zero on
/// its tree (resolution) invocation, forcing the named-only fallback.
#[allow(dead_code)]
pub const RESOLUTION_FAILS: &str = "RESOLUTION_FAILS";

/// Write an executable tree-aware fake package manager into `dir`. An
/// invocation carrying the manager's tree flag emits `payload` (stdout for
/// pip's `--dry-run --report -`, `./package-lock.json` for npm's
/// `--package-lock-only`, whose cwd is the resolver's throwaway temp dir)
/// and exits 0 — the tree pass; if `payload` is `RESOLUTION_FAILS` it exits
/// non-zero instead, emitting nothing. Any other invocation records its
/// argv to `marker` and exits `exit_code`.
#[cfg(unix)]
#[allow(dead_code)]
pub fn write_fake_tree_pm(
    dir: &std::path::Path,
    binary: &str,
    marker: &std::path::Path,
    payload: &str,
    exit_code: i32,
) {
    let (tree_flag, redirect, fail_exit) = match binary {
        "pip" => ("--dry-run", "", 2),
        "npm" => ("--package-lock-only", " > package-lock.json", 1),
        other => panic!("unsupported fake manager {other}"),
    };
    let tree_branch = if payload == RESOLUTION_FAILS {
        format!("exit {fail_exit}")
    } else {
        let payload_path = dir.join(format!("{binary}-tree-payload.json"));
        std::fs::write(&payload_path, payload).expect("write fake pm payload");
        format!("{}{redirect}; exit 0", emit(&payload_path))
    };
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" {tree_flag} \"*) {tree_branch};; esac\nprintf '%s' \"$*\" > '{marker}'\nexit {exit_code}\n",
        marker = marker.display(),
    );
    write_script(dir, binary, &script);
}
