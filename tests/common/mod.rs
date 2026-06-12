//! Shared helpers for the e2e CLI tests (standard Cargo `tests/common/mod.rs`
//! pattern — included via `mod common;` from each integration-test crate, so
//! items unused by one consumer are `#[allow(dead_code)]`).

use corgea::vuln_api_stub::PackageKey;
use std::collections::HashMap;
use std::io::Read;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// A `corgea` invocation isolated from the host environment: temp
/// HOME/USERPROFILE, no Corgea config/registry env vars, and no
/// agent-detection env vars leaking in.
#[allow(dead_code)]
pub fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let vuln_stub = corgea::vuln_api_stub::spawn_with_statuses(HashMap::new(), HashMap::new());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("CORGEA_TOKEN")
        .env_remove("CORGEA_URL")
        .env_remove("CORGEA_NPM_REGISTRY")
        .env_remove("CORGEA_PYPI_REGISTRY")
        .env_remove("CORGEA_VULN_API_URL")
        .env_remove("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL")
        .env_remove("CORGEA_OSV_API_URL")
        .env("CORGEA_VULN_API_URL", vuln_stub.base_url)
        .env("CORGEA_OSV_API_URL", spawn_osv_stub(HashMap::new(), 200))
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

#[allow(dead_code)]
pub fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

/// Single-match vulnerable verdict body for the vuln-api stub; `fixed: None`
/// renders `"fixed_version":null`.
#[allow(dead_code)]
pub fn vulnerable_body(
    ecosystem: &str,
    name: &str,
    version: &str,
    advisory: &str,
    fixed: Option<&str>,
) -> String {
    let fixed = fixed.map_or("null".to_string(), |f| format!(r#""{f}""#));
    format!(
        r#"{{"ecosystem":"{ecosystem}","package_name":"{name}","version":"{version}","is_vulnerable":true,
        "matches":[{{"advisory_id":"{advisory}","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":{fixed}}}]}}"#
    )
}

/// Pip `--report -` payload: `oldpkg` (named/requested) + `evildep`
/// (transitive).
#[allow(dead_code)]
pub const TREE_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"oldpkg","version":"1.0.0"},"requested":true},
  {"metadata":{"name":"evildep","version":"0.4.2"},"requested":false}]}"#;

/// npm lockfile-v3 fixture: named `oldpkg` 1.0.0 + transitive `evildep` 0.4.2.
#[allow(dead_code)]
pub const NPM_LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
  "":{"name":"proj","version":"1.0.0"},
  "node_modules/oldpkg":{"version":"1.0.0"},
  "node_modules/evildep":{"version":"0.4.2"}}}"#;

/// `uv pip compile` stdout: `oldpkg` + transitive `evildep`, same shape as
/// `TREE_REPORT` / `NPM_LOCK`.
#[allow(dead_code)]
pub const UV_COMPILED: &str = "oldpkg==1.0.0\nevildep==0.4.2\n";

/// Spawn a one-response-per-connection HTTP stub on an ephemeral 127.0.0.1
/// port; `route` maps a request path to `(status line, body)`. Returns the
/// base URL. `Connection: close` is load-bearing — without it reqwest pools
/// the socket and a second request races the close and fails.
#[allow(dead_code)]
pub fn spawn_http_stub<F>(route: F) -> String
where
    F: Fn(&str) -> (&'static str, String) + Send + 'static,
{
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let buf = corgea::vuln_api_stub::read_http_request(&mut stream);
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

/// OSV querybatch stub. Unknown packages are clean; packages in `vulns` return
/// the provided OSV vulnerability object JSON inside `vulns[]`.
#[allow(dead_code)]
pub fn spawn_osv_stub(vulns: HashMap<PackageKey, String>, status_code: u16) -> String {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let request = read_http_request_with_body(&mut stream);
            let req = String::from_utf8_lossy(&request);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let response_body = if path == "/v1/querybatch" && status_code < 400 {
                osv_response_body(body, &vulns)
            } else if status_code < 400 {
                NOT_FOUND_JSON.to_string()
            } else {
                r#"{"error":"osv unavailable"}"#.to_string()
            };
            let effective_status = if path == "/v1/querybatch" {
                status_code
            } else {
                404
            };
            let reason = match effective_status {
                200 => "OK",
                404 => "Not Found",
                500..=599 => "Internal Server Error",
                _ => "Error",
            };
            let response = format!(
                "HTTP/1.1 {effective_status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    base_url
}

fn read_http_request_with_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    while header_end.is_none() {
        let Ok(n) = stream.read(&mut chunk) else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    }
    let Some(header_end) = header_end else {
        return buf;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let current_body_len = buf.len().saturating_sub(header_end);
    let remaining = content_length.saturating_sub(current_body_len);
    if remaining > 0 {
        let mut rest = vec![0u8; remaining];
        let _ = stream.read_exact(&mut rest);
        buf.extend_from_slice(&rest);
    }
    buf
}

fn osv_response_body(request_body: &str, vulns: &HashMap<PackageKey, String>) -> String {
    let parsed: serde_json::Value =
        serde_json::from_str(request_body).unwrap_or_else(|_| serde_json::json!({}));
    let results = parsed
        .get("queries")
        .and_then(|v| v.as_array())
        .map(|queries| {
            queries
                .iter()
                .map(|query| {
                    let ecosystem = query
                        .get("package")
                        .and_then(|p| p.get("ecosystem"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let name = query
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let version = query.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    let key = (ecosystem.to_string(), name.to_string(), version.to_string());
                    let lower_key = (
                        ecosystem.to_ascii_lowercase(),
                        name.to_string(),
                        version.to_string(),
                    );
                    vulns
                        .get(&key)
                        .or_else(|| vulns.get(&lower_key))
                        .map(|body| serde_json::json!({ "vulns": [serde_json::from_str::<serde_json::Value>(body).unwrap()] }))
                        .unwrap_or_else(|| serde_json::json!({ "vulns": [] }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::json!({ "results": results }).to_string()
}

/// Registry stub serving `/pypi/oldpkg/json` (pypi) and `/oldpkg` (npm
/// packument), both published 2020 → never recent. Everything else 404s.
#[allow(dead_code)]
pub fn spawn_oldpkg_registry_stub() -> String {
    spawn_http_stub(|path| match path {
        "/pypi/oldpkg/json" => ("200 OK", OLDPKG_PYPI_JSON.to_string()),
        "/oldpkg" => ("200 OK", OLDPKG_NPM_PACKUMENT.to_string()),
        _ => ("404 Not Found", NOT_FOUND_JSON.to_string()),
    })
}

/// Registry stub serving `/pypi/<name>/json` for any single-segment name,
/// always version 1.0.0 published 2020 → never recent. Everything else 404s.
#[allow(dead_code)]
pub fn spawn_wildcard_pypi_stub() -> String {
    spawn_http_stub(|path| {
        let name = path
            .strip_prefix("/pypi/")
            .and_then(|p| p.strip_suffix("/json"))
            .filter(|n| !n.is_empty() && !n.contains('/'));
        match name {
            Some(name) => (
                "200 OK",
                format!(
                    r#"{{"info":{{"name":"{name}"}},"releases":{{"1.0.0":[{{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}}]}}}}"#
                ),
            ),
            None => ("404 Not Found", NOT_FOUND_JSON.to_string()),
        }
    })
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
/// pip's `--dry-run --report -` and uv's `pip compile`,
/// `./package-lock.json` for npm's `--package-lock-only`, whose cwd is the
/// resolver's throwaway temp dir) and exits 0 — the tree pass; if `payload`
/// is `RESOLUTION_FAILS` it exits non-zero instead, emitting nothing. Any
/// other invocation records its argv to `marker` and exits `exit_code`.
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
        "pip" | "pip3" => ("--dry-run", "", 2),
        "npm" => ("--package-lock-only", " > package-lock.json", 1),
        "uv" => ("compile", "", 1),
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

/// `corgea` wired to the wildcard pypi registry stub, a report-less fake pip
/// (recording its argv to a marker), and a vuln-api stub.
#[cfg(unix)]
#[allow(dead_code)]
pub struct PipHarness {
    pub cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

#[cfg(unix)]
#[allow(dead_code)]
impl PipHarness {
    /// `token: None` exercises public mode (no CORGEA_TOKEN set).
    pub fn new(
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        token: Option<&str>,
        pip_exit_code: i32,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_pip_without_report(bin.path(), &marker, pip_exit_code);
        let registry = spawn_wildcard_pypi_stub();
        let vuln_stub = corgea::vuln_api_stub::spawn_with_statuses(checks, statuses);
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
        if let Some(t) = token {
            cmd.env("CORGEA_TOKEN", t);
        }
        Self {
            cmd,
            marker,
            _home: home,
            _bin: bin,
        }
    }

    pub fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

/// `corgea` wired to the oldpkg registry stub, a tree-aware fake `binary`
/// (`"pip"` or `"npm"`) answering the tree pass with `payload`, a vuln-api
/// stub, and a token.
#[cfg(unix)]
#[allow(dead_code)]
pub struct TreeHarness {
    pub cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

#[cfg(unix)]
#[allow(dead_code)]
impl TreeHarness {
    pub fn new(
        binary: &str,
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        payload: &str,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_tree_pm(bin.path(), binary, &marker, payload, 0);
        let registry = spawn_oldpkg_registry_stub();
        let vuln_stub = corgea::vuln_api_stub::spawn_with_statuses(checks, statuses);
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_NPM_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1")
            .env("CORGEA_TOKEN", "test-token");
        Self {
            cmd,
            marker,
            _home: home,
            _bin: bin,
        }
    }

    pub fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}
