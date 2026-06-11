//! Shared helpers for the e2e CLI tests (standard Cargo `tests/common/mod.rs`
//! pattern — included via `mod common;` from each integration-test crate, so
//! items unused by one consumer are `#[allow(dead_code)]`).

use corgea::vuln_api_stub::PackageKey;
#[cfg(unix)]
use std::collections::HashMap;
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("CORGEA_TOKEN")
        .env_remove("CORGEA_URL")
        .env_remove("CORGEA_NPM_REGISTRY")
        .env_remove("CORGEA_PYPI_REGISTRY")
        .env_remove("CORGEA_VULN_API_URL")
        .env_remove("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL")
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

/// One configurable harness behind every gate test: isolated `corgea`, a
/// private PATH of fake package managers, optional registry stubs, the
/// vuln-api stub, optional token, and an optional throwaway project cwd.
#[cfg(unix)]
#[allow(dead_code)]
pub struct GateHarness {
    pub cmd: Command,
    marker: PathBuf,
    project: Option<TempDir>,
    checks: HashMap<PackageKey, String>,
    statuses: HashMap<PackageKey, u16>,
    _home: TempDir,
    _bin: TempDir,
    _vuln_stub: Option<corgea::vuln_api_stub::VulnApiStub>,
}

#[cfg(unix)]
#[allow(dead_code)]
impl GateHarness {
    pub fn new() -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        cmd.env("PATH", bin.path());
        Self {
            cmd,
            marker,
            project: None,
            checks: HashMap::new(),
            statuses: HashMap::new(),
            _home: home,
            _bin: bin,
            _vuln_stub: None,
        }
    }

    /// Tree-aware fake manager: emits `payload` on its tree flag, records
    /// argv and exits `exit_code` otherwise.
    pub fn fake_tree_pm(self, binary: &str, payload: &str, exit_code: i32) -> Self {
        write_fake_tree_pm(self._bin.path(), binary, &self.marker, payload, exit_code);
        self
    }

    /// Plain argv recorder. Call repeatedly for multiple binaries; call
    /// never for an empty PATH.
    pub fn fake_recorder(self, binary: &str, exit_code: i32) -> Self {
        write_fake_recorder(self._bin.path(), binary, &self.marker, exit_code);
        self
    }

    /// Raw script escape hatch.
    pub fn script(self, binary: &str, script: &str) -> Self {
        write_script(self._bin.path(), binary, script);
        self
    }

    /// Raw script escape hatch for scripts that need the temp bin dir or
    /// marker path.
    pub fn script_with_paths<F>(self, binary: &str, make_script: F) -> Self
    where
        F: FnOnce(&std::path::Path, &std::path::Path) -> String,
    {
        let script = make_script(self._bin.path(), &self.marker);
        write_script(self._bin.path(), binary, &script);
        self
    }

    /// oldpkg stub on both registry env vars; only the exercised ecosystem
    /// dials it.
    pub fn oldpkg_registry(mut self) -> Self {
        let url = spawn_oldpkg_registry_stub();
        self.cmd
            .env("CORGEA_PYPI_REGISTRY", &url)
            .env("CORGEA_NPM_REGISTRY", &url);
        self
    }

    pub fn wildcard_pypi_registry(mut self) -> Self {
        let url = spawn_wildcard_pypi_stub();
        self.cmd.env("CORGEA_PYPI_REGISTRY", &url);
        self
    }

    pub fn registry_env(mut self, var: &str, url: &str) -> Self {
        self.cmd.env(var, url);
        self
    }

    pub fn vuln_checks(mut self, checks: HashMap<PackageKey, String>) -> Self {
        self.checks = checks;
        self
    }

    pub fn vuln_statuses(mut self, statuses: HashMap<PackageKey, u16>) -> Self {
        self.statuses = statuses;
        self
    }

    pub fn token(mut self, token: &str) -> Self {
        self.cmd.env("CORGEA_TOKEN", token);
        self
    }

    pub fn in_project_dir(mut self) -> Self {
        let project = TempDir::new().expect("project dir");
        self.cmd.current_dir(project.path());
        self.project = Some(project);
        self
    }

    pub fn with_project_file(mut self, name: &str, body: &str) -> Self {
        if self.project.is_none() {
            self = self.in_project_dir();
        }
        let dir = self.project.as_ref().unwrap().path();
        std::fs::write(dir.join(name), body).expect("write project file");
        self
    }

    pub fn build(mut self) -> Self {
        let stub = corgea::vuln_api_stub::spawn_with_statuses(
            std::mem::take(&mut self.checks),
            std::mem::take(&mut self.statuses),
        );
        self.cmd.env("CORGEA_VULN_API_URL", &stub.base_url);
        self._vuln_stub = Some(stub);
        self
    }

    pub fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

/// `corgea` wired to the wildcard pypi registry stub, a report-less fake pip
/// (recording its argv to a marker), and a vuln-api stub.
#[cfg(unix)]
#[allow(dead_code)]
pub struct PipHarness(GateHarness);

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
        // RESOLUTION_FAILS models an old pip with no `--report`: the tree
        // dry-run exits 2, so these tests exercise the named-only fallback.
        let mut h = GateHarness::new()
            .fake_tree_pm("pip", RESOLUTION_FAILS, pip_exit_code)
            .wildcard_pypi_registry()
            .vuln_checks(checks)
            .vuln_statuses(statuses);
        if let Some(t) = token {
            h = h.token(t);
        }
        Self(h.build())
    }
}

#[cfg(unix)]
impl std::ops::Deref for PipHarness {
    type Target = GateHarness;

    fn deref(&self) -> &GateHarness {
        &self.0
    }
}

#[cfg(unix)]
impl std::ops::DerefMut for PipHarness {
    fn deref_mut(&mut self) -> &mut GateHarness {
        &mut self.0
    }
}

/// `corgea` wired to the oldpkg registry stub, a tree-aware fake `binary`
/// (`"pip"` or `"npm"`) answering the tree pass with `payload`, a vuln-api
/// stub, and a token.
#[cfg(unix)]
#[allow(dead_code)]
pub struct TreeHarness(GateHarness);

#[cfg(unix)]
#[allow(dead_code)]
impl TreeHarness {
    pub fn new(
        binary: &str,
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        payload: &str,
    ) -> Self {
        Self(
            GateHarness::new()
                .fake_tree_pm(binary, payload, 0)
                .oldpkg_registry()
                .vuln_checks(checks)
                .vuln_statuses(statuses)
                .token("test-token")
                .build(),
        )
    }
}

#[cfg(unix)]
impl std::ops::Deref for TreeHarness {
    type Target = GateHarness;

    fn deref(&self) -> &GateHarness {
        &self.0
    }
}

#[cfg(unix)]
impl std::ops::DerefMut for TreeHarness {
    fn deref_mut(&mut self) -> &mut GateHarness {
        &mut self.0
    }
}
