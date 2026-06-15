//! Shared helpers for the e2e CLI tests (standard Cargo `tests/common/mod.rs`
//! pattern — included via `mod common;` from each integration-test crate, so
//! items unused by one consumer are `#[allow(dead_code)]`).

#[cfg(unix)]
use corgea::vuln_api_stub::PackageKey;
/// `(ecosystem, name, version)` stub key and the single-match vulnerable
/// verdict body, shared with the in-crate unit tests.
#[allow(unused_imports)]
pub use corgea::vuln_api_stub::{key, vulnerable_body};
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

/// Publish timestamp far in the past → never recent.
#[allow(dead_code)]
pub const OLD_TS: &str = "2020-01-01T00:00:00Z";

/// PyPI release JSON: one release of `version`, published at `ts`.
#[allow(dead_code)]
pub fn pypi_release_json(name: &str, version: &str, ts: &str) -> String {
    format!(
        r#"{{"info":{{"name":"{name}"}},"releases":{{"{version}":[{{"upload_time_iso_8601":"{ts}"}}]}}}}"#
    )
}

/// npm packument: a single `version` as latest, published at `ts`.
#[allow(dead_code)]
pub fn npm_packument(version: &str, ts: &str) -> String {
    format!(
        r#"{{"dist-tags":{{"latest":"{version}"}},"versions":{{"{version}":{{}}}},"time":{{"{version}":"{ts}"}}}}"#
    )
}

/// Spawn a one-response-per-connection HTTP stub on an ephemeral 127.0.0.1
/// port; `route` maps a request path to `(status line, body)`. Returns the
/// base URL.
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
            let response = corgea::vuln_api_stub::http_response(status, "", &body);
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
        "/pypi/oldpkg/json" => ("200 OK", pypi_release_json("oldpkg", "1.0.0", OLD_TS)),
        "/oldpkg" => ("200 OK", npm_packument("1.0.0", OLD_TS)),
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
            Some(name) => ("200 OK", pypi_release_json(name, "1.0.0", OLD_TS)),
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

/// One configurable harness behind every gate test: isolated `corgea`, a
/// private PATH of fake package managers, optional registry stubs, the
/// vuln-api stub, and an optional throwaway project cwd.
#[cfg(unix)]
#[allow(dead_code)]
pub struct GateHarness {
    pub cmd: Command,
    marker: PathBuf,
    project: Option<TempDir>,
    checks: HashMap<PackageKey, String>,
    statuses: HashMap<PackageKey, u16>,
    vuln_api: bool,
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
            vuln_api: true,
            _home: home,
            _bin: bin,
            _vuln_stub: None,
        }
    }

    /// Plain argv recorder. Call repeatedly for multiple binaries; call
    /// never for an empty PATH.
    pub fn fake_recorder(self, binary: &str, exit_code: i32) -> Self {
        write_fake_recorder(self._bin.path(), binary, &self.marker, exit_code);
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

    /// Skip the vuln-api stub: `CORGEA_VULN_API_URL` stays unset so tests
    /// can exercise the no-endpoint / unreachable-endpoint behavior.
    pub fn without_vuln_api(mut self) -> Self {
        self.vuln_api = false;
        self
    }

    pub fn build(mut self) -> Self {
        if !self.vuln_api {
            return self;
        }
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

/// `corgea` wired to the wildcard pypi registry stub (every package
/// published 2020 → recency never blocks), a fake pip recording its argv
/// to a marker, and a vuln-api stub. Every block in a `pip_harness` test
/// is the verdict's doing.
#[cfg(unix)]
#[allow(dead_code)]
pub fn pip_harness(
    checks: HashMap<PackageKey, String>,
    statuses: HashMap<PackageKey, u16>,
    pip_exit_code: i32,
) -> GateHarness {
    GateHarness::new()
        .fake_recorder("pip", pip_exit_code)
        .wildcard_pypi_registry()
        .vuln_checks(checks)
        .vuln_statuses(statuses)
        .build()
}
