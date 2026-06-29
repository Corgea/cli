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
///
/// The recency gate is pinned **off** (`CORGEA_RECENCY_GATE=0`) so that — as
/// with the registry stubs — every block in a gate test is the vuln verdict's
/// doing, not an incidental publish-date. Recency-specific tests opt back in
/// with `h.cmd.env("CORGEA_RECENCY_GATE", "1")`.
#[allow(dead_code)]
pub fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("CORGEA_RECENCY_GATE", "0")
        .env_remove("CORGEA_RECENCY_THRESHOLD_DAYS")
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

    /// Skip the vuln-api stub: `CORGEA_VULN_API_URL` stays unset so tests
    /// can exercise the no-endpoint / unreachable-endpoint behavior.
    pub fn without_vuln_api(mut self) -> Self {
        self.vuln_api = false;
        self
    }

    /// Re-point the corgea invocation at a (created) subdirectory of the
    /// project dir — for tests proving ancestor-walk behavior.
    pub fn in_subdir(mut self, name: &str) -> Self {
        if self.project.is_none() {
            self = self.in_project_dir();
        }
        let dir = self.project.as_ref().unwrap().path().join(name);
        std::fs::create_dir_all(&dir).expect("create subdir");
        self.cmd.current_dir(&dir);
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
/// published 2020 → recency never blocks), a report-less fake pip
/// (recording its argv to a marker), and a vuln-api stub. Every block in a
/// `pip_harness` test is the verdict's doing.
/// `token: None` exercises public mode (no CORGEA_TOKEN set).
#[cfg(unix)]
#[allow(dead_code)]
pub fn pip_harness(
    checks: HashMap<PackageKey, String>,
    statuses: HashMap<PackageKey, u16>,
    token: Option<&str>,
    pip_exit_code: i32,
) -> GateHarness {
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
    h.build()
}

/// `corgea` wired to the oldpkg registry stub, a tree-aware fake `binary`
/// (`"pip"`, `"pip3"`, or `"npm"`) answering the tree pass with `payload`,
/// and a vuln-api stub.
#[cfg(unix)]
#[allow(dead_code)]
pub fn tree_harness(
    binary: &str,
    checks: HashMap<PackageKey, String>,
    statuses: HashMap<PackageKey, u16>,
    payload: &str,
) -> GateHarness {
    GateHarness::new()
        .fake_tree_pm(binary, payload, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .vuln_statuses(statuses)
        .build()
}

// --- project-resolution e2e fixtures (shared by list_resolution.rs and
// wait_resolution.rs) -------------------------------------------------------

/// Canonical project name for the Bank-of-Hope resolution case: the dir
/// basename (`dotnet-azure-web-tsb`) differs from the stored project name.
#[allow(dead_code)]
pub const CANON: &str = "bohappdev/dotnet-azure-web-tsb";
/// Git remote whose slug resolves to `CANON`.
#[allow(dead_code)]
pub const REMOTE: &str = "https://github.com/bohappdev/dotnet-azure-web-tsb.git";

/// `/projects` hit returning the canonical project whose `repo_url` contains
/// the slug (id 7) — the new-backend confirmed path.
#[allow(dead_code)]
pub fn projects_match() -> String {
    r#"{"status":"ok","projects":[{"id":7,"name":"bohappdev/dotnet-azure-web-tsb","repo_url":"https://github.com/bohappdev/dotnet-azure-web-tsb"}]}"#.to_string()
}

/// `/projects` miss (repo not onboarded / pre-COR-1426 backend filtered out).
#[allow(dead_code)]
pub fn projects_empty() -> String {
    r#"{"status":"ok","projects":[]}"#.to_string()
}

/// `/scans` returning one `Complete` scan under `project`.
#[allow(dead_code)]
pub fn scans_one(project: &str) -> String {
    format!(
        r#"{{"status":"ok","page":1,"total_pages":1,"scans":[{{"id":"scan-123","project":"{project}","repo":"https://github.com/bohappdev/dotnet-azure-web-tsb","branch":"main","status":"Complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}}]}}"#
    )
}

/// `/scans` returning an empty page.
#[allow(dead_code)]
pub fn scans_empty() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"scans":[]}"#.to_string()
}

/// Temp git repo at `<tmp>/<dirname>` with `origin` set to `remote`. The dir
/// basename is the caller's to choose so it can differ from the stored name.
#[allow(dead_code)]
pub fn temp_git_repo(dirname: &str, remote: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().expect("temp dir");
    let repo_dir = tmp.path().join(dirname);
    std::fs::create_dir(&repo_dir).expect("create repo dir");
    let repo = git2::Repository::init(&repo_dir).expect("git init");
    repo.remote("origin", remote).expect("set origin");
    (tmp, repo_dir)
}

/// Temp NON-git dir at `<tmp>/<dirname>` (no remote).
#[allow(dead_code)]
pub fn temp_plain_dir(dirname: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().expect("temp dir");
    let dir = tmp.path().join(dirname);
    std::fs::create_dir(&dir).expect("create dir");
    (tmp, dir)
}
