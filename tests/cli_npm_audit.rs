//! Hermetic e2e tests for the warn-only `npm audit` second opinion
//! (`corgea npm install …` with a token + vuln-api stub).
//!
//! Extends the `cli_tree.rs` harness pattern with an audit-aware fake npm:
//! a `--package-lock-only` invocation writes a canned lockfile (the tree
//! pass), an `audit` invocation emits a canned audit report on stdout (real
//! `npm audit` exits 1 when it finds advisories — that's the success case),
//! and any other invocation records its argv to a marker. The audit is a
//! supplementary signal only: it must never block, never unblock, and never
//! change exit codes.

#![cfg(unix)]

mod common;

use common::corgea_isolated;
use corgea::vuln_api_stub::{self, PackageKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use tempfile::TempDir;

fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

/// npm lockfile-v3 fixture: named `oldpkg` 1.0.0 + transitive `evildep` 0.4.2.
const NPM_LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
  "":{"name":"proj","version":"1.0.0"},
  "node_modules/oldpkg":{"version":"1.0.0"},
  "node_modules/evildep":{"version":"0.4.2"}}}"#;

/// npm audit report v2 with two advisories: 1 critical + 1 high.
const AUDIT_ADVISORIES: &str = r#"{"auditReportVersion":2,
  "vulnerabilities":{
    "minimist":{"name":"minimist","severity":"critical","via":[]},
    "lodash":{"name":"lodash","severity":"high","via":[]}},
  "metadata":{"vulnerabilities":
    {"info":0,"low":0,"moderate":0,"high":1,"critical":1,"total":2}}}"#;

/// npm audit report v2 with no advisories.
const AUDIT_CLEAN: &str = r#"{"auditReportVersion":2,"vulnerabilities":{},
  "metadata":{"vulnerabilities":
    {"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}"#;

fn vulnerable_evildep_body() -> String {
    r#"{"ecosystem":"npm","package_name":"evildep","version":"0.4.2","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}]}"#
        .to_string()
}

/// How the fake npm behaves on its `audit --json` invocation.
#[derive(Clone, Copy)]
enum AuditScenario {
    /// Emits `AUDIT_ADVISORIES` and exits 1 — real npm audit's
    /// advisories-found behaviour.
    Advisories,
    /// Emits `AUDIT_CLEAN` and exits 0.
    Clean,
    /// Emits nothing and exits 1 — unparsable output must be a silent skip.
    Broken,
    /// Never answers — the gate's `recv_timeout` must move on without it.
    Hang,
}

/// Registry stub serving the `/oldpkg` npm packument, published 2020 →
/// never recent. Everything else 404s.
fn spawn_registry_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
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

            let (status, body) = if path == "/oldpkg" {
                (
                    "200 OK",
                    r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}"#,
                )
            } else {
                ("404 Not Found", r#"{"message":"not found"}"#)
            };
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

/// Shell loop that emits `path` line by line — works under the locked-down
/// test PATH (no `cat`); the `|| [ -n "$line" ]` guard keeps a final line
/// with no trailing newline.
fn emit(path: &Path) -> String {
    format!(
        "while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{}'",
        path.display()
    )
}

/// Write an executable fake npm into `dir`:
///   * `audit` (checked first — the audit argv also carries
///     `--package-lock-only`) → records argv to `audit_marker`, then acts out
///     `scenario`;
///   * `--package-lock-only` → writes `NPM_LOCK` to `./package-lock.json`
///     (cwd is the resolver's throwaway temp dir), exits 0 — the tree pass;
///   * anything else → records argv to `marker`, exits 0 — the real install.
fn write_fake_npm(
    dir: &Path,
    marker: &Path,
    audit_marker: &Path,
    audit_pid: &Path,
    scenario: AuditScenario,
) {
    use std::os::unix::fs::PermissionsExt;
    let lock_payload = dir.join("npm-lock-payload.json");
    std::fs::write(&lock_payload, NPM_LOCK).expect("write lock payload");
    let audit_branch = match scenario {
        AuditScenario::Advisories | AuditScenario::Clean => {
            let (body, code) = match scenario {
                AuditScenario::Advisories => (AUDIT_ADVISORIES, 1),
                _ => (AUDIT_CLEAN, 0),
            };
            let audit_payload = dir.join("npm-audit-payload.json");
            std::fs::write(&audit_payload, body).expect("write audit payload");
            format!("{}; exit {code}", emit(&audit_payload))
        }
        AuditScenario::Broken => "exit 1".to_string(),
        // Record the PID, then `exec` so the sleep IS the audit child (a
        // plain `/bin/sleep 10` would be a grandchild the gate's kill never
        // reaches).
        AuditScenario::Hang => format!(
            "printf '%s' $$ > '{}'; exec /bin/sleep 10",
            audit_pid.display()
        ),
    };
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in\n\
         *\" audit \"*) printf '%s' \"$*\" > '{audit_marker}'; {audit_branch};;\n\
         *\" --package-lock-only \"*) {lock} > package-lock.json; exit 0;;\n\
         esac\nprintf '%s' \"$*\" > '{marker}'\nexit 0\n",
        lock = emit(&lock_payload),
        audit_marker = audit_marker.display(),
        marker = marker.display(),
    );
    let path = dir.join("npm");
    std::fs::write(&path, script).expect("write fake npm");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// `corgea` wired to the registry stub, an audit-aware fake npm, and a
/// vuln-api stub.
struct AuditHarness {
    cmd: Command,
    marker: PathBuf,
    audit_marker: PathBuf,
    audit_pid: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl AuditHarness {
    fn new(checks: HashMap<PackageKey, String>, scenario: AuditScenario) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        let audit_marker = bin.path().join("audit-argv.txt");
        let audit_pid = bin.path().join("audit-pid.txt");
        write_fake_npm(bin.path(), &marker, &audit_marker, &audit_pid, scenario);
        let registry = spawn_registry_stub();
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, HashMap::new());
        cmd.env("PATH", bin.path())
            .env("CORGEA_NPM_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_TOKEN", "test-token")
            .env_remove("CORGEA_NO_NPM_AUDIT");
        Self {
            cmd,
            marker,
            audit_marker,
            audit_pid,
            _home: home,
            _bin: bin,
        }
    }

    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

#[test]
fn audit_advisories_warn_on_stderr_without_blocking() {
    // Verdicts all clean; only npm audit complains → note on stderr, the
    // install still runs, exit code stays 0.
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Advisories);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "audit findings must not block");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "note: npm audit reports 2 advisories (2 high/critical) — supplementary signal, not blocking"
        ),
        "stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&h.audit_marker).as_deref().ok(),
        Some("audit --json --package-lock-only"),
        "audit must run as `npm audit --json --package-lock-only`"
    );
}

#[test]
fn audit_clean_report_prints_no_note() {
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Clean);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("npm audit reports"),
        "zero advisories must stay silent: {stderr}"
    );
}

#[test]
fn audit_json_object_in_tree_arm() {
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Advisories);
    let out = h
        .cmd
        .args(["npm", "--json", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let audit = &parsed["tree"]["npm_audit"];
    assert_eq!(audit["total"], 2);
    assert_eq!(audit["critical"], 1);
    assert_eq!(audit["high"], 1);
    assert_eq!(audit["moderate"], 0);
    // `top` is sorted severest first.
    assert_eq!(audit["top"][0]["name"], "minimist");
    assert_eq!(audit["top"][0]["severity"], "critical");
    assert_eq!(audit["top"][1]["name"], "lodash");
    assert_eq!(audit["top"][1]["severity"], "high");
}

#[test]
fn audit_disabled_by_env_var() {
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Advisories);
    let out = h
        .cmd
        .env("CORGEA_NO_NPM_AUDIT", "1")
        .args(["npm", "--json", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("npm audit reports"), "stderr: {stderr}");
    assert!(
        !h.audit_marker.exists(),
        "CORGEA_NO_NPM_AUDIT=1 must skip the audit subprocess entirely"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["mode"], "full");
    assert!(parsed["tree"]["npm_audit"].is_null());
}

#[test]
fn audit_failure_is_a_silent_skip() {
    // Audit exits 1 with no output (unparsable) → no note, null in JSON,
    // gate result untouched.
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Broken);
    let out = h
        .cmd
        .args(["npm", "--json", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("npm audit"),
        "a failed audit must stay silent"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed["tree"]["npm_audit"].is_null());
}

#[test]
fn audit_hang_is_skipped_within_the_collect_window() {
    // The fake audit sleeps 10s; the gate's 1s collect window must move on —
    // and must kill the audit child on its way out, not orphan it past the
    // CLI's exit.
    let started = std::time::Instant::now();
    let mut h = AuditHarness::new(HashMap::new(), AuditScenario::Hang);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("npm audit"),
        "a timed-out audit must stay silent"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "gate must not wait out the hung audit (took {:?})",
        started.elapsed()
    );
    let pid = std::fs::read_to_string(&h.audit_pid).expect("audit must have started");
    let alive = Command::new("kill")
        .args(["-0", pid.trim()])
        .status()
        .expect("run kill -0")
        .success();
    assert!(
        !alive,
        "hung audit child (pid {}) must be dead after the CLI exits",
        pid.trim()
    );
}

#[test]
fn audit_never_unblocks_a_vulnerable_verdict() {
    // Transitive `evildep` is flagged by the verdict; the audit also has
    // findings. Block behaviour and exit code are the verdict's alone — the
    // audit note still prints as a supplementary signal.
    let mut checks = HashMap::new();
    checks.insert(key("npm", "evildep", "0.4.2"), vulnerable_evildep_body());
    let mut h = AuditHarness::new(checks, AuditScenario::Advisories);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "verdict block must stand");
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict regardless of audit"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm audit reports 2 advisories"),
        "stderr: {stderr}"
    );
}
