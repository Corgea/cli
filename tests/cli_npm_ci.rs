//! Hermetic e2e tests for the `corgea npm ci` gate and install-verb routing.
//!
//! `npm ci` installs the project lockfile exactly as written, so the gate
//! verdicts the lockfile-pinned set directly — no dry-run subprocess. Verb
//! routing must also find the install verb behind global flags
//! (`npm --silent install …`), or those spellings would exec ungated.
//!
//! Harness mirrors `cli_bare_install.rs`: fake npm argv recorder on a
//! private PATH + local registry stub + in-crate vuln-api stub.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, GateHarness, NPM_LOCK};
use std::collections::HashMap;

const PACKAGE_JSON: &str = r#"{"name":"proj","version":"1.0.0","dependencies":{"oldpkg":"1.0.0"}}"#;

fn vulnerable_evildep_checks() -> HashMap<corgea::vuln_api_stub::PackageKey, String> {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    checks
}

#[test]
fn npm_ci_vulnerable_lockfile_blocks() {
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(vulnerable_evildep_checks())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h.cmd.args(["npm", "ci"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "vulnerable lockfile must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in ["evildep", "MAL-2024-0002", "(locked)"] {
        assert!(stdout.contains(needle), "stdout: {stdout}");
    }
}

#[test]
fn npm_ci_clean_lockfile_proceeds() {
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "ci", "--ignore-scripts"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean lockfile must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("ci --ignore-scripts"));
}

#[test]
fn npm_ci_clean_lockfile_json_summary_counts_the_tree() {
    // A lockfile install has no named outcomes, so a clean `npm ci` must
    // report its checked packages under `summary.tree`, not as an all-zero
    // summary. `named` stays empty; `tree` reconciles against the lockfile.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean lockfile must proceed");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let summary = &parsed["summary"];
    assert_eq!(summary["tree"]["resolved_count"], 2);
    assert_eq!(summary["tree"]["clean"], 2);
    assert_eq!(summary["tree"]["vulnerable"], 0);
    assert_eq!(summary["named"]["ok"], 0);
    assert_eq!(summary["named"]["clean"], 0);
}

#[test]
fn npm_ci_no_project_json_emits_single_empty_report() {
    // `npm ci` in a directory with no package.json: npm errors on its own,
    // but under --json stdout must still be exactly one parseable Corgea
    // document (an empty report) — not empty, and not the manager's stdout.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"), "npm still runs");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be one JSON document");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["summary"]["tree"]["resolved_count"], 0);
}

#[test]
fn npm_ci_no_lockfile_json_emits_single_empty_report() {
    // package.json but no package-lock.json: same one-document contract as
    // the no-project case above.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"), "npm still runs");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be one JSON document");
    assert_eq!(parsed["schema_version"], 1);
}

#[test]
fn npm_ci_json_missing_binary_after_report_is_single_doc() {
    // A clean lockfile prints its report, then npm is missing from PATH (no
    // fake recorder). The missing-binary error must stay on stderr and exit
    // 127 — never append a second {"error"} JSON document onto the report.
    let mut h = GateHarness::new()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(127), "missing npm exits 127");
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("stdout must be exactly one JSON document, not two concatenated");
    assert_eq!(parsed["schema_version"], 1);
    // The report (not an error doc) is what's on stdout; the binary-missing
    // message goes to stderr.
    assert_eq!(parsed["summary"]["tree"]["clean"], 2);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not found on PATH"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn npm_ci_unparsable_lockfile_refuses_without_force() {
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", "not json")
        .build();
    let out = h.cmd.args(["npm", "ci"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "unverifiable lockfile refuses");
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot verify 'npm ci'") && stderr.contains("--force"),
        "stderr: {stderr}"
    );
}

#[test]
fn npm_ci_unparsable_lockfile_force_proceeds() {
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", "not json")
        .build();
    let out = h
        .cmd
        .args(["npm", "--force", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force proceeds unchecked");
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("proceeding under --force"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn npm_ci_unparsable_lockfile_force_json_emits_proceed_doc() {
    // --force over an unparsable lockfile proceeds — but under --json
    // stdout must still carry one parseable document (a warning/proceeded
    // doc), not be left empty for a CI consumer to choke on.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", "not json")
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "--force", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force proceeds unchecked");
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["proceeded"], true, "parsed: {parsed}");
    assert!(
        parsed["warning"]
            .as_str()
            .is_some_and(|w| w.contains("cannot verify")),
        "parsed: {parsed}"
    );
}

#[test]
fn npm_ci_unparsable_lockfile_json_refusal_is_parseable() {
    // The unparsable-lockfile refusal must emit a parseable {"error": …}
    // document under --json, not bare stderr.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", "not json")
        .build();
    let out = h
        .cmd
        .args(["npm", "--json", "ci"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(
        parsed["error"]
            .as_str()
            .is_some_and(|e| e.contains("cannot verify 'npm ci'")),
        "parsed: {parsed}"
    );
}

#[test]
fn npm_ci_root_redirect_refuses_without_force() {
    // `npm ci --prefix ../other` installs a different project's lockfile than
    // the CWD one we'd verdict — fail closed rather than pass on the wrong
    // project.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "ci", "--prefix", "/tmp/other-project"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "root-redirect ci must refuse");
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--prefix") && stderr.contains("redirected project"),
        "stderr: {stderr}"
    );

    // --force bypasses.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "--force", "ci", "--prefix", "/tmp/other-project"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force proceeds");
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("ci --prefix /tmp/other-project")
    );
}

#[test]
fn npm_ci_registry_flag_warns_then_proceeds() {
    // `npm ci --registry <url>` pulls tarballs from the override while the
    // gate verdicts the lockfile against the default registry — warn, but
    // still proceed on a clean lockfile.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .build();
    let out = h
        .cmd
        .args(["npm", "ci", "--registry", "https://evil.example/"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean lockfile must proceed");
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("ci --registry https://evil.example/")
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--registry") && stderr.contains("custom registry"),
        "npm ci --registry must warn: {stderr}"
    );
}

#[test]
fn npm_ci_npmrc_registry_warns_then_proceeds() {
    // A project `.npmrc` `registry=` line silently redirects resolution; the
    // gate copies it into its temp dir so resolution honours the override, yet
    // verdicts against the default registry — warn on it.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .with_project_file("package-lock.json", NPM_LOCK)
        .with_project_file(".npmrc", "registry=https://evil.example/\n")
        .build();
    let out = h.cmd.args(["npm", "ci"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean lockfile must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(".npmrc") && stderr.contains("custom registry"),
        "project .npmrc registry override must warn: {stderr}"
    );
}

#[test]
fn npm_ci_without_lockfile_execs() {
    // npm ci errors on its own without a lockfile; nothing to gate.
    let mut h = GateHarness::new()
        .fake_recorder("npm", 9)
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "ci"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(9), "npm's own exit code propagates");
    assert_eq!(h.recorded_argv().as_deref(), Some("ci"));
}

#[test]
fn global_flags_before_the_verb_still_gate() {
    // `npm --loglevel silent install <vulnerable pin>` must route to the
    // gate, not the ungated passthrough.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "oldpkg", "1.0.0"),
        vulnerable_body("npm", "oldpkg", "1.0.0", "MAL-2024-0001", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .in_project_dir()
        .build();
    let out = h
        .cmd
        .args(["npm", "--loglevel", "silent", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "flags before the verb must not skip the gate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
}

#[test]
fn global_flags_before_the_verb_forward_on_clean() {
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h
        .cmd
        .args(["npm", "--loglevel", "silent", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean pin proceeds");
    // The verb leads the reconstructed argv; the global flags still arrive.
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install --loglevel silent oldpkg@1.0.0")
    );
}
