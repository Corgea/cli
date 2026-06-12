//! Hermetic e2e tests for zero-spec ("bare") installs.
//!
//! With a `package.json`, bare `npm install` is gated like any other
//! install: the tree pass resolves the full lockfile set and verdicts
//! every package, so a vulnerable lockfile blocks (exit 1, `--force`
//! escape). Bare yarn/pnpm/uv installs have no safe dry-run — they exec
//! unchecked behind one honest stderr note.
//!
//! Harness mirrors `cli_tree.rs`: fake package manager on a private PATH
//! (tree-aware for npm, plain argv recorder for yarn/pnpm/uv) + local
//! registry stub + in-crate vuln-api stub. `oldpkg` is published in 2020 so
//! recency never blocks here.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, GateHarness, NPM_LOCK, RESOLUTION_FAILS};
use std::collections::HashMap;

const PACKAGE_JSON: &str = r#"{"name":"proj","version":"1.0.0","dependencies":{"oldpkg":"1.0.0"}}"#;

#[test]
fn bare_npm_install_vulnerable_lockfile_blocks() {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "vulnerable lockfile must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
    assert!(stdout.contains("MAL-2024-0002"), "stdout: {stdout}");
    assert!(stdout.contains("(transitive)"), "stdout: {stdout}");
    // A bare install names no targets, so everything resolved is the
    // existing tree's — the refusal must say so.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("your existing dependency tree has known-vulnerable packages"),
        "bare install blames the existing tree: {stderr}"
    );
}

#[test]
fn bare_npm_install_clean_lockfile_proceeds() {
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree: 2 packages resolved"),
        "stdout: {stdout}"
    );
}

#[test]
fn bare_npm_install_force_overrides_block() {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h
        .cmd
        .args(["npm", "--force", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force must run the install");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("evildep"),
        "findings still printed under --force"
    );
}

#[test]
fn bare_npm_resolution_failure_falls_back_with_warning() {
    // Fake npm exits 1 on `--package-lock-only`. Nothing named remains to
    // verify, so the install proceeds behind the loud fallback warning.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", RESOLUTION_FAILS, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "fallback must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("transitive dependencies not checked"),
        "stderr must carry the fallback warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_npm_without_package_json_passes_through() {
    // No package.json in cwd → nothing to resolve → straight exec, no gate.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 3)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(3), "npm's own exit code propagates");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Pre-checking"), "stdout: {stdout}");
}

#[test]
fn bare_npm_install_root_redirect_refuses_without_force() {
    // A bare `npm install --prefix <other>` installs another project's whole
    // tree; the gate can't resolve that from the CWD and nothing named
    // verifies it — fail closed unless --force.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h
        .cmd
        .args(["npm", "install", "--prefix", "/tmp/other-project"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "bare root-redirect must refuse");
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("redirects the project root"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // --force bypasses.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h
        .cmd
        .args([
            "npm",
            "--force",
            "install",
            "--prefix",
            "/tmp/other-project",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force proceeds");
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install --prefix /tmp/other-project")
    );
}

#[test]
fn bare_yarn_with_no_args_prints_note_and_execs() {
    // `corgea yarn` with zero args IS `yarn install` — it must get the same
    // honest ungated note instead of a silent exec.
    let mut h = GateHarness::new()
        .fake_recorder("yarn", 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h.cmd.args(["yarn"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bare 'yarn install' is not gated"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_ungated_managers_print_note_and_exec() {
    // yarn's nonzero exit also proves the manager's own exit code propagates.
    let cases = [
        ("yarn", &["yarn", "install"][..], "install", 7),
        ("pnpm", &["pnpm", "install"][..], "install", 0),
        ("uv", &["uv", "add"][..], "add", 0),
        ("uv", &["uv", "pip", "install"][..], "pip install", 0),
    ];
    for (binary, args, forwarded_argv, exit_code) in cases {
        let mut h = GateHarness::new()
            .fake_recorder(binary, exit_code)
            .oldpkg_registry()
            .vuln_checks(HashMap::new())
            .in_project_dir()
            .build();
        let out = h.cmd.args(args).output().expect("run corgea");
        assert_eq!(out.status.code(), Some(exit_code), "{args:?}");
        assert_eq!(h.recorded_argv().as_deref(), Some(forwarded_argv));
        let note = format!(
            "note: bare '{}' is not gated (no safe dry-run) — dependencies install unchecked",
            args.join(" ")
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(&note),
            "{args:?} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn yarn_cwd_value_does_not_bypass_the_gate() {
    // SECURITY: yarn-classic's `--cwd <dir>` takes a value; if the
    // directory is mistaken for the verb, `yarn --cwd packages/app add x`
    // execs as ungated passthrough. The vulnerable named target must
    // still block.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "oldpkg", "1.0.0"),
        vulnerable_body("npm", "oldpkg", "1.0.0", "MAL-2024-0007", None),
    );
    let mut h = GateHarness::new()
        .fake_recorder("yarn", 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .in_project_dir()
        .build();
    let out = h
        .cmd
        .args(["yarn", "--cwd", "packages/app", "add", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "--cwd's value must not swallow the verb: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv(), None, "yarn must not run when blocked");
}

#[test]
fn yarn_named_target_does_not_print_bare_note() {
    // A named target takes the gated path: named-only warning, no bare note.
    let mut h = GateHarness::new()
        .fake_recorder("yarn", 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h
        .cmd
        .args(["yarn", "add", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean named target proceeds");
    assert_eq!(h.recorded_argv().as_deref(), Some("add oldpkg@1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not gated"),
        "named install must not print the bare note: {stderr}"
    );
    assert!(
        stderr.contains("transitive dependencies not checked"),
        "named-only warning still applies to yarn: {stderr}"
    );
}

#[test]
fn bare_npm_install_from_subdirectory_is_gated() {
    // npm walks ancestors to find the project; the gate must too, or a
    // bare install from <project>/src would install the whole (vulnerable)
    // tree silently unchecked.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .in_subdir("src")
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "vulnerable lockfile must block from a subdirectory too"
    );
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
}
