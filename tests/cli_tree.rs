//! Hermetic e2e tests for the full-tree resolution pass
//! (`corgea pip|npm install …` with a `CORGEA_VULN_API_URL` stub).
//!
//! Composes the `cli_verdict.rs` harness pattern (fake package manager on a
//! private PATH + local registry stub + in-crate vuln-api stub) with a
//! tree-aware fake manager: a dry-run invocation answers with a canned
//! payload, every other invocation records its argv to a marker and exits.
//! `oldpkg` is published in 2020 so recency never blocks here — every block
//! is the verdict's doing.

#![cfg(unix)]

mod common;

use common::{
    key, tree_harness, vulnerable_body, GateHarness, NPM_LOCK, RESOLUTION_FAILS, TREE_REPORT,
    UV_COMPILED,
};
use std::collections::HashMap;
use tempfile::TempDir;

#[test]
fn pip_only_binary_guard_wins_over_user_no_binary() {
    // SECURITY: the non-execution guard `--only-binary :all:` must land AFTER
    // the user's args (pip format-control is last-wins), so a user
    // `--no-binary :all:` can't re-enable sdist builds during the report step.
    // The fake pip records its dry-run argv to the marker on the --dry-run
    // branch and no-ops the real install, so `recorded_argv()` is the dry-run.
    let mut h = GateHarness::new()
        .script_with_paths("pip", |_, marker| {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) printf '%s' \"$*\" > '{}'; printf '{{\"install\":[{{\"metadata\":{{\"name\":\"oldpkg\",\"version\":\"1.0.0\"}},\"requested\":true}}]}}'; exit 0;; esac\nexit 0\n",
                marker.display()
            )
        })
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .build();
    let out = h
        .cmd
        .args(["pip", "install", "--no-binary", ":all:", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree proceeds");
    let argv = h.recorded_argv().expect("dry-run argv recorded");
    assert!(
        argv.contains("--no-binary :all:"),
        "user flag must be forwarded: {argv}"
    );
    assert!(
        argv.trim_end().ends_with("--only-binary :all:"),
        "the guard must be appended LAST so it wins: {argv}"
    );
}

#[test]
fn pip_requirements_format_control_refuses_dry_run() {
    // SECURITY: pip applies `--no-binary` directives found INSIDE a -r file
    // AFTER CLI parsing, overriding the trailing `--only-binary :all:`
    // guard — the dry-run would select and build sdists, executing package
    // code. The tree pass must refuse to dry-run such files and degrade to
    // the named-only fallback (whose parser skips option lines), still
    // verdicting the file's registry entries.
    let cwd = TempDir::new().expect("temp cwd");
    std::fs::write(
        cwd.path().join("requirements.txt"),
        "--no-binary :all:\noldpkg==1.0.0\n",
    )
    .expect("write requirements.txt");
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0004", None),
    );
    // The fake pip records argv ONLY on its dry-run branch: a recorded
    // marker would mean the dry-run executed against the hostile file.
    let mut h = GateHarness::new()
        .script_with_paths("pip", |_, marker| {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) printf '%s' \"$*\" > '{}';; esac\nexit 0\n",
                marker.display()
            )
        })
        .oldpkg_registry()
        .vuln_checks(checks)
        .build();
    let out = h
        .cmd
        .current_dir(cwd.path())
        .args(["pip", "install", "-r", "requirements.txt"])
        .output()
        .expect("run corgea");

    assert_eq!(
        out.status.code(),
        Some(1),
        "the file's vulnerable entry must still block via the fallback"
    );
    assert_eq!(
        h.recorded_argv(),
        None,
        "the dry-run must never execute against a format-control requirements file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--no-binary") && stderr.contains("not dry-running"),
        "stderr must name the refusing directive: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MAL-2024-0004"), "stdout: {stdout}");
}

fn vulnerable_evildep_body(ecosystem: &str) -> String {
    vulnerable_body(ecosystem, "evildep", "0.4.2", "MAL-2024-0002", None)
}

#[test]
fn transitive_vulnerable_blocks_install() {
    // Only the transitive `evildep` is flagged; the named `oldpkg` is clean.
    let cases = [
        (
            "pip",
            "pypi",
            TREE_REPORT,
            &["pip", "install", "oldpkg==1.0.0"][..],
        ),
        (
            "npm",
            "npm",
            NPM_LOCK,
            &["npm", "install", "oldpkg@1.0.0"][..],
        ),
        (
            "uv",
            "pypi",
            UV_COMPILED,
            &["uv", "pip", "install", "oldpkg==1.0.0"][..],
        ),
    ];
    for (binary, eco, payload, args) in cases {
        let mut checks = HashMap::new();
        checks.insert(key(eco, "evildep", "0.4.2"), vulnerable_evildep_body(eco));
        let mut h = tree_harness(binary, checks, HashMap::new(), payload);
        let out = h.cmd.args(args).output().expect("run corgea");
        assert_eq!(
            out.status.code(),
            Some(1),
            "{binary}: transitive vuln must block"
        );
        assert_eq!(
            h.recorded_argv(),
            None,
            "{binary} must not run on a transitive vulnerable verdict"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        for needle in ["evildep", "MAL-2024-0002", "(transitive)"] {
            assert!(stdout.contains(needle), "{binary} stdout: {stdout}");
        }
    }
}

#[test]
fn uv_requirements_file_install_is_tree_gated() {
    // `uv pip install -r requirements.txt` names no targets — the gate must
    // still resolve the full set via `uv pip compile` and block on the
    // vulnerable pin instead of exec'ing unchecked.
    let cwd = TempDir::new().expect("temp cwd");
    std::fs::write(cwd.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements.txt");
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_evildep_body("pypi"),
    );
    let mut h = tree_harness("uv", checks, HashMap::new(), UV_COMPILED);
    let out = h
        .cmd
        .current_dir(cwd.path())
        .args(["uv", "pip", "install", "-r", "requirements.txt"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert_eq!(h.recorded_argv(), None, "uv must not run when blocked");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in ["evildep", "MAL-2024-0002", "(transitive)"] {
        assert!(stdout.contains(needle), "stdout: {stdout}");
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not gated"),
        "gated uv requirements install must not print the bare note: {stderr}"
    );
}

#[test]
fn tree_pass_runs_via_pip3_when_pip_is_absent() {
    // Only `pip3` exists on PATH (common Linux/macOS). The tree pass must
    // use the same pip → pip3 fallback as the exec path instead of silently
    // degrading to named-only — the transitive `evildep` must still block.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_evildep_body("pypi"),
    );
    let mut h = tree_harness("pip3", checks, HashMap::new(), TREE_REPORT);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("transitive dependencies not checked"),
        "tree pass must not degrade with only pip3 on PATH: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
}

#[test]
fn authenticated_tree_resolution_failure_fails_closed() {
    // The org guarantee: with a token (authenticated mode), a pip/npm/uv tree
    // pass that degrades to NamedOnly leaves the whole transitive set
    // unchecked — that must BLOCK, not install unverified transitives. The
    // named target itself is clean, so the block is purely the unchecked tree.
    let mut h = GateHarness::new()
        .fake_tree_pm("pip", RESOLUTION_FAILS, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .token("test-token")
        .build();
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "authenticated tree-resolution failure must fail closed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv(), None, "pip must not run");

    // The SAME command in public mode (no token) fails open and proceeds.
    let mut h = GateHarness::new()
        .fake_tree_pm("pip", RESOLUTION_FAILS, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .build();
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "public mode fails open");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
}

#[test]
fn authenticated_yarn_named_only_does_not_fail_closed() {
    // yarn has no safe dry-run, so its NamedOnly tree is inherent, not a
    // resolution failure. An authenticated yarn install with clean named
    // targets must still proceed — fail-closed applies only to managers that
    // HAVE a resolver (pip/npm/uv).
    let mut h = GateHarness::new()
        .fake_recorder("yarn", 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .token("test-token")
        .in_project_dir()
        .build();
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["yarn", "add", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "authenticated yarn named-only must proceed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("add oldpkg@1.0.0"));
}

#[test]
fn resolution_failure_falls_back_with_loud_warning() {
    // The fake manager fails its tree invocation (pip: exits 2 on `--dry-run`,
    // simulating an old pip with no `--report`; npm: exits 1 on
    // `--package-lock-only`). Stub is all-clean, so the named-only fallback
    // proceeds.
    let cases = [
        (
            "pip",
            &["pip", "install", "oldpkg==1.0.0"][..],
            "install oldpkg==1.0.0",
        ),
        (
            "npm",
            &["npm", "install", "oldpkg@1.0.0"][..],
            "install oldpkg@1.0.0",
        ),
        (
            "uv",
            &["uv", "pip", "install", "oldpkg==1.0.0"][..],
            "pip install oldpkg==1.0.0",
        ),
    ];
    for (binary, args, forwarded_argv) in cases {
        let mut h = tree_harness(binary, HashMap::new(), HashMap::new(), RESOLUTION_FAILS);
        let out = h.cmd.args(args).output().expect("run corgea");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{binary}: clean named-only must proceed"
        );
        assert_eq!(h.recorded_argv().as_deref(), Some(forwarded_argv));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("transitive dependencies not checked"),
            "{binary} stderr must carry the fallback warning: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn pip_requirements_fallback_checks_file_entries_when_tree_fails() {
    // A VCS requirement can make pip's dry-run fail before it emits a report.
    // The degraded path must still verify registry requirements from the file
    // and surface the VCS row as skipped instead of producing an empty check.
    let cwd = TempDir::new().expect("temp cwd");
    std::fs::write(
        cwd.path().join("requirements.txt"),
        "oldpkg==1.0.0\nidna @ git+https://github.com/jazzband/idna.git@main\n",
    )
    .expect("write requirements.txt");
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0003", None),
    );
    let mut h = tree_harness("pip", checks, HashMap::new(), RESOLUTION_FAILS);
    let out = h
        .cmd
        .current_dir(cwd.path())
        .args(["pip", "install", "-r", "requirements.txt"])
        .output()
        .expect("run corgea");

    assert_eq!(out.status.code(), Some(1), "requirements vuln must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a vulnerable requirements entry"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "oldpkg==1.0.0",
        "MAL-2024-0003",
        "idna @ git+https://github.com/jazzband/idna.git@main",
        "PEP 508 direct reference",
    ] {
        assert!(stdout.contains(needle), "stdout: {stdout}");
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("transitive dependencies not checked"),
        "stderr must carry the fallback warning: {stderr}"
    );
}

#[test]
fn pip_json_carries_tree_object() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_evildep_body("pypi"),
    );
    let mut h = tree_harness("pip", checks, HashMap::new(), TREE_REPORT);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["mode"], "full");
    assert_eq!(parsed["tree"]["transitive"][0]["name"], "evildep");
    assert_eq!(
        parsed["tree"]["transitive"][0]["verdict"]["status"],
        "vulnerable"
    );
    assert_eq!(parsed["summary"]["tree"]["vulnerable"], 1);
}

#[test]
fn pip_clean_tree_proceeds() {
    // Stub default-clean (no overrides), so every resolved package is clean.
    let mut h = tree_harness("pip", HashMap::new(), HashMap::new(), TREE_REPORT);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree: 2 packages resolved"),
        "stdout: {stdout}"
    );
}

#[test]
fn pip_full_tree_still_notes_requirements_skip_recency() {
    // A successful (Full) tree pass verdicts the `-r` packages but never
    // recency-checks them, so the "not recency-checked" note must still print —
    // it was previously suppressed whenever the tree pass was Full.
    let cwd = TempDir::new().expect("temp cwd");
    std::fs::write(cwd.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements.txt");
    let mut h = tree_harness("pip", HashMap::new(), HashMap::new(), TREE_REPORT);
    let out = h
        .cmd
        .current_dir(cwd.path())
        .args(["pip", "install", "-r", "requirements.txt"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("requirements.txt") && stderr.contains("not recency-checked"),
        "Full tree pass with -r must still note recency is skipped: {stderr}"
    );
}

#[test]
fn npm_root_redirect_flag_degrades_to_named_only() {
    // `--prefix` overrides npm's project root regardless of cwd, so the
    // throwaway-dir resolution would write the REAL lockfile at that path.
    // The tree pass must refuse and fall back to named-only instead.
    let elsewhere = TempDir::new().expect("redirect target");
    let lock_path = elsewhere.path().join("package-lock.json");

    let mut h = tree_harness("npm", HashMap::new(), HashMap::new(), NPM_LOCK);
    let out = h
        .cmd
        .args([
            "npm",
            "install",
            "--prefix",
            elsewhere.path().to_str().unwrap(),
            "oldpkg@1.0.0",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean named target proceeds");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("transitive dependencies not checked") && stderr.contains("--prefix"),
        "must degrade loudly naming the flag: {stderr}"
    );
    assert!(
        !lock_path.exists(),
        "the dry run must never write through --prefix"
    );
    // The real install still gets the user's full argv.
    assert_eq!(
        h.recorded_argv(),
        Some(format!(
            "install --prefix {} oldpkg@1.0.0",
            elsewhere.path().display()
        ))
    );
}

#[test]
fn npm_does_not_touch_project_lockfile() {
    // Run from a project dir holding sentinel manifests; the resolver works in
    // a throwaway copy, so after a gated run both files are byte-identical.
    let project = TempDir::new().expect("project dir");
    let pkg_json = project.path().join("package.json");
    let lock_json = project.path().join("package-lock.json");
    let pkg_sentinel = r#"{"name":"sentinel","version":"0.0.0"}"#;
    let lock_sentinel = r#"{"name":"sentinel","lockfileVersion":3,"packages":{}}"#;
    std::fs::write(&pkg_json, pkg_sentinel).expect("write package.json");
    std::fs::write(&lock_json, lock_sentinel).expect("write package-lock.json");

    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_evildep_body("npm"),
    );
    let mut h = tree_harness("npm", checks, HashMap::new(), NPM_LOCK);
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");

    assert_eq!(
        std::fs::read_to_string(&pkg_json).unwrap(),
        pkg_sentinel,
        "package.json must be untouched"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_json).unwrap(),
        lock_sentinel,
        "package-lock.json must be untouched"
    );
}
