//! Hermetic end-to-end tests for the install wrappers (`corgea pip|npm …`).
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_corgea`) against:
//!   * a local TcpListener stub standing in for PyPI / the npm registry
//!     (wired up via `CORGEA_PYPI_REGISTRY` / `CORGEA_NPM_REGISTRY`), and
//!   * a fake package manager on `PATH` — a shell script that records its
//!     argv to a marker file, proving whether the install actually ran.
//!
//! No live network. The fake package managers are Unix shell scripts, so
//! the whole file is Unix-only (matching the repo's Linux/macOS CI).

#![cfg(unix)]

mod common;

use common::{
    npm_packument, pip_harness, pypi_release_json, spawn_http_stub, GateHarness, NOT_FOUND_JSON,
    OLD_TS, RESOLUTION_FAILS,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

/// Spawn a registry stub serving both the PyPI and npm routes the
/// resolver hits. Returns the base URL and a counter of accepted
/// connections (used to prove "no registry hit" for passthroughs).
///
/// Routes:
///   * `/pypi/oldpkg/json`   — one release, published 2020-01-01
///   * `/pypi/freshpkg/json` — one release, published one hour ago
///   * `/oldpkg`             — npm metadata, published 2020-01-01
///   * `/freshpkg`           — npm metadata, published one hour ago
///   * anything else         — 404
fn spawn_registry_stub() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in_stub = Arc::clone(&hits);
    let base_url = spawn_http_stub(move |path| {
        hits_in_stub.fetch_add(1, Ordering::SeqCst);
        let fresh_ts = (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        match path {
            "/pypi/oldpkg/json" => ("200 OK", pypi_release_json("oldpkg", "1.0.0", OLD_TS)),
            "/pypi/freshpkg/json" => ("200 OK", pypi_release_json("freshpkg", "9.9.9", &fresh_ts)),
            "/oldpkg" => ("200 OK", npm_packument("1.0.0", OLD_TS)),
            "/freshpkg" => ("200 OK", npm_packument("9.9.9", &fresh_ts)),
            _ => ("404 Not Found", NOT_FOUND_JSON.to_string()),
        }
    });
    (base_url, hits)
}

fn wrapper(binary: &str, registry_env: &str, pm_exit_code: i32) -> GateHarness {
    wrapper_with_hits(binary, registry_env, pm_exit_code).0
}

fn wrapper_with_hits(
    binary: &str,
    registry_env: &str,
    pm_exit_code: i32,
) -> (GateHarness, Arc<AtomicUsize>) {
    let (base_url, registry_hits) = spawn_registry_stub();
    // RESOLUTION_FAILS: the tree dry-run exits non-zero without touching
    // the argv marker, so `recorded_argv()` reflects only the real install.
    // yarn/pnpm/uv have no tree invocation to intercept — plain recorders.
    let h = GateHarness::new();
    let h = match binary {
        "npm" | "pip" => h.fake_tree_pm(binary, RESOLUTION_FAILS, pm_exit_code),
        _ => h.fake_recorder(binary, pm_exit_code),
    };
    let h = h.registry_env(registry_env, &base_url).build();
    (h, registry_hits)
}

/// Harness whose fake `pip` shebang points at a fake `python-managed`
/// interpreter that reports an EXTERNALLY-MANAGED stdlib (PEP 668).
fn externally_managed_pip() -> (GateHarness, Arc<AtomicUsize>) {
    let (base_url, registry_hits) = spawn_registry_stub();
    let h = GateHarness::new()
        .script_with_paths("python-managed", |_, marker| {
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-c\" ]; then printf '1\\n'; exit 0; fi\nprintf '%s' \"$*\" > '{}'\nexit 0\n",
                marker.display()
            )
        })
        .script_with_paths("pip", |bin, _| {
            format!("#!{}\n", bin.join("python-managed").display())
        });
    (
        h.registry_env("CORGEA_PYPI_REGISTRY", &base_url).build(),
        registry_hits,
    )
}

#[test]
fn externally_managed_pip_blocks_before_registry_checks() {
    let (mut h, registry_hits) = externally_managed_pip();
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "externally-managed preflight must run before registry checks"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: this Python environment is externally managed (PEP 668)."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(
            "Create and activate a virtualenv, then retry `corgea pip install oldpkg==1.0.0`."
        ),
        "stderr: {stderr}"
    );
}

#[test]
fn externally_managed_pip_force_proceeds() {
    // The fake nested-shebang pip is not a usable recorder on macOS (the
    // libc ENOEXEC fallback runs it as an empty sh script), so this test
    // pins only the guard bypass: no PEP 668 refusal, exit 0.
    let (mut h, _registry_hits) = externally_managed_pip();
    let out = h
        .cmd
        .args(["pip", "--force", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--force must bypass the PEP 668 guard: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("externally managed"),
        "no PEP 668 refusal under --force: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn pip_fresh_pin_installs_and_shows_publish_date() {
    // Recency is pinned off in the harness (CORGEA_RECENCY_GATE=0), so a
    // freshly-published pin installs and its publish time is shown for
    // provenance. The recency-on behavior is covered below.
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh pins install with the gate off; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9")
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("published"), "stdout: {stdout}");
}

#[test]
fn pip_fresh_pin_blocks_when_recency_gate_on() {
    // With the recency gate enabled, a pin published an hour ago is refused
    // before pip runs, and the refusal points at the config toggle.
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .env("CORGEA_RECENCY_GATE", "1")
        .args(["pip", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a recency block"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("recency window"), "stderr: {stderr}");
    assert!(stderr.contains("freshpkg@9.9.9"), "stderr: {stderr}");
    assert!(
        stderr.contains("recency_gate = false"),
        "refusal must name the config toggle; stderr: {stderr}"
    );
}

#[test]
fn pip_recency_block_bypassed_by_force() {
    // `--force` overrides the recency block like every other block.
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .env("CORGEA_RECENCY_GATE", "1")
        .args(["pip", "--force", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9")
    );
}

#[test]
fn pip_recency_threshold_zero_allows_fresh_pin() {
    // A zero-day window can never be tripped — proves the threshold plumbs
    // through from the env override.
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .env("CORGEA_RECENCY_GATE", "1")
        .env("CORGEA_RECENCY_THRESHOLD_DAYS", "0")
        .args(["pip", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9")
    );
}

#[test]
fn pip_old_pin_not_blocked_by_recency() {
    // Even with the gate on, a 2020-published pin is well outside the window.
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .env("CORGEA_RECENCY_GATE", "1")
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
}

#[test]
fn pip_old_pin_runs_install_with_forwarded_args() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("published"), "stdout: {stdout}");
}

#[test]
fn pip_non_install_subcommand_passes_through_without_registry_hit() {
    let (mut h, registry_hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "list"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("list"));
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "passthrough must not touch the registry"
    );
}

#[test]
fn pip_add_blocks_with_install_suggestion_without_running_pip() {
    let (mut h, registry_hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "add", "oldpkg"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "invalid pip command must not touch the registry"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: pip does not support `add`."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea pip install oldpkg`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn pip_resolution_error_prints_error_but_install_proceeds() {
    // `nosuchpkg` hits the stub's 404 route → an error outcome, which
    // warns but does not block: public mode fails open when no verdict
    // can be obtained — the install must still run.
    let (mut h, registry_hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "nosuchpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        registry_hits.load(Ordering::SeqCst) >= 1,
        "the 404 route must have been hit"
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install nosuchpkg==1.0.0"),
        "a resolution error must not block the install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("not found"), "stdout: {stdout}");
    assert!(stdout.contains("1 errors"), "stdout: {stdout}");
}

#[test]
fn pip_json_reports_publish_date() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9")
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["results"][0]["status"], "ok");
    assert_eq!(parsed["results"][0]["name"], "freshpkg");
    assert!(
        parsed["results"][0]["published_at"].is_string(),
        "published_at must be reported: {parsed}"
    );
}

#[test]
fn pip_json_routes_package_manager_stdout_to_stderr() {
    // The fake pip fails its tree dry-run (named-only fallback) and prints
    // to stdout on the real install; under --json that output must move to
    // stderr so stdout stays parseable JSON.
    let (base_url, _hits) = spawn_registry_stub();
    let mut h = GateHarness::new()
        .script_with_paths("pip", |_, marker| {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) exit 2;; esac\nprintf 'FAKE-PM-STDOUT\\n'\nprintf '%s' \"$*\" > '{}'\nexit 0\n",
                marker.display()
            )
        })
        .registry_env("CORGEA_PYPI_REGISTRY", &base_url)
        .build();
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}): {stdout}"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("FAKE-PM-STDOUT"),
        "pip output must land on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn pip_json_guard_refusal_is_parseable() {
    // Guard refusals happen before any report exists; under --json stdout
    // must still carry one parseable document.
    let (mut h, _hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--json", "add", "oldpkg"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(
        parsed["error"]
            .as_str()
            .is_some_and(|e| e.contains("pip does not support `add`")),
        "parsed: {parsed}"
    );
}

#[test]
fn npm_json_passthrough_forwards_flag_to_manager() {
    // A non-install subcommand produces no Corgea report, so the wrapper's
    // `--json` belongs to npm — it must reach the manager rather than being
    // silently swallowed.
    let mut h = GateHarness::new().fake_recorder("npm", 0).build();
    let out = h
        .cmd
        .args(["npm", "--json", "ls"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("ls --json"),
        "the wrapper's --json must be forwarded to the manager on passthrough"
    );
}

#[test]
fn npm_json_after_verb_belongs_to_the_manager() {
    // Position sensitivity: flags after the verb belong to the package
    // manager. `corgea npm install --json x` forwards --json to npm on a
    // gated install while the gate itself stays in text mode.
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0", "--json"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0), "clean old pin proceeds");
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install oldpkg@1.0.0 --json"),
        "post-verb --json must reach npm untouched"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Pre-checking"),
        "the gate must stay in text mode: {stdout}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_err(),
        "stdout is the text report, not a JSON document"
    );
}

#[test]
fn pip_mixed_fresh_and_old_pins_both_install() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9 oldpkg==1.0.0"),
        "both pins install regardless of publish date"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("2 ok"), "stdout: {stdout}");
}

#[test]
fn npm_fresh_pin_installs() {
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "freshpkg@9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh pins no longer block; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install freshpkg@9.9.9"));
}

#[test]
fn npm_old_pin_runs_install_with_forwarded_args() {
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
}

#[test]
fn node_wrong_manager_lockfiles_block_with_suggestions() {
    struct Case {
        run_manager: &'static str,
        lockfile: &'static str,
        lock_contents: &'static str,
        args: &'static [&'static str],
        expected_manager: &'static str,
        expected_suggestion: &'static str,
    }

    let cases = [
        Case {
            run_manager: "npm",
            lockfile: "pnpm-lock.yaml",
            lock_contents: "lockfileVersion: '9.0'\n",
            args: &["npm", "i", "oldpkg"],
            expected_manager: "pnpm",
            expected_suggestion: "corgea pnpm add oldpkg",
        },
        Case {
            run_manager: "pnpm",
            lockfile: "package-lock.json",
            lock_contents: "{}",
            args: &["pnpm", "install"],
            expected_manager: "npm",
            expected_suggestion: "corgea npm install",
        },
        Case {
            run_manager: "npm",
            lockfile: "yarn.lock",
            lock_contents: "# yarn lockfile v1\n",
            args: &["npm", "i", "oldpkg"],
            expected_manager: "yarn",
            expected_suggestion: "corgea yarn add oldpkg",
        },
    ];

    for case in cases {
        let (mut h, registry_hits) = wrapper_with_hits(case.run_manager, "CORGEA_NPM_REGISTRY", 0);
        let project = TempDir::new().expect("project dir");
        std::fs::write(project.path().join(case.lockfile), case.lock_contents)
            .expect("write lockfile");
        let out = h
            .cmd
            .current_dir(project.path())
            .args(case.args)
            .output()
            .expect("run corgea");
        assert_eq!(out.status.code(), Some(1), "{}", case.lockfile);
        assert_eq!(
            h.recorded_argv(),
            None,
            "{} must not run in a {} project",
            case.run_manager,
            case.expected_manager
        );
        assert_eq!(
            registry_hits.load(Ordering::SeqCst),
            0,
            "wrong-manager refusal must not touch the registry"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!(
                "this project appears to use {}",
                case.expected_manager
            )),
            "{} stderr: {stderr}",
            case.lockfile
        );
        assert!(
            stderr.contains(&format!("Did you mean `{}`?", case.expected_suggestion)),
            "{} stderr: {stderr}",
            case.lockfile
        );
    }
}

#[test]
fn force_overrides_the_wrong_manager_guard() {
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .expect("write lockfile");
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "--force", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--force must bypass the guard: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
}

#[test]
fn fresh_project_is_not_blamed_for_ancestor_lockfiles() {
    // A project with its own package.json but no manager indicators must
    // not inherit a stray ancestor pnpm-lock.yaml.
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let root = TempDir::new().expect("root dir");
    std::fs::write(
        root.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .expect("write ancestor lockfile");
    let project = root.path().join("newapp");
    std::fs::create_dir(&project).expect("mkdir");
    std::fs::write(project.join("package.json"), "{}").expect("write manifest");
    let out = h
        .cmd
        .current_dir(&project)
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh project must not be refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
}

#[test]
fn package_manager_field_beats_missing_lockfile_for_node_guard() {
    // `packageManager: "pnpm@9"` marks a pnpm project even before the
    // first install writes a lockfile.
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"proj","packageManager":"pnpm@9.0.0"}"#,
    )
    .expect("write manifest");
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "i", "oldpkg"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("this project appears to use pnpm"),
        "stderr: {stderr}"
    );
}

#[test]
fn conflicting_node_lockfiles_do_not_block_as_wrong_manager() {
    // Two lockfiles → ambiguous; the guard must stand down rather than
    // guess.
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .expect("write pnpm lockfile");
    std::fs::write(project.path().join("yarn.lock"), "# yarn lockfile v1\n")
        .expect("write yarn lockfile");
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "ambiguous indicators must not refuse: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
}

#[test]
fn pip_in_uv_lock_project_blocks_with_uv_add_suggestion() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("uv.lock"), "version = 1\n").expect("write uv.lock");
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("this project appears to use uv"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea uv add oldpkg==1.0.0`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn uv_add_in_requirements_project_blocks_with_pip_install_suggestion() {
    let mut h = wrapper("uv", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements.txt");
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["uv", "add", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "uv must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("this project appears to use pip"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea pip install oldpkg==1.0.0`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn npm_install_verb_behind_global_flags_is_still_gated() {
    // SKILL.md promises `npm --loglevel silent install x` is still gated:
    // the verb is found behind global flags, and the flag's value is not
    // mistaken for the verb. The gated path prints the "Pre-checking" header;
    // an ungated passthrough would emit no gate output at all.
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "--loglevel", "silent", "install", "freshpkg@9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Pre-checking"),
        "gate must fire behind flags; stdout: {stdout}"
    );
}

#[test]
fn npm_install_aliases_are_gated_not_passed_through() {
    // npm accepts many install aliases (and tolerates the typo `isntall`).
    // Each must route through the GATE, not the ungated passthrough: the gate
    // resolves the package and prints its "Pre-checking" header. An alias that
    // slipped past the gate would reach npm with no gate output.
    for alias in ["isntall", "in", "ins"] {
        let (mut h, registry_hits) = wrapper_with_hits("npm", "CORGEA_NPM_REGISTRY", 0);
        let out = h
            .cmd
            .args(["npm", alias, "freshpkg@9.9.9"])
            .output()
            .expect("failed to run corgea");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Pre-checking"),
            "alias `{alias}` must be gated; stdout: {stdout}"
        );
        assert!(
            registry_hits.load(Ordering::SeqCst) > 0,
            "alias `{alias}`: the gate must resolve the package"
        );
    }
}

#[test]
fn wrapper_forwards_package_manager_exit_code() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 7);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "the package manager's exit code must be forwarded"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
}

// SKILL.md promises "Git/URL/path specs … are noted, never blocked". The
// three tests below pin that end-to-end.

#[test]
fn pip_git_url_spec_skips_verification_and_execs() {
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "git+https://github.com/x/y.git"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install git+https://github.com/x/y.git"),
        "pip must receive the raw spec"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("registry verification skipped"),
        "stdout: {stdout}"
    );
}

#[test]
fn pip_filesystem_path_spec_skips_verification_and_execs() {
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "."])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install ."));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("registry verification skipped"),
        "stdout: {stdout}"
    );
}

#[test]
fn npm_github_shorthand_skips_verification_and_execs() {
    let mut h = GateHarness::new()
        .fake_recorder("npm", 0)
        .vuln_checks(HashMap::new())
        .build();
    let out = h
        .cmd
        .args(["npm", "install", "user/repo"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install user/repo"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("registry verification skipped"),
        "stdout: {stdout}"
    );
}
