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
    npm_packument, pypi_release_json, spawn_http_stub, GateHarness, NOT_FOUND_JSON, OLD_TS,
    RESOLUTION_FAILS,
};
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
    let h = GateHarness::new();
    let h = match binary {
        "npm" | "pip" => h.fake_tree_pm(binary, RESOLUTION_FAILS, pm_exit_code),
        _ => h.fake_recorder(binary, pm_exit_code),
    };
    (
        h.registry_env(registry_env, &base_url).build(),
        registry_hits,
    )
}

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
fn pip_fresh_pin_blocks_without_running_install() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run when blocked");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refusing to run install"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
fn pip_no_fail_demotes_block_and_installs() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--no-fail", "install", "freshpkg==9.9.9"])
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
        Some("install freshpkg==9.9.9"),
        "--no-fail must still run the install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
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
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
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
fn bare_externally_managed_pip_blocks_before_running_pip() {
    let (mut h, registry_hits) = externally_managed_pip();
    let out = h
        .cmd
        .args(["pip", "install"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "externally-managed preflight must run before registry checks"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: this Python environment is externally managed (PEP 668)."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Create and activate a virtualenv, then retry `corgea pip install`."),
        "stderr: {stderr}"
    );
}

#[test]
fn pip_json_reports_fresh_pin_as_recent() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["results"][0]["status"], "recent");
    assert_eq!(parsed["results"][0]["name"], "freshpkg");
    assert_eq!(parsed["summary"]["recent"], 1);
}

#[test]
fn pip_resolution_error_prints_error_but_install_proceeds() {
    // `nosuchpkg` hits the stub's 404 route → an error outcome, which
    // warns but does not block in public mode (authenticated mode fails
    // closed — see cli_verdict.rs) — the install must still run.
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
fn pip_mixed_fresh_and_old_pins_block_without_running_install() {
    let mut h = wrapper("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "one recent target must block the whole install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
    assert!(stdout.contains("1 ok, 1 recent"), "stdout: {stdout}");
}

#[test]
fn npm_fresh_pin_blocks_without_running_install() {
    let mut h = wrapper("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "freshpkg@9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "npm must not run when blocked");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refusing to run install"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
        std::fs::write(project.path().join("package.json"), r#"{"name":"proj"}"#)
            .expect("write package.json");
        std::fs::write(project.path().join(case.lockfile), case.lock_contents)
            .expect("write lockfile");

        let out = h
            .cmd
            .current_dir(project.path())
            .args(case.args)
            .output()
            .expect("failed to run corgea");

        assert_eq!(out.status.code(), Some(1), "case: {:?}", case.args);
        assert_eq!(h.recorded_argv(), None, "{} must not run", case.run_manager);
        assert_eq!(
            registry_hits.load(Ordering::SeqCst),
            0,
            "wrong-manager guard must run before registry checks"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!(
                "error: this project appears to use {}, but you ran {}.",
                case.expected_manager, case.run_manager
            )),
            "stderr: {stderr}"
        );
        assert!(
            stderr.contains(&format!("Did you mean `{}`?", case.expected_suggestion)),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn package_manager_field_beats_missing_lockfile_for_node_guard() {
    let (mut h, registry_hits) = wrapper_with_hits("npm", "CORGEA_NPM_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"proj","packageManager":"pnpm@9.12.0"}"#,
    )
    .expect("write package.json");

    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    assert_eq!(registry_hits.load(Ordering::SeqCst), 0);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Did you mean `corgea pnpm add oldpkg`?"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn conflicting_node_lockfiles_do_not_block_as_wrong_manager() {
    let (mut h, registry_hits) = wrapper_with_hits("npm", "CORGEA_NPM_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("package.json"), r#"{"name":"proj"}"#)
        .expect("write package.json");
    std::fs::write(project.path().join("package-lock.json"), "{}").expect("write npm lock");
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .expect("write pnpm lock");

    let out = h
        .cmd
        .current_dir(project.path())
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
    assert!(
        registry_hits.load(Ordering::SeqCst) >= 1,
        "the normal install gate should still run"
    );
}

#[test]
fn pip_in_uv_lock_project_blocks_with_uv_add_suggestion() {
    let (mut h, registry_hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("uv.lock"), "version = 1\n").expect("write uv lock");

    let out = h
        .cmd
        .current_dir(project.path())
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    assert_eq!(registry_hits.load(Ordering::SeqCst), 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: this project appears to use uv, but you ran pip."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea uv add oldpkg==1.0.0`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn pip_requirements_in_uv_project_suggests_uv_pip_install() {
    let (mut h, registry_hits) = wrapper_with_hits("pip", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("uv.lock"), "version = 1\n").expect("write uv lock");
    std::fs::write(project.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements");

    let out = h
        .cmd
        .current_dir(project.path())
        .args(["pip", "install", "-r", "requirements.txt"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    assert_eq!(registry_hits.load(Ordering::SeqCst), 0);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("Did you mean `corgea uv pip install -r requirements.txt`?"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn uv_add_in_requirements_project_blocks_with_pip_install_suggestion() {
    let (mut h, registry_hits) = wrapper_with_hits("uv", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements");

    let out = h
        .cmd
        .current_dir(project.path())
        .args(["uv", "add", "oldpkg"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "uv must not run");
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "wrong-manager guard must run before registry checks"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: this project appears to use pip, but you ran uv."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea pip install oldpkg`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn uv_install_blocks_with_uv_pip_install_suggestion_without_running_uv() {
    let (mut h, registry_hits) = wrapper_with_hits("uv", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["uv", "install", "oldpkg"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "uv must not run");
    assert_eq!(
        registry_hits.load(Ordering::SeqCst),
        0,
        "invalid uv command must not touch the registry"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: uv does not support top-level `install`."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea uv pip install oldpkg`?"),
        "stderr: {stderr}"
    );
}

#[test]
fn uv_add_in_pyproject_with_requirements_does_not_guess_pip() {
    let (mut h, registry_hits) = wrapper_with_hits("uv", "CORGEA_PYPI_REGISTRY", 0);
    let project = TempDir::new().expect("project dir");
    std::fs::write(
        project.path().join("pyproject.toml"),
        "[project]\nname = \"proj\"\nversion = \"0.1.0\"\n",
    )
    .expect("write pyproject");
    std::fs::write(project.path().join("requirements.txt"), "oldpkg==1.0.0\n")
        .expect("write requirements");

    let out = h
        .cmd
        .current_dir(project.path())
        .args(["uv", "add", "oldpkg"])
        .output()
        .expect("failed to run corgea");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("add oldpkg"));
    assert!(
        registry_hits.load(Ordering::SeqCst) >= 1,
        "the normal uv add gate should still run"
    );
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
