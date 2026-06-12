//! Command-surface tests for install wrappers: leading package-manager flags,
//! invalid install-like commands, project guards, and pip environment guard.

#![cfg(unix)]

mod common;

use common::{
    corgea_isolated, spawn_oldpkg_registry_stub, write_fake_recorder, write_fake_tree_pm,
    write_script, RESOLUTION_FAILS,
};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

struct SurfaceHarness {
    cmd: Command,
    marker: PathBuf,
    project: TempDir,
    _home: TempDir,
    _bin: TempDir,
}

impl SurfaceHarness {
    fn new(binary: &str) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin");
        let project = TempDir::new().expect("temp project");
        let marker = bin.path().join("pm-argv.txt");
        match binary {
            "pip" | "npm" => write_fake_tree_pm(bin.path(), binary, &marker, RESOLUTION_FAILS, 0),
            _ => write_fake_recorder(bin.path(), binary, &marker, 0),
        }
        let registry = spawn_oldpkg_registry_stub();
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_NPM_REGISTRY", &registry)
            .current_dir(project.path());
        Self {
            cmd,
            marker,
            project,
            _home: home,
            _bin: bin,
        }
    }

    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

#[test]
fn wrapper_help_is_corgea_help_not_package_manager_help() {
    let mut h = SurfaceHarness::new("npm");
    let out = h.cmd.args(["npm", "--help"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage: corgea npm"), "stdout: {stdout}");
}

#[test]
fn npm_leading_package_manager_flags_are_forwarded_and_install_is_gated() {
    let mut h = SurfaceHarness::new("npm");
    let out = h
        .cmd
        .args([
            "npm",
            "--loglevel",
            "silent",
            "install",
            "oldpkg@1.0.0",
            "--save-dev",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("--loglevel silent install oldpkg@1.0.0 --save-dev")
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Pre-checking"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn pip_add_is_refused_with_install_suggestion() {
    let mut h = SurfaceHarness::new("pip");
    let out = h
        .cmd
        .args(["pip", "add", "oldpkg"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("corgea pip install"), "stderr: {stderr}");
}

#[test]
fn top_level_pip3_is_refused_with_pip_suggestion() {
    let mut h = SurfaceHarness::new("pip");
    let out = h
        .cmd
        .args(["pip3", "install", "oldpkg"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("corgea pip"), "stderr: {stderr}");
}

#[test]
fn uv_install_is_refused_with_uv_pip_install_suggestion() {
    let mut h = SurfaceHarness::new("uv");
    let out = h
        .cmd
        .args(["uv", "install", "oldpkg"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("corgea uv pip install"), "stderr: {stderr}");
}

#[test]
fn npm_in_pnpm_project_is_refused_with_suggestion() {
    let mut h = SurfaceHarness::new("npm");
    std::fs::write(
        h.project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: 9\n",
    )
    .expect("write pnpm lock");
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("corgea pnpm add"), "stderr: {stderr}");
}

#[test]
fn pip_externally_managed_environment_blocks_without_override() {
    let mut h = SurfaceHarness::new("pip");
    h.cmd.env("CORGEA_PIP_EXTERNALLY_MANAGED", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("externally managed Python environment"),
        "stderr: {stderr}"
    );
}

#[test]
fn pip_externally_managed_environment_allows_explicit_target() {
    let mut h = SurfaceHarness::new("pip");
    h.cmd.env("CORGEA_PIP_EXTERNALLY_MANAGED", "1");
    let out = h
        .cmd
        .args(["pip", "install", "--target", "./vendor", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install --target ./vendor oldpkg==1.0.0")
    );
}

#[test]
fn json_install_keeps_package_manager_stdout_off_stdout() {
    let (mut cmd, home) = corgea_isolated();
    let bin = TempDir::new().expect("temp bin");
    let project = TempDir::new().expect("temp project");
    let marker = bin.path().join("pm-argv.txt");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) exit 2;; esac\nprintf 'pm stdout\\n'\nprintf 'pm stderr\\n' >&2\nprintf '%s' \"$*\" > '{}'\nexit 0\n",
        marker.display()
    );
    write_script(bin.path(), "pip", &script);
    let registry = spawn_oldpkg_registry_stub();
    cmd.env("PATH", bin.path())
        .env("CORGEA_PYPI_REGISTRY", &registry)
        .current_dir(project.path());

    let out = cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout JSON");
    assert!(!stdout.contains("pm stdout"), "stdout: {stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("pm stdout"), "stderr: {stderr}");
    assert!(stderr.contains("pm stderr"), "stderr: {stderr}");
    assert_eq!(
        std::fs::read_to_string(marker).ok().as_deref(),
        Some("install oldpkg==1.0.0")
    );
    drop(home);
}
