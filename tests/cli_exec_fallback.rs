//! Hermetic e2e tests for package-manager binary resolution: the pip→pip3
//! fallback and the missing-binary error (exit 127).
//!
//! Same harness shape as `cli_install.rs`: the real `corgea` binary, a local
//! TcpListener stub standing in for PyPI, and a controlled `PATH` dir that
//! either holds a fake `pip3` (recording its argv to a marker file) or
//! nothing at all. Unix-only — the fake manager is a shell script.

#![cfg(unix)]

mod common;

use common::GateHarness;

#[test]
fn pip_install_falls_back_to_pip3_when_pip_missing() {
    let mut h = GateHarness::new()
        .fake_recorder("pip3", 0)
        .oldpkg_registry()
        .build();
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install oldpkg==1.0.0"),
        "the install must run via pip3 with forwarded args"
    );
}

#[test]
fn pip_passthrough_falls_back_to_pip3() {
    let mut h = GateHarness::new()
        .fake_recorder("pip3", 0)
        .oldpkg_registry()
        .build();
    let out = h.cmd.args(["pip", "list"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("list"));
}

#[test]
fn pip_missing_both_pip_and_pip3_exits_127_with_message() {
    let mut h = GateHarness::new().oldpkg_registry().build();
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(127));
    assert_eq!(h.recorded_argv(), None, "nothing must have run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: 'pip' not found on PATH (also tried 'pip3')"),
        "stderr: {stderr}"
    );
}

#[test]
fn pip3_top_level_command_prints_pip_wrapper_suggestion() {
    let mut h = GateHarness::new()
        .fake_recorder("pip3", 0)
        .oldpkg_registry()
        .build();
    let out = h
        .cmd
        .args(["pip3", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip3 must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: unknown package manager `pip3`."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Did you mean `corgea pip install oldpkg==1.0.0`?"),
        "stderr: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn npm_missing_binary_error_names_binary_without_fallback() {
    let mut h = GateHarness::new().oldpkg_registry().build();
    let out = h.cmd.args(["npm", "list"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: 'npm' not found on PATH"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("also tried"),
        "npm has no fallback alias; stderr: {stderr}"
    );
}
