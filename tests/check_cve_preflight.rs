mod common;

use common::cve_integration_lock;
use std::path::PathBuf;
use std::process::Command;

fn npm_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/deps/npm")
}

#[test]
fn check_cve_preflight_exits_two_without_token() {
    let _lock = cve_integration_lock();
    let output = Command::new(env!("CARGO_BIN_EXE_corgea"))
        .args([
            "deps",
            "verify",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            npm_fixture_dir().to_str().unwrap(),
        ])
        .env("CORGEA_TOKEN", "")
        .env_remove("CORGEA_CONFIG")
        .env("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1")
        .output()
        .expect("spawn corgea");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Corgea token"),
        "expected token requirement in stderr, got: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "preflight should not print a report; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn check_cve_preflight_exits_two_with_whitespace_token() {
    let _lock = cve_integration_lock();
    let output = Command::new(env!("CARGO_BIN_EXE_corgea"))
        .args([
            "deps",
            "verify",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            npm_fixture_dir().to_str().unwrap(),
        ])
        .env("CORGEA_TOKEN", "   ")
        .env_remove("CORGEA_CONFIG")
        .env("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1")
        .output()
        .expect("spawn corgea");

    assert_eq!(output.status.code(), Some(2));
}
