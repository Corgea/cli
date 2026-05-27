use std::process::Command;
use tempfile::TempDir;

fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("CORGEA_TOKEN")
        .env_remove("CORGEA_URL");
    (cmd, home)
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn cli_scan_runs_without_token_or_config() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("python-poetry"),
            "--out-format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed.get("findings").is_some());
}

#[test]
fn cli_scan_does_not_write_outside_home() {
    let (mut cmd, home) = corgea_isolated();
    cmd.args(["deps", "scan", &fixture("node-app")])
        .output()
        .expect("failed to run corgea");
    assert!(home.path().exists());
}

#[test]
fn cli_scan_fail_on_high_exits_one() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--fail-on", "high"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn cli_scan_clean_fixture_fail_on_high_exits_zero() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("python-poetry"),
            "--fail-on",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn cli_deps_without_subcommand_exits_nonzero() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["deps"]).output().expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn cli_scan_out_file_writes_json() {
    let (mut cmd, home) = corgea_isolated();
    let out_file = home.path().join("deps.json");
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("java-gradle"),
            "--out-format",
            "json",
            "--out-file",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read_to_string(&out_file).expect("out-file should exist");
    let _: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
}
