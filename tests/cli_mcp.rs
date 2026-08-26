//! End-to-end coverage for `corgea mcp install`.
//!
//! The binary is required to refuse an unauthenticated run (same gate as
//! `scan` / `skill`), then — with a stubbed `/api/v1/verify` — write the
//! agent JSON using the URL and token from config.

mod common;

use common::{corgea_isolated, spawn_http_stub};
use serde_json::Value;
use std::fs;

fn spawn_verify_stub() -> String {
    spawn_http_stub(|path| {
        let p = path.split('?').next().unwrap_or(path);
        if p == "/api/v1/verify" {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else {
            ("404 Not Found", r#"{"message":"not found"}"#.to_string())
        }
    })
}

#[test]
fn mcp_install_without_token_exits_like_other_commands() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["mcp", "install", "--agent", "cursor"])
        .output()
        .expect("run corgea mcp install");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr.contains("No token set."),
        "unauthenticated mcp install must use the shared login gate: {stderr}"
    );
}

#[test]
fn mcp_install_rejects_unknown_agent_after_auth() {
    let base_url = spawn_verify_stub();
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["mcp", "install", "--agent", "not-an-agent"])
        .output()
        .expect("run corgea mcp install");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(1));
    assert!(stderr.contains("Unsupported agent"), "stderr was: {stderr}");
    assert!(stderr.contains("cursor"), "stderr was: {stderr}");
}

#[test]
fn mcp_install_writes_cursor_config_from_stored_url_and_token() {
    let base_url = spawn_verify_stub();
    let (mut cmd, home) = corgea_isolated();
    let out = cmd
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "cli-token")
        .args(["mcp", "install", "--agent", "cursor"])
        .output()
        .expect("run corgea mcp install");

    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let path = home.path().join(".cursor/mcp.json");
    let body = fs::read_to_string(&path).expect("cursor mcp.json");
    let v: Value = serde_json::from_str(&body).expect("valid json");
    let args = v["mcpServers"]["corgea"]["args"]
        .as_array()
        .expect("args array");
    let expected_url = format!("{base_url}/mcp");
    assert!(
        args.iter()
            .any(|a| a.as_str() == Some(expected_url.as_str())),
        "expected MCP url {expected_url} in {body}"
    );
    assert!(
        args.iter()
            .any(|a| a.as_str() == Some("CORGEA-TOKEN:cli-token")),
        "expected stored token in {body}"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Installed Corgea MCP"),
        "stdout was: {stdout}"
    );
}

#[test]
fn mcp_install_reinstalls_to_refresh_url_and_token() {
    let base_url = spawn_verify_stub();
    let (mut first, home) = corgea_isolated();
    let path = home.path().join(".cursor/mcp.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{
  "mcpServers": {
    "other": { "command": "echo" },
    "corgea": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://old.corgea.app/mcp", "--header", "CORGEA-TOKEN:stale"]
    }
  }
}
"#,
    )
    .unwrap();

    let out = first
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "fresh-token")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .args(["mcp", "install", "--agent", "cursor"])
        .output()
        .expect("run corgea mcp install");

    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let body = fs::read_to_string(&path).expect("cursor mcp.json");
    let v: Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(v["mcpServers"]["other"]["command"], "echo");
    let args = v["mcpServers"]["corgea"]["args"]
        .as_array()
        .expect("args array");
    assert!(args
        .iter()
        .any(|a| a.as_str() == Some("CORGEA-TOKEN:fresh-token")));
    assert!(!body.contains("stale"));
    assert!(!body.contains("old.corgea.app"));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Updated Corgea MCP"),
        "stdout was: {stdout}"
    );
}

#[test]
fn mcp_install_claude_writes_desktop_env_block() {
    let base_url = spawn_verify_stub();
    let (mut cmd, home) = corgea_isolated();
    let custom = home.path().join("claude_desktop_config.json");
    let out = cmd
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "desktop-token")
        .args([
            "mcp",
            "install",
            "--agent",
            "claude",
            "--dir",
            custom.to_str().unwrap(),
        ])
        .output()
        .expect("run corgea mcp install --agent claude");

    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let v: Value = serde_json::from_str(&fs::read_to_string(&custom).unwrap()).unwrap();
    assert_eq!(
        v["mcpServers"]["corgea"]["env"]["CORGEA_TOKEN"],
        "desktop-token"
    );
}

#[test]
fn mcp_help_lists_install() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["mcp", "--help"]).output().expect("mcp help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("install"), "help was: {stdout}");
    assert!(stdout.contains("MCP"), "help was: {stdout}");
}
