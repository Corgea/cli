//! End-to-end coverage for `corgea scan --sbom`: drives the real binary
//! through the blast scan flow (token verify -> upload -> poll -> issues)
//! against a stubbed HTTP server, then asserts the CycloneDX SBOM the
//! scanner generates locally afterwards (src/scanners/blast.rs, near the
//! end of `run`).

mod common;

use common::{corgea_isolated, spawn_http_stub};
use std::fs;
use tempfile::TempDir;

/// Route table for a minimal successful blast scan:
/// - `GET  /api/v1/verify`                       -> token ok
/// - `POST /api/v1/start-scan`                   -> hands back a transfer id
/// - `PATCH /api/v1/start-scan/<id>/`            -> single chunk completes upload, returns scan_id
/// - `GET  /api/v1/scan/<scan_id>`                -> status complete
/// - `GET  /api/v1/scan/<scan_id>/issues*`         -> empty issues page (report_scan_status)
fn spawn_scan_stub(scan_id: &'static str) -> String {
    spawn_http_stub(move |path| {
        let p = path.split('?').next().unwrap_or(path);
        if p == "/api/v1/verify" {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if p == "/api/v1/start-scan" {
            ("200 OK", r#"{"transfer_id":"transfer-1"}"#.to_string())
        } else if p == "/api/v1/start-scan/transfer-1/" {
            (
                "200 OK",
                format!(r#"{{"scan_id":"{}","project_id":"1"}}"#, scan_id),
            )
        } else if p == format!("/api/v1/scan/{}", scan_id) {
            (
                "200 OK",
                format!(
                    r#"{{"id":"{}","project":"proj","repo":null,"branch":null,"status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}}"#,
                    scan_id
                ),
            )
        } else if p == format!("/api/v1/scan/{}/issues", scan_id) {
            (
                "200 OK",
                r#"{"status":"ok","issues":[],"page":1,"total_pages":1,"total_issues":0}"#
                    .to_string(),
            )
        } else {
            ("404 Not Found", r#"{"message":"not found"}"#.to_string())
        }
    })
}

/// Project dir with a small node package + lockfile, matching the shapes in
/// `tests/fixtures/node-app`, so the SBOM has real component content.
fn write_node_project(dir: &std::path::Path) {
    fs::write(
        dir.join("package.json"),
        r#"{
  "name": "node-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2"
  }
}
"#,
    )
    .expect("write package.json");

    fs::write(
        dir.join("package-lock.json"),
        r#"{
  "name": "node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "node-app",
      "version": "1.0.0",
      "dependencies": { "express": "^4.18.2" }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    }
  }
}
"#,
    )
    .expect("write package-lock.json");
}

/// `--sbom` with no value writes the default `bom.json`, with real
/// CycloneDX content sourced from the project's npm lockfile.
#[test]
fn scan_sbom_default_filename_writes_cyclonedx_bom() {
    let base_url = spawn_scan_stub("scan-default");
    let (mut cmd, _home) = corgea_isolated();
    let project = TempDir::new().expect("project dir");
    write_node_project(project.path());

    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["scan", "--sbom"]);

    let output = cmd.output().expect("run corgea scan --sbom");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let bom_path = project.path().join("bom.json");
    assert!(bom_path.exists(), "expected default bom.json to be written");

    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bom_path).expect("read bom.json"))
            .expect("bom.json must be valid JSON");

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.7");
    let components = bom["components"].as_array().expect("components array");
    assert!(
        components.iter().any(|c| c["purl"]
            .as_str()
            .is_some_and(|p| p.starts_with("pkg:npm/"))),
        "expected at least one npm component, got: {}",
        bom["components"]
    );
}

/// `--sbom <file>` honors a custom output path.
#[test]
fn scan_sbom_custom_filename() {
    let base_url = spawn_scan_stub("scan-custom");
    let (mut cmd, _home) = corgea_isolated();
    let project = TempDir::new().expect("project dir");
    write_node_project(project.path());

    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["scan", "--sbom", "custom-sbom.json"]);

    let output = cmd
        .output()
        .expect("run corgea scan --sbom custom-sbom.json");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let bom_path = project.path().join("custom-sbom.json");
    assert!(bom_path.exists(), "expected custom-sbom.json to be written");
    assert!(
        !project.path().join("bom.json").exists(),
        "default bom.json should not be written when a custom name is given"
    );

    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bom_path).expect("read custom-sbom.json"))
            .expect("custom-sbom.json must be valid JSON");
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.7");
}

/// An unwritable `--sbom` path fails with a clean error and exit 1, not a panic.
#[test]
fn scan_sbom_unwritable_path_errors_cleanly() {
    let base_url = spawn_scan_stub("scan-badpath");
    let (mut cmd, _home) = corgea_isolated();
    let project = TempDir::new().expect("project dir");
    write_node_project(project.path());

    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["scan", "--sbom", "missing-dir/bom.json"]);

    let output = cmd
        .output()
        .expect("run corgea scan --sbom missing-dir/bom.json");
    assert_eq!(
        output.status.code(),
        Some(1),
        "clean exit 1, not a panic (101)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to write SBOM"),
        "stderr should name the write failure, got:\n{stderr}"
    );
}

/// Without `--sbom`, no bom file is produced anywhere in the project.
#[test]
fn scan_without_sbom_flag_writes_no_bom_file() {
    let base_url = spawn_scan_stub("scan-none");
    let (mut cmd, _home) = corgea_isolated();
    let project = TempDir::new().expect("project dir");
    write_node_project(project.path());

    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["scan"]);

    let output = cmd.output().expect("run corgea scan");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(!project.path().join("bom.json").exists());
}
