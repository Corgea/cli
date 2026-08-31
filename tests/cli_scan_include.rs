//! End-to-end coverage for force-include rules: drives the real binary through
//! the blast scan flow against a stubbed HTTP server and asserts that files the
//! packager would normally leave out — `node_modules`, `.gitignore`d paths,
//! `--exclude`d paths — are bundled when `--include` or the project's own
//! include rules name them, and that the rules travel with the upload.

mod common;

use common::corgea_isolated;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Raw bodies of the chunk uploads the CLI sent.
type Uploads = Arc<Mutex<Vec<Vec<u8>>>>;

/// The blast scan route table, answering `/scan-settings` with `include_paths`
/// so a test can exercise the platform-configured rules as well as the flag.
fn spawn_scan_stub(
    scan_id: &'static str,
    project_include_paths: &'static str,
) -> (String, Uploads) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let uploads: Uploads = Default::default();
    let recorder = Arc::clone(&uploads);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let request = corgea::vuln_api_stub::read_http_request(&mut stream);
            let request_line = String::from_utf8_lossy(&request[..request.len().min(1024)])
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let target = request_line.split_whitespace().nth(1).unwrap_or("");
            let path = target.split('?').next().unwrap_or(target);

            let (status, body) = if path == "/api/v1/verify" {
                ("200 OK", r#"{"status":"ok"}"#.to_string())
            } else if path == "/api/v1/scan-settings" {
                (
                    "200 OK",
                    format!(
                        r#"{{"status":"ok","project":null,"settings":{{"include_paths":{},"ignore_paths":[]}}}}"#,
                        project_include_paths
                    ),
                )
            } else if path == "/api/v1/start-scan" {
                ("200 OK", r#"{"transfer_id":"transfer-1"}"#.to_string())
            } else if path == "/api/v1/start-scan/transfer-1/" {
                recorder.lock().unwrap().push(request.clone());
                (
                    "200 OK",
                    format!(r#"{{"scan_id":"{}","project_id":"1"}}"#, scan_id),
                )
            } else if path == format!("/api/v1/scan/{}", scan_id) {
                (
                    "200 OK",
                    format!(
                        r#"{{"id":"{}","project":"proj","repo":null,"branch":null,"status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}}"#,
                        scan_id
                    ),
                )
            } else if path == format!("/api/v1/scan/{}/issues", scan_id) {
                (
                    "200 OK",
                    r#"{"status":"ok","issues":[],"page":1,"total_pages":1,"total_issues":0}"#
                        .to_string(),
                )
            } else {
                ("404 Not Found", r#"{"message":"not found"}"#.to_string())
            };

            let response = corgea::vuln_api_stub::http_response(status, "", &body);
            let _ = stream.write_all(response.as_bytes());
        }
    });

    (base_url, uploads)
}

/// Everything the CLI uploaded, as lossy text. Zip entry names are stored
/// verbatim in each local file header, so searching for a path here proves it
/// was bundled.
fn uploaded_text(uploads: &Uploads) -> String {
    let uploads = uploads.lock().expect("upload log");
    assert!(!uploads.is_empty(), "no chunk upload was recorded");
    uploads
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// A project whose proprietary code sits where Corgea assumes dependencies live.
fn stub_project() -> TempDir {
    let project = TempDir::new().expect("project dir");
    let root = project.path();
    fs::write(root.join("main.py"), "print(1)\n").expect("write source file");
    fs::create_dir_all(root.join("node_modules/internal-sdk")).expect("create vendor dir");
    fs::write(
        root.join("node_modules/internal-sdk/index.js"),
        "module.exports = 1;\n",
    )
    .expect("write force-include candidate");
    fs::create_dir_all(root.join("node_modules/third-party")).expect("create dependency dir");
    fs::write(
        root.join("node_modules/third-party/index.js"),
        "module.exports = 2;\n",
    )
    .expect("write third-party file");
    project
}

fn scan(base_url: &str, project: &TempDir, args: &[&str]) -> std::process::Output {
    let (mut cmd, _home) = corgea_isolated();
    cmd.current_dir(project.path())
        .env("CORGEA_URL", base_url)
        .env("CORGEA_TOKEN", "test-token")
        .arg("scan")
        .args(args);
    let output = cmd.output().expect("run corgea scan");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn include_flag_bundles_a_file_the_default_excludes_would_drop() {
    let (base_url, uploads) = spawn_scan_stub("scan-include-flag", "[]");
    let project = stub_project();

    let output = scan(
        &base_url,
        &project,
        &["--include", "node_modules/internal-sdk/index.js"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Force-including 1 file(s)"),
        "should report what it forced in, got:\n{stdout}"
    );

    let uploaded = uploaded_text(&uploads);
    assert!(
        uploaded.contains("node_modules/internal-sdk/index.js"),
        "the force-included file should be bundled"
    );
    assert!(
        !uploaded.contains("node_modules/third-party/index.js"),
        "other node_modules files stay excluded"
    );
    assert!(uploaded.contains("main.py"), "source files still upload");
    // The server does not know this run's flag values, so they travel with it.
    assert!(
        uploaded.contains(r#"["node_modules/internal-sdk/index.js"]"#),
        "the --include patterns should be sent with the upload"
    );
}

#[test]
fn project_include_rules_from_the_platform_are_applied() {
    let (base_url, uploads) =
        spawn_scan_stub("scan-include-project", r#"["node_modules/internal-sdk"]"#);
    let project = stub_project();

    let output = scan(&base_url, &project, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Applying 1 project include rule(s) from Corgea"),
        "should say the rules came from the platform, got:\n{stdout}"
    );

    let uploaded = uploaded_text(&uploads);
    assert!(uploaded.contains("node_modules/internal-sdk/index.js"));
    assert!(!uploaded.contains("node_modules/third-party/index.js"));
    // Already stored server-side, so nothing to send back.
    assert!(!uploaded.contains(r#"name="include_paths""#));
}

#[test]
fn an_include_rule_overrides_exclude_patterns() {
    let (base_url, uploads) = spawn_scan_stub("scan-include-exclude", "[]");
    let project = stub_project();
    fs::write(project.path().join(".gitignore"), "generated/\n").expect("write gitignore");
    fs::create_dir_all(project.path().join("generated")).expect("create generated dir");
    fs::write(
        project.path().join("generated/Payments.java"),
        "class Payments {}\n",
    )
    .expect("write generated file");

    scan(
        &base_url,
        &project,
        &[
            "--exclude",
            "generated/**",
            "--include",
            "generated/Payments.java",
        ],
    );

    assert!(uploaded_text(&uploads).contains("generated/Payments.java"));
}

#[test]
fn an_include_rule_that_matches_nothing_warns_and_still_scans() {
    let (base_url, uploads) = spawn_scan_stub("scan-include-nomatch", "[]");
    let project = stub_project();

    let output = scan(&base_url, &project, &["--include", "no/such/path.java"]);

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("No files matched your include rules"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(uploaded_text(&uploads).contains("main.py"));
}
