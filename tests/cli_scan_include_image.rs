//! End-to-end coverage for `corgea scan --include-image`: drives the real
//! binary through the blast scan flow against a stubbed HTTP server with a
//! stubbed container CLI, and asserts the exported image archive is bundled
//! into the uploaded project zip under the name the backend greps for
//! (`corgea-image-scanning-*.tar`).

mod common;

use common::{corgea_isolated, write_script};
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Raw bodies of the chunk uploads the CLI sent.
type Uploads = Arc<Mutex<Vec<Vec<u8>>>>;

/// Stub container CLI: reports every image as available locally and writes the
/// archive that `save -o <path> <image>` asks for.
const STUB_ENGINE: &str = r#"#!/bin/sh
if [ "$1" = "image" ]; then
  exit 0
fi
if [ "$1" = "save" ]; then
  printf 'archive of %s' "$4" > "$3"
  exit 0
fi
exit 1
"#;

/// Stub container CLI that has nothing and can't pull.
const BROKEN_ENGINE: &str = "#!/bin/sh\necho 'no such image' 1>&2\nexit 1\n";

/// The blast scan route table (verify -> upload -> poll -> issues), with the
/// upload chunk bodies captured so a test can inspect what was bundled.
fn spawn_recording_scan_stub(scan_id: &'static str) -> (String, Uploads) {
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
/// verbatim in each local file header, so searching for an archive name here
/// proves it was bundled.
fn uploaded_text(uploads: &Uploads) -> String {
    let uploads = uploads.lock().expect("upload log");
    assert!(!uploads.is_empty(), "no chunk upload was recorded");
    uploads
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

fn stub_project() -> TempDir {
    let project = TempDir::new().expect("project dir");
    fs::write(project.path().join("main.py"), "print(1)\n").expect("write source file");
    project
}

/// Commit everything in `dir` so the working tree is clean, which is what makes
/// `--only-uncommitted` resolve to zero files.
fn commit_everything(dir: &std::path::Path) {
    let repo = git2::Repository::init(dir).expect("git init");
    let mut index = repo.index().expect("index");
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .expect("stage files");
    index.write().expect("write index");
    let tree = repo
        .find_tree(index.write_tree().expect("write tree"))
        .expect("find tree");
    let signature = git2::Signature::now("Corgea Test", "test@corgea.app").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
}

#[cfg(unix)]
#[test]
fn scan_include_image_bundles_every_exported_archive() {
    let (base_url, uploads) = spawn_recording_scan_stub("scan-images");
    let project = stub_project();
    let bin = TempDir::new().expect("engine dir");
    write_script(bin.path(), "stub-engine", STUB_ENGINE);

    let (mut cmd, _home) = corgea_isolated();
    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .env("CORGEA_CONTAINER_ENGINE", bin.path().join("stub-engine"))
        .args([
            "scan",
            "--include-image",
            "myapp:1.0",
            "--include-image",
            "ghcr.io/acme/api:2.0",
        ]);

    let output = cmd.output().expect("run corgea scan --include-image");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        stdout.contains("corgea-image-scanning-myapp-1.0.tar")
            && stdout.contains("corgea-image-scanning-ghcr.io-acme-api-2.0.tar"),
        "scan output should name both archives, got:\n{stdout}"
    );

    let uploaded = uploaded_text(&uploads);
    for archive in [
        "corgea-image-scanning-myapp-1.0.tar",
        "corgea-image-scanning-ghcr.io-acme-api-2.0.tar",
    ] {
        assert!(
            uploaded.contains(archive),
            "uploaded zip should contain {archive}"
        );
    }
}

/// An explicit image is a complete scan payload: a clean working tree makes
/// `--only-uncommitted` resolve to zero files, and the scan must still upload the
/// exported archive instead of failing on the empty target.
#[cfg(unix)]
#[test]
fn scan_only_uncommitted_with_include_image_uploads_the_archive() {
    let (base_url, uploads) = spawn_recording_scan_stub("scan-clean-tree");
    let project = stub_project();
    commit_everything(project.path());
    let bin = TempDir::new().expect("engine dir");
    write_script(bin.path(), "stub-engine", STUB_ENGINE);

    let (mut cmd, _home) = corgea_isolated();
    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .env("CORGEA_CONTAINER_ENGINE", bin.path().join("stub-engine"))
        .args(["scan", "--only-uncommitted", "--include-image", "myapp:1.0"]);

    let output = cmd.output().expect("run corgea scan --only-uncommitted");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "image-only scan should succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("only the included container image"),
        "should say the scan covers only the image, got:\n{stderr}"
    );
    assert!(uploaded_text(&uploads).contains("corgea-image-scanning-myapp-1.0.tar"));
}

/// A copy of an archive living in the repository must not ride along: it would put
/// the backend into image-scanning mode on scans that never asked for it.
#[test]
fn scan_excludes_an_archive_checked_into_the_project() {
    let (base_url, uploads) = spawn_recording_scan_stub("scan-stale-archive");
    let project = stub_project();
    fs::write(
        project.path().join("corgea-image-scanning-stale-1.0.tar"),
        "a stale export somebody committed",
    )
    .expect("write stale archive");

    let (mut cmd, _home) = corgea_isolated();
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

    let uploaded = uploaded_text(&uploads);
    assert!(
        !uploaded.contains("corgea-image-scanning-stale-1.0.tar"),
        "a checked-in archive should not be bundled"
    );
    assert!(uploaded.contains("main.py"), "source files still upload");
}

#[cfg(unix)]
#[test]
fn scan_without_include_image_bundles_no_archive() {
    let (base_url, uploads) = spawn_recording_scan_stub("scan-noimages");
    let project = stub_project();

    let (mut cmd, _home) = corgea_isolated();
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

    assert!(!uploaded_text(&uploads).contains("corgea-image-scanning-"));
}

#[cfg(unix)]
#[test]
fn scan_include_image_fails_before_uploading_when_the_image_is_unavailable() {
    let (base_url, uploads) = spawn_recording_scan_stub("scan-missing-image");
    let project = stub_project();
    let bin = TempDir::new().expect("engine dir");
    write_script(bin.path(), "broken-engine", BROKEN_ENGINE);

    let (mut cmd, _home) = corgea_isolated();
    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .env("CORGEA_CONTAINER_ENGINE", bin.path().join("broken-engine"))
        .args(["scan", "--include-image", "myapp:1.0"]);

    let output = cmd.output().expect("run corgea scan --include-image");
    assert_eq!(
        output.status.code(),
        Some(1),
        "clean exit 1, not a panic (101)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("myapp:1.0"),
        "stderr should name the image, got:\n{stderr}"
    );
    assert!(
        uploads.lock().unwrap().is_empty(),
        "nothing should be uploaded when the image can't be exported"
    );
}

#[test]
fn scan_include_image_rejects_an_unusable_reference() {
    let (base_url, _uploads) = spawn_recording_scan_stub("scan-bad-ref");
    let project = stub_project();

    let (mut cmd, _home) = corgea_isolated();
    cmd.current_dir(project.path())
        .env("CORGEA_URL", &base_url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["scan", "--include-image", "  "]);

    let output = cmd.output().expect("run corgea scan --include-image");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--include-image"));
}
