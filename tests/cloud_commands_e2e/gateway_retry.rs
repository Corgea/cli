//! The CLI's answer to intermittent `502 Bad Gateway` from the proxy in front
//! of Corgea: replay the request on a fixed schedule instead of failing the
//! pipeline, and exit non-zero only once the retries are spent — but only for
//! the requests a second copy of is harmless. A `POST` is a create, and the
//! proxy cannot say whether the API committed the first one, so those are sent
//! once and the 502 goes to the caller.
//!
//! The stub's plan is ordered and rejects unexpected requests, so these tests
//! pin the exact attempt count as well as the outcome — a retry loop that runs
//! twice over (or not at all) fails the plan rather than passing quietly.

use crate::common::*;
use hyper::{Method, StatusCode};

/// The pauses are 10s/30s/50s in production; a run under test cannot spend 90
/// seconds, so it retries on the same schedule compressed to milliseconds.
const FAST_RETRIES: (&str, &str) = ("DEBUG_CORGEA_OVERRIDE_RETRY_DELAYS_MS", "50,50,50");

/// The retry budget: three replays, so four attempts in all.
const ATTEMPTS: usize = 4;

/// What a gateway returns when it cannot reach the API: HTML, not the JSON
/// envelope the endpoints parse.
fn bad_gateway() -> (StatusCode, String) {
    (
        StatusCode::BAD_GATEWAY,
        "<html><head><title>502 Bad Gateway</title></head><body>502 Bad Gateway</body></html>"
            .to_string(),
    )
}

fn rejected_scan_read(scan_id: &'static str) -> ExpectedRequest {
    let path = format!("/api/v1/scan/{scan_id}");
    expected_request(
        "reject the scan read with a gateway error",
        move |request| assert_authenticated_request(request, Method::GET, &path),
        bad_gateway(),
    )
}

#[test]
fn wait_rides_out_a_gateway_blip_on_the_scan_read() {
    let project = tempfile::TempDir::new().expect("create wait project");
    let local_project = temp_project_name(project.path());
    let scan_id = "flaky-gateway-scan";
    let mut plan = vec![verify_request()];
    plan.push(rejected_scan_read(scan_id));
    plan.push(rejected_scan_read(scan_id));
    append_wait_plan(&mut plan, &local_project, scan_id, &["complete"]);
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["wait", scan_id]);

    let output = run_with_timeout(command, &api);
    // Every planned request was made and none beyond them: the two 502s were
    // replayed, and the scan read that followed was not.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Scan has been processed successfully!"),
        "{context}"
    );
    // The retries are reported, so a pipeline log shows a ridden-out blip
    // rather than an unexplained pause.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("502 Bad Gateway"), "{context}");
    assert!(stderr.contains("Retrying in"), "{context}");
    assert!(!stderr.contains("Giving up"), "{context}");
}

#[test]
fn wait_exits_unclean_once_the_retries_are_spent() {
    let project = tempfile::TempDir::new().expect("create wait project");
    let scan_id = "down-gateway-scan";
    let mut plan = vec![verify_request()];
    for _ in 0..ATTEMPTS {
        plan.push(rejected_scan_read(scan_id));
    }
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["wait", scan_id]);

    let output = run_with_timeout(command, &api);
    // Exactly four attempts: a fifth would be an unexpected request, and a
    // third would leave one planned request unserved.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("502 Bad Gateway"), "{context}");
    assert!(stderr.contains("Giving up"), "{context}");
    assert!(
        stderr.contains(&format!("Unable to read scan '{scan_id}'")),
        "{context}"
    );
}

#[test]
fn a_rejected_scan_start_is_not_sent_again() {
    // The incident this guards: `POST /start-scan` mints a transfer, and the
    // 502 the proxy returns is also what it returns after the API committed one
    // and the reply was lost. Replaying it was turning a single `corgea scan`
    // into a scan per attempt in the project.
    let project = git_project();
    let mut plan = vec![verify_request()];
    for branch in ["main", "master"] {
        plan.push(expected_request(
            "look up a baseline scan to diff against",
            move |request| assert_baseline_lookup_request(request, "cloud-e2e", branch),
            json_response(scans_response(Vec::new())),
        ));
    }
    plan.push(expected_request(
        "reject the scan start with a gateway error",
        |request| assert_authenticated_request(request, Method::POST, "/api/v1/start-scan"),
        bad_gateway(),
    ));
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let output = run_with_timeout(command, &api);
    // A second start-scan would be an unexpected request, and the stub fails
    // the plan on it.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_ne!(output.status.code(), Some(0), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Retrying in"), "{context}");
}

#[test]
fn a_rejected_source_upload_stops_the_whole_upload_walk() {
    // A source upload is a `POST`, so the 502 is the answer rather than the
    // start of a schedule. It is also the platform being unavailable rather
    // than something wrong with this one file, so the paths behind it must not
    // each collect the same answer: with two referenced sources, a walk that
    // kept going would ask for two uploads instead of one.
    let project = two_source_report_project();
    let plan = vec![
        verify_request(),
        expected_request(
            "reject the source upload with a gateway error",
            |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/code-upload")?;
                // Whichever of the two sources is walked first: the point is
                // how many uploads are attempted, not their order.
                let path = query_value(request, "path")?;
                if !path.starts_with("src/") {
                    return Err(format!("unexpected upload path {path}"));
                }
                Ok(())
            },
            bad_gateway(),
        ),
    ];
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args([
        "upload",
        project.report_path().to_str().expect("UTF-8 report path"),
        "--project-name",
        "upload-contract",
    ]);

    let output = run_with_timeout(command, &api);
    // A second upload would be either a replay of the first file or the walk
    // reaching the next one, and the stub rejects it as unexpected.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The file that was never attempted is still reported as unsent, so the
    // summary cannot read as a single bad file.
    assert!(stderr.contains("2 of 2 files were not sent"), "{context}");
    assert!(
        stderr.contains("Failed to upload any files for the scan"),
        "{context}"
    );
}

#[test]
fn blast_upload_replays_an_archive_chunk_the_gateway_rejects() {
    // The upload bodies are streamed multipart forms, which cannot be replayed
    // from a built request — this is what proves the form is rebuilt, since the
    // planned chunk request that follows asserts every field of it.
    let project = git_project();
    let mut plan = blast_upload_plan(&project.sha, false, false);
    // `blast_upload_plan` order: verify, two baseline lookups, the start-scan
    // POST, then the chunk PATCH this rejects once before letting it through.
    const ARCHIVE_UPLOAD: usize = 4;
    plan.insert(
        ARCHIVE_UPLOAD,
        expected_request(
            "reject the archive chunk with a gateway error",
            |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )
            },
            bad_gateway(),
        ),
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan Completed Successfully"), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("502 Bad Gateway"), "{context}");
}
