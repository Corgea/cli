//! The CLI's answer to the two statuses that are not Corgea rejecting a request
//! on its merits: retry on a fixed schedule instead of failing the pipeline, and
//! exit non-zero only once the retries are spent.
//!
//! Which requests get that retry depends on which status it is. A `429` is the
//! rate limiter declining the request before the API sees it, so every method is
//! sent again, writes included. A `502` comes from the proxy, which cannot say
//! whether the API acted, so only reads are replayed and a write's 502 goes
//! straight to the caller.
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

fn too_many_requests() -> (StatusCode, String) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        r#"{"message":"rate limit exceeded"}"#.to_string(),
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
fn a_rate_limited_scan_start_goes_through_on_a_retry() {
    // The upload bodies are streamed multipart forms, which cannot be replayed
    // from a request that was already built — so this also proves the form is
    // rebuilt per attempt, since the planned start-scan that follows asserts
    // every field of it.
    let project = git_project();
    let mut plan = blast_upload_plan(&project.sha, false, false);
    // `blast_upload_plan` order: verify, two baseline lookups, the start-scan
    // POST this rate-limits twice before letting through, then the chunk PATCH.
    const SCAN_START: usize = 3;
    for _ in 0..2 {
        plan.insert(
            SCAN_START,
            expected_request(
                "rate-limit the scan start",
                |request| assert_authenticated_request(request, Method::POST, "/api/v1/start-scan"),
                too_many_requests(),
            ),
        );
    }
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    // A rate limit never reached the API, so re-sending the create finishes the
    // one scan rather than starting another.
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan Completed Successfully"), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("429 Too Many Requests"), "{context}");
    assert!(stderr.contains("Retrying in"), "{context}");
    assert!(!stderr.contains("Giving up"), "{context}");
}

#[test]
fn an_exhausted_rate_limit_stops_the_whole_source_upload_walk() {
    // The retries are spent on the platform declining to take uploads, not on
    // one file, so the paths behind it must not each spend the schedule again:
    // with two referenced sources that would be eight uploads instead of four.
    let project = two_source_report_project();
    let mut plan = vec![verify_request()];
    for _ in 0..ATTEMPTS {
        plan.push(expected_request(
            "rate-limit the source upload",
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
            too_many_requests(),
        ));
    }
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
    // A fifth upload would be the second file starting the schedule again, and
    // the stub rejects it as unexpected.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Giving up"), "{context}");
    // The file that was never attempted is still reported as unsent, so the
    // summary cannot read as a single bad file.
    assert!(stderr.contains("2 of 2 files were not sent"), "{context}");
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
fn a_rejected_archive_chunk_is_not_sent_again() {
    // The archive chunk names the byte range it fills, so a replay would not
    // double the bytes. It is excluded anyway: the chunk that fills the last of
    // `Upload-Length` is the one that answers with `scan_id`, and an archive
    // under the 50 MB chunk size — which this fixture, and most repos, is — has
    // only that one chunk. Replaying it risks the second scan.
    let project = git_project();
    // `blast_upload_plan` order: verify, two baseline lookups, the start-scan
    // POST, then the chunk PATCH. Everything from the chunk on is dropped,
    // since the rejected chunk ends the command.
    let mut plan = blast_upload_plan(&project.sha, false, false);
    const ARCHIVE_UPLOAD: usize = 4;
    plan.truncate(ARCHIVE_UPLOAD);
    plan.push(expected_request(
        "reject the archive chunk with a gateway error",
        |request| {
            assert_authenticated_request(request, Method::PATCH, "/api/v1/start-scan/transfer-123/")
        },
        bad_gateway(),
    ));
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.env(FAST_RETRIES.0, FAST_RETRIES.1);
    command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let output = run_with_timeout(command, &api);
    // A second chunk would be an unexpected request, and the stub fails the
    // plan on it.
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_ne!(output.status.code(), Some(0), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Retrying in"), "{context}");
}
