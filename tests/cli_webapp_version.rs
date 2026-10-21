//! The compatibility pre-flight is wired into a real command: `corgea` reads
//! `GET /api/version` and warns when the webapp is older than this CLI
//! requires, without ever failing the command. Parsing and comparison live in
//! `version_check`'s unit tests.

mod common;

use common::{corgea_isolated, scans_empty, temp_plain_dir, webapp_version, Hits, Routes};
use std::process::Output;
use std::time::{Duration, Instant};

const MINIMUM: &str = "v1.71.3";

fn spawn_stub(version: Option<String>) -> (String, Hits) {
    common::spawn_resolution_stub(Routes {
        scans: Some(scans_empty()),
        version,
        ..Default::default()
    })
}

/// `corgea list` against `url`, with the floor pinned so the test does not
/// shift when `MIN_WEBAPP_VERSION` is bumped. `--project-name` keeps an empty
/// scan page from being a resolution failure.
fn run_list(url: &str, extra_env: &[(&str, &str)]) -> Output {
    let (tmp, cwd) = temp_plain_dir("proj");
    let (mut cmd, _home) = corgea_isolated();
    cmd.args(["list", "--project-name", "demo"])
        .current_dir(&cwd)
        .env("CORGEA_URL", url)
        .env("CORGEA_TOKEN", "test-token")
        .env("CORGEA_MIN_WEBAPP_VERSION", MINIMUM);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("spawn corgea");
    drop(tmp);
    output
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn an_outdated_webapp_warns_and_still_runs_the_command() {
    let (url, hits) = spawn_stub(Some(webapp_version("v1.70.0")));

    let out = run_list(&url, &[]);
    let stderr = stderr(&out);

    assert!(
        stderr.contains(MINIMUM) && stderr.contains("v1.70.0"),
        "expected a version warning; stderr: {stderr}"
    );
    assert!(
        out.status.success(),
        "the warning must not fail the command"
    );
    assert!(
        hits.lock()
            .unwrap()
            .iter()
            .any(|h| h.starts_with("/api/v1/scans")),
        "the command must still run; hits: {:?}",
        hits.lock().unwrap()
    );
}

#[test]
fn an_unknown_version_does_not_warn() {
    // 404 is a webapp that predates the endpoint. Null is one that could not
    // determine its own version. A 404 must stay silent: the endpoint ships
    // above the floor, so a deployment sitting exactly at it also 404s.
    for version in [None, Some(r#"{"status":"ok","version":null}"#.to_string())] {
        let (url, hits) = spawn_stub(version);
        let out = run_list(&url, &[]);
        let stderr = stderr(&out);

        assert!(
            hits.lock().unwrap().iter().any(|h| h == "/api/version"),
            "the endpoint must be dialed; hits: {:?}",
            hits.lock().unwrap()
        );
        assert!(
            !stderr.contains("requires Corgea webapp"),
            "an unknown version must not warn; stderr: {stderr}"
        );
        assert!(out.status.success());
    }
}

/// Accepts `/api/version` and never replies. One thread per connection, so the
/// hung request cannot block the ones that follow it.
fn spawn_stalling_version_stub() -> String {
    use std::io::Write;
    use std::net::TcpListener;

    let routes = Routes {
        scans: Some(scans_empty()),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let routes = routes.clone();
            std::thread::spawn(move || {
                let buf = corgea::vuln_api_stub::read_http_request(&mut stream);
                let request = String::from_utf8_lossy(&buf);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                if path == "/api/version" {
                    // Long enough that answering at all would fail the elapsed
                    // assertion, so only the per-request timeout can save it.
                    std::thread::sleep(Duration::from_secs(600));
                    return;
                }
                let (status, body) = routes.answer(&path);
                let response = corgea::vuln_api_stub::http_response(status, "", &body);
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    base_url
}

#[test]
fn a_stalled_version_endpoint_does_not_hold_up_the_command() {
    // Without a timeout of its own the pre-flight inherits the shared client's
    // 150s, delaying a command that was ready to run.
    let url = spawn_stalling_version_stub();

    let started = Instant::now();
    let out = run_list(&url, &[]);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(60),
        "the advisory pre-flight held the command for {elapsed:?}"
    );
    assert!(
        out.status.success(),
        "the command must still run; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn the_skip_env_var_silences_the_warning_and_the_request() {
    let (url, hits) = spawn_stub(Some(webapp_version("v1.70.0")));

    let out = run_list(&url, &[("CORGEA_SKIP_WEBAPP_VERSION_CHECK", "1")]);

    assert!(
        !stderr(&out).contains("requires Corgea webapp"),
        "the skip flag must silence the warning; stderr: {}",
        stderr(&out)
    );
    assert!(
        !hits.lock().unwrap().iter().any(|h| h == "/api/version"),
        "the skip flag must also skip the request; hits: {:?}",
        hits.lock().unwrap()
    );
    assert!(out.status.success());
}
