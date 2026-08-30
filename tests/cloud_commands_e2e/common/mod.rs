use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub(crate) const TOKEN: &str = "opaque-test-token";
pub(crate) const SOURCE_BODY: &str = "print(\"cloud contract\")\n";
pub(crate) const REPORT_BODY: &str =
    r#"{"version":"semgrep.dev/v1","results":[{"path":"src/main.py"}]}"#;

#[derive(Debug, Clone)]
pub(crate) struct CapturedRequest {
    method: Method,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

pub(crate) type RequestCheck = dyn Fn(&CapturedRequest) -> Result<(), String> + Send;

pub(crate) struct ExpectedRequest {
    label: &'static str,
    check: Box<RequestCheck>,
    status: StatusCode,
    body: String,
}

pub(crate) struct ApiState {
    expected: VecDeque<ExpectedRequest>,
    captured: Vec<CapturedRequest>,
    failures: Vec<String>,
}

pub(crate) struct ApiStub {
    base_url: String,
    state: Arc<Mutex<ApiState>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl ApiStub {
    pub(crate) fn start(expected: Vec<ExpectedRequest>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind API stub");
        listener
            .set_nonblocking(true)
            .expect("make API listener nonblocking");
        let base_url = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("API listener address").port()
        );
        let state = Arc::new(Mutex::new(ApiState {
            expected: expected.into(),
            captured: Vec::new(),
            failures: Vec::new(),
        }));
        let server_state = Arc::clone(&state);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build API stub runtime");
            runtime.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("adopt API listener");
                let mut shutdown_rx = shutdown_rx;
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.expect("accept API connection");
                            let state = Arc::clone(&server_state);
                            tokio::task::spawn(async move {
                                let service_state = Arc::clone(&state);
                                let service = service_fn(move |request| {
                                    handle_request(request, Arc::clone(&service_state))
                                });
                                if let Err(error) = http1::Builder::new()
                                    .serve_connection(TokioIo::new(stream), service)
                                    .await
                                {
                                    let mut state = state.lock().expect("lock API state");
                                    state.failures.push(format!(
                                        "failed to serve API connection: {error}"
                                    ));
                                }
                            });
                        }
                    }
                }
            });
        });

        Self {
            base_url,
            state,
            shutdown: Some(shutdown),
            server: Some(server),
        }
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn transcript(&self) -> String {
        let state = self.state.lock().expect("lock API transcript");
        format_transcript(&state.captured)
    }

    pub(crate) fn assert_finished(mut self) -> String {
        self.stop();
        let state = self.state.lock().expect("lock finished API state");
        let remaining = state
            .expected
            .iter()
            .map(|request| request.label)
            .collect::<Vec<_>>();
        let transcript = format_transcript(&state.captured);
        assert!(
            state.failures.is_empty() && remaining.is_empty(),
            "API contract did not finish\nfailures:\n{}\nremaining: {:?}\ntranscript:\n{}",
            state.failures.join("\n"),
            remaining,
            transcript
        );
        transcript
    }

    pub(crate) fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.join().expect("join API stub");
        }
    }
}

impl Drop for ApiStub {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

pub(crate) async fn handle_request(
    request: Request<Incoming>,
    state: Arc<Mutex<ApiState>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await?.to_bytes().to_vec();
    let captured = CapturedRequest {
        method: parts.method,
        target: parts
            .uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string()),
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value
                        .to_str()
                        .map(str::to_string)
                        .unwrap_or_else(|_| format!("{value:?}")),
                )
            })
            .collect(),
        body,
    };

    let (status, body) = {
        let mut state = state.lock().expect("lock API request state");
        state.captured.push(captured.clone());
        match state.expected.pop_front() {
            Some(expected) => match (expected.check)(&captured) {
                Ok(()) => (expected.status, expected.body),
                Err(error) => {
                    state
                        .failures
                        .push(format!("{}: {}", expected.label, error));
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"status": "error", "message": error}).to_string(),
                    )
                }
            },
            None => {
                let error = format!(
                    "unexpected extra request: {} {}",
                    captured.method, captured.target
                );
                state.failures.push(error.clone());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"status": "error", "message": error}).to_string(),
                )
            }
        }
    };

    Ok(Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("build API response"))
}

pub(crate) fn expected_request<F>(
    label: &'static str,
    check: F,
    response: (StatusCode, String),
) -> ExpectedRequest
where
    F: Fn(&CapturedRequest) -> Result<(), String> + Send + 'static,
{
    ExpectedRequest {
        label,
        check: Box::new(check),
        status: response.0,
        body: response.1,
    }
}

pub(crate) fn json_response(body: Value) -> (StatusCode, String) {
    (StatusCode::OK, body.to_string())
}

pub(crate) fn json_response_with_status(status: StatusCode, body: Value) -> (StatusCode, String) {
    (status, body.to_string())
}

pub(crate) fn target_path_and_query(target: &str) -> (&str, Vec<(String, String)>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    (path, query)
}

pub(crate) fn assert_method_and_path(
    request: &CapturedRequest,
    method: Method,
    path: &str,
) -> Result<(), String> {
    let (actual_path, _) = target_path_and_query(&request.target);
    if request.method != method {
        return Err(format!("expected method {method}, got {}", request.method));
    }
    if actual_path != path {
        return Err(format!("expected path {path}, got {actual_path}"));
    }
    Ok(())
}

pub(crate) fn assert_opaque_auth(request: &CapturedRequest) -> Result<(), String> {
    match header_value(request, "corgea-token") {
        Some(value) if value == TOKEN => Ok(()),
        Some(value) => Err(format!("expected CORGEA-TOKEN {TOKEN}, got {value}")),
        None => Err("missing CORGEA-TOKEN header".to_string()),
    }
}

pub(crate) fn assert_authenticated_request(
    request: &CapturedRequest,
    method: Method,
    path: &str,
) -> Result<(), String> {
    assert_method_and_path(request, method, path)?;
    assert_opaque_auth(request)
}

pub(crate) fn assert_query(
    request: &CapturedRequest,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let (_, query) = target_path_and_query(&request.target);
    match query.iter().find(|(name, _)| name == key) {
        Some((_, value)) if value == expected => Ok(()),
        Some((_, value)) => Err(format!("expected query {key}={expected}, got {value}")),
        None => Err(format!("missing query field {key}")),
    }
}

pub(crate) fn assert_scan_list_request(
    request: &CapturedRequest,
    project: &str,
) -> Result<(), String> {
    assert_authenticated_request(request, Method::GET, "/api/v1/scans")?;
    assert_query(request, "page", "1")?;
    assert_query(request, "page_size", "30")?;
    assert_query(request, "project", project)
}

/// One baseline lookup an incremental scan makes before uploading.
///
/// Asserting the filters is the point: they keep this to one request per trunk
/// branch instead of a page walk, and a server dropping them silently returns
/// pull-request and dirty scans for the client to reject. `branch` is asserted
/// because a baseline may only come from trunk.
pub(crate) fn assert_baseline_lookup_request(
    request: &CapturedRequest,
    project: &str,
    branch: &str,
) -> Result<(), String> {
    assert_scan_list_request(request, project)?;
    assert_query(request, "engine", "corgea-blast")?;
    assert_query(request, "status", "complete")?;
    assert_query(request, "exclude_pull_requests", "true")?;
    assert_query(request, "worktree_dirty", "false")?;
    assert_query(request, "full_project_state", "true")?;
    assert_query(request, "branch", branch)
}

pub(crate) fn query_value(request: &CapturedRequest, key: &str) -> Result<String, String> {
    let (_, query) = target_path_and_query(&request.target);
    query
        .into_iter()
        .find_map(|(name, value)| (name == key).then_some(value))
        .ok_or_else(|| format!("missing query field {key}"))
}

pub(crate) fn assert_body_contains(
    request: &CapturedRequest,
    expected: &[u8],
) -> Result<(), String> {
    if request
        .body
        .windows(expected.len())
        .any(|window| window == expected)
    {
        Ok(())
    } else {
        Err(format!(
            "request body does not contain {:?}",
            String::from_utf8_lossy(expected)
        ))
    }
}

pub(crate) fn header_value<'a>(request: &'a CapturedRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn assert_content_type(request: &CapturedRequest, expected: &str) -> Result<(), String> {
    match header_value(request, "content-type") {
        Some(value) if value.starts_with(expected) => Ok(()),
        Some(value) => Err(format!("expected content type {expected}, got {value}")),
        None => Err("missing Content-Type header".to_string()),
    }
}

pub(crate) fn assert_header(
    request: &CapturedRequest,
    name: &str,
    expected: &str,
) -> Result<(), String> {
    match header_value(request, name) {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(format!("expected header {name}: {expected}, got {value}")),
        None => Err(format!("missing {name} header")),
    }
}

pub(crate) fn assert_multipart_text_field(
    request: &CapturedRequest,
    name: &str,
    value: &str,
) -> Result<(), String> {
    let expected = format!("name=\"{name}\"\r\n\r\n{value}\r\n");
    if request
        .body
        .windows(expected.len())
        .any(|window| window == expected.as_bytes())
    {
        Ok(())
    } else {
        Err(format!("missing multipart field {name}={value:?}"))
    }
}

/// Proves a field was left off the form entirely. Some fields are only safe in
/// pairs, so "absent" is as much the contract as any value.
pub(crate) fn assert_no_multipart_field(
    request: &CapturedRequest,
    name: &str,
) -> Result<(), String> {
    let needle = format!("name=\"{name}\"");
    if request
        .body
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
    {
        return Err(format!("unexpected multipart field {name}"));
    }
    Ok(())
}

pub(crate) fn format_transcript(requests: &[CapturedRequest]) -> String {
    if requests.is_empty() {
        return "<no requests>".to_string();
    }
    requests
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let preview_len = request.body.len().min(512);
            let preview = String::from_utf8_lossy(&request.body[..preview_len]);
            format!(
                "{}. {} {}\nheaders: {:?}\nbody ({} bytes): {}{}",
                index + 1,
                request.method,
                request.target,
                request.headers,
                request.body.len(),
                preview,
                if request.body.len() > preview_len {
                    "…"
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn run_with_timeout(mut command: Command, api: &ApiStub) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn corgea");
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        if child.try_wait().expect("poll corgea").is_some() {
            return child.wait_with_output().expect("collect corgea output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("reap timed-out corgea");
            panic!(
                "corgea timed out\nstatus: {}\nstdout:\n{}\nstderr:\n{}\nAPI transcript:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                api.transcript(),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn output_context(output: &Output, transcript: &str) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}\nAPI transcript:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        transcript
    )
}

pub(crate) fn parse_output_json(output: &Output, transcript: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "failed to parse CLI stdout as JSON: {error}\n{}",
            output_context(output, transcript)
        )
    })
}

pub(crate) fn cloud_command(api: &ApiStub, path: &Path) -> (Command, TempDir) {
    let (mut command, home) = crate::repo_common::corgea_isolated();
    command
        .current_dir(path)
        .env("CORGEA_TOKEN", TOKEN)
        .env("CORGEA_URL", api.base_url());
    (command, home)
}

pub(crate) struct ReportProject {
    root: TempDir,
    report_path: PathBuf,
}

pub(crate) struct GitProject {
    root: TempDir,
    pub(crate) sha: String,
}

impl GitProject {
    pub(crate) fn path(&self) -> &Path {
        self.root.path()
    }
}

impl ReportProject {
    pub(crate) fn path(&self) -> &Path {
        self.root.path()
    }

    pub(crate) fn report_path(&self) -> &Path {
        &self.report_path
    }
}

pub(crate) fn report_project() -> ReportProject {
    let root = TempDir::new().expect("create report project");
    let source_dir = root.path().join("src");
    std::fs::create_dir(&source_dir).expect("create source directory");
    std::fs::write(source_dir.join("main.py"), SOURCE_BODY).expect("write source");
    let report_path = root.path().join("semgrep.json");
    std::fs::write(&report_path, REPORT_BODY).expect("write report");
    ReportProject { root, report_path }
}

pub(crate) fn git_project() -> GitProject {
    let root = TempDir::new().expect("create Git project");
    for args in [
        vec!["init"],
        vec!["config", "user.email", "cloud-e2e@example.com"],
        vec!["config", "user.name", "Cloud E2E"],
        vec!["checkout", "-b", "e2e-main"],
        vec![
            "remote",
            "add",
            "origin",
            "https://github.com/corgea/cloud-e2e.git",
        ],
    ] {
        run_git(root.path(), &args);
    }
    std::fs::write(root.path().join("main.py"), SOURCE_BODY).expect("write Git source");
    run_git(root.path(), &["add", "main.py"]);
    run_git(root.path(), &["commit", "-m", "fixture"]);
    let output = run_git(root.path(), &["rev-parse", "HEAD"]);
    let sha = String::from_utf8(output.stdout)
        .expect("UTF-8 Git SHA")
        .trim()
        .to_string();
    assert_eq!(sha.len(), 40, "expected full Git SHA, got {sha}");
    GitProject { root, sha }
}

pub(crate) fn run_git(path: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub(crate) fn temp_project_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 temp project name")
        .to_string()
}

pub(crate) fn verify_request() -> ExpectedRequest {
    expected_request(
        "verify token",
        |request| assert_authenticated_request(request, Method::GET, "/api/v1/verify"),
        json_response(json!({"status": "ok"})),
    )
}

pub(crate) fn scan_response(scan_id: &str, project: &str, status: &str) -> Value {
    json!({
        "id": scan_id,
        "project": project,
        "repo": null,
        "branch": null,
        "status": status,
        "engine": "semgrep",
        "created_at": "2026-07-30T12:00:00Z",
        "git_sha": null
    })
}

pub(crate) fn scans_response(scans: Vec<Value>) -> Value {
    json!({
        "status": "ok",
        "page": 1,
        "total_pages": 1,
        "scans": scans
    })
}

pub(crate) fn regular_issue(issue_id: &str, scan_id: &str, project: &str, urgency: &str) -> Value {
    json!({
        "id": issue_id,
        "scan_id": scan_id,
        "status": "open",
        "urgency": urgency,
        "created_at": "2026-07-30T12:00:00Z",
        "classification": {
            "id": format!("class-{issue_id}"),
            "name": format!("{urgency} test issue"),
            "description": null
        },
        "location": {
            "file": {
                "name": "main.py",
                "language": "python",
                "path": "src/main.py"
            },
            "line_number": 7,
            "project": {
                "name": project,
                "branch": null,
                "git_sha": null
            }
        },
        "details": null,
        "auto_triage": {
            "false_positive_detection": {
                "status": "not_started",
                "reasoning": null
            }
        },
        "auto_fix_suggestion": null
    })
}

pub(crate) fn regular_issue_page(scan_id: &str, project: &str) -> Value {
    let issues = vec![
        regular_issue("issue-cr", scan_id, project, "CR"),
        regular_issue("issue-hi-1", scan_id, project, "HI"),
        regular_issue("issue-hi-2", scan_id, project, "HI"),
        regular_issue("issue-me", scan_id, project, "ME"),
    ];
    json!({
        "status": "ok",
        "issues": issues,
        "page": 1,
        "total_pages": 1,
        "total_issues": 4
    })
}

pub(crate) fn empty_issue_page() -> Value {
    json!({
        "status": "ok",
        "issues": [],
        "page": 1,
        "total_pages": 1,
        "total_issues": 0
    })
}

pub(crate) fn malicious_sca_issue_page() -> Value {
    json!({
        "status": "ok",
        "issues": [{
            "id": "sca-malicious-1",
            "created_at": "2026-07-30T12:00:00Z",
            "description": "malicious dependency",
            "details": null,
            "severity": "critical",
            "classification": "malicious",
            "cve": null,
            "package": {
                "name": "bad-package",
                "version": "1.0.0",
                "ecosystem": "npm",
                "fix_version": null
            },
            "location": {
                "path": "package-lock.json"
            }
        }],
        "page": 1,
        "total_pages": 1,
        "total_issues": 1
    })
}

pub(crate) fn upload_plan(scan_id: &str, project_id: i64) -> Vec<ExpectedRequest> {
    let run_id = Arc::new(Mutex::new(None::<String>));
    let code_run_id = Arc::clone(&run_id);
    let scan_run_id = Arc::clone(&run_id);
    vec![
        verify_request(),
        expected_request(
            "upload referenced source",
            move |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/code-upload")?;
                assert_query(request, "path", "src/main.py")?;
                assert_content_type(request, "multipart/form-data")?;
                assert_body_contains(request, SOURCE_BODY.as_bytes())?;
                let value = query_value(request, "run_id")?;
                *code_run_id.lock().expect("lock upload run ID") = Some(value);
                Ok(())
            },
            json_response(json!({"status": "ok"})),
        ),
        expected_request(
            "upload report",
            move |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/scan-upload")?;
                assert_query(request, "engine", "semgrep")?;
                assert_query(request, "project", "upload-contract")?;
                assert_query(request, "ci", "false")?;
                assert_query(request, "ci_platform", "unknown")?;
                assert_content_type(request, "application/json")?;
                assert_body_contains(request, REPORT_BODY.as_bytes())?;
                let value = query_value(request, "run_id")?;
                let expected = scan_run_id
                    .lock()
                    .expect("lock upload run ID")
                    .clone()
                    .ok_or_else(|| "source upload did not capture run_id".to_string())?;
                if value != expected {
                    return Err(format!(
                        "scan upload run_id {value} does not match source upload {expected}"
                    ));
                }
                let (_, query) = target_path_and_query(&request.target);
                if query.iter().any(|(key, _)| key == "repo_data") {
                    return Err("unexpected repo_data query field".to_string());
                }
                Ok(())
            },
            json_response(json!({
                "status": "ok",
                "sast_scan_id": scan_id,
                "project_id": project_id
            })),
        ),
    ]
}

pub(crate) fn append_wait_plan(
    expected: &mut Vec<ExpectedRequest>,
    project: &str,
    scan_id: &str,
    statuses: &[&str],
) {
    for (index, status) in statuses.iter().enumerate() {
        let path = format!("/api/v1/scan/{scan_id}");
        let body = scan_response(scan_id, project, status);
        expected.push(expected_request(
            if index == 0 {
                "read initial scan status"
            } else {
                "poll scan status"
            },
            move |request| assert_authenticated_request(request, Method::GET, &path),
            json_response(body),
        ));
    }

    let issue_path = format!("/api/v1/scan/{scan_id}/issues");
    expected.push(expected_request(
        "read completed scan issues",
        move |request| {
            assert_authenticated_request(request, Method::GET, &issue_path)?;
            assert_query(request, "page", "1")?;
            assert_query(request, "page_size", "30")
        },
        json_response(regular_issue_page(scan_id, project)),
    ));
}

pub(crate) fn assert_issue_summary(stdout: &str, context: &str) {
    for (urgency, count) in [("CR", 1), ("HI", 2), ("ME", 1), ("LO", 0)] {
        let row = format!("{urgency:<20} | {count}");
        assert!(stdout.contains(&row), "missing {row:?}\n{context}");
    }
    let total = format!("{:<20} | 4", "Total");
    assert!(stdout.contains(&total), "missing {total:?}\n{context}");
}

pub(crate) fn blast_plan(sha: &str) -> Vec<ExpectedRequest> {
    blast_upload_plan(sha, false, true)
}

/// BLAST upload contract. `include_sca` covers `--fail-on malicious` (SCA fetch).
pub(crate) fn blast_upload_plan(sha: &str, dirty: bool, include_sca: bool) -> Vec<ExpectedRequest> {
    let patch_sha = sha.to_string();
    let dirty_value = if dirty { "true" } else { "false" }.to_string();
    let patch_path = "/api/v1/start-scan/transfer-123/".to_string();
    let detail_path = "/api/v1/scan/blast-scan-123".to_string();
    let issue_path = "/api/v1/scan/blast-scan-123/issues".to_string();
    let mut plan = vec![verify_request()];
    // Scans are incremental by default, so every clean-tree run looks for a
    // baseline before uploading -- once per trunk branch, since the fixture
    // records no origin/HEAD. Answering with no scans keeps this the full-scan
    // contract: nothing to diff from, no incremental fields on the upload. A
    // dirty tree never asks.
    if !dirty {
        for branch in ["main", "master"] {
            plan.push(expected_request(
                "look up a baseline scan to diff against",
                move |request| assert_baseline_lookup_request(request, "cloud-e2e", branch),
                json_response(scans_response(Vec::new())),
            ));
        }
    }
    plan.extend([
        expected_request(
            "start BLAST upload",
            |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/start-scan")?;
                assert_query(request, "scan_type", "blast")?;
                assert_content_type(request, "multipart/form-data")
            },
            json_response(json!({"transfer_id": "transfer-123"})),
        ),
        expected_request(
            "upload BLAST archive",
            move |request| {
                assert_authenticated_request(request, Method::PATCH, &patch_path)?;
                assert_query(request, "scan_type", "blast")?;
                assert_content_type(request, "multipart/form-data")?;
                assert_header(request, "upload-offset", "0")?;
                assert_header(request, "upload-name", "cloud-e2e.zip")?;
                let upload_length = header_value(request, "upload-length")
                    .ok_or_else(|| "missing Upload-Length header".to_string())?;
                let parsed_length = upload_length
                    .parse::<u64>()
                    .map_err(|error| format!("invalid Upload-Length {upload_length}: {error}"))?;
                if parsed_length == 0 {
                    return Err("Upload-Length must be positive".to_string());
                }
                assert_multipart_text_field(request, "file_size", upload_length)?;
                assert_multipart_text_field(request, "project_name", "cloud-e2e")?;
                assert_multipart_text_field(request, "branch", "e2e-main")?;
                assert_multipart_text_field(
                    request,
                    "repo_url",
                    "https://github.com/corgea/cloud-e2e.git",
                )?;
                assert_multipart_text_field(request, "sha", &patch_sha)?;
                assert_multipart_text_field(request, "dirty", &dirty_value)?;
                assert_body_contains(request, b"name=\"chunk_data\"")
            },
            json_response(json!({
                "scan_id": "blast-scan-123",
                "project_id": 91
            })),
        ),
        expected_request(
            "read completed BLAST scan",
            move |request| assert_authenticated_request(request, Method::GET, &detail_path),
            json_response(scan_response("blast-scan-123", "cloud-e2e", "complete")),
        ),
        expected_request(
            "read regular BLAST issues",
            move |request| {
                assert_authenticated_request(request, Method::GET, &issue_path)?;
                assert_query(request, "page", "1")?;
                assert_query(request, "page_size", "30")
            },
            json_response(empty_issue_page()),
        ),
    ]);
    if include_sca {
        let sca_path = "/api/v1/scan/blast-scan-123/issues/sca".to_string();
        plan.push(expected_request(
            "read malicious SCA issues",
            move |request| {
                assert_authenticated_request(request, Method::GET, &sca_path)?;
                assert_query(request, "page", "1")?;
                assert_query(request, "page_size", "30")
            },
            json_response(malicious_sca_issue_page()),
        ));
    }
    plan
}
