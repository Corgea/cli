//! Corgea vuln-api client.
//!
//! Deliberately independent of `utils::api::SHARED_CLIENT` because:
//!   * the vuln-api host is user-configurable via `CORGEA_VULN_API_URL`,
//!     so we must never silently replay Corgea cookies / non-JWT
//!     `CORGEA-TOKEN` headers via redirect following or the shared
//!     cookie jar.
//!   * the shared client's `check_for_warnings` exits the process on
//!     HTTP 410, which is wrong for per-dep CVE lookups.
//!
//! The auth header is attached explicitly per call from a caller-owned
//! token (no global state).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::log::debug;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on how much of an error response body we splice into the
/// user-facing error message. Fits a CLI line, captures
/// `{"error":"…"}`-class messages comfortably, and truncates
/// Cloudflare HTML before it gets ugly.
const ERROR_BODY_SNIPPET_LEN: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnCheckResponse {
    pub ecosystem: String,
    pub package_name: String,
    pub version: String,
    pub is_vulnerable: bool,
    pub matches: Vec<VulnMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnMatch {
    pub advisory_id: String,
    pub severity_level: String,
    pub tier: u8,
    pub vulnerable_version_range: Option<String>,
    pub fixed_version: Option<String>,
}

fn user_agent() -> String {
    format!("corgea-cli/{} (vuln-api)", env!("CARGO_PKG_VERSION"))
}

pub fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(user_agent())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("failed to build vuln-api http client: {}", e))
}

fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

fn normalize_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

/// Encode package name for the vuln-api path segment.
/// npm scoped names: `@scope/pkg` → `@scope%2fpkg` (mirrors registry.rs).
fn encode_package_name(ecosystem: &str, name: &str) -> String {
    if ecosystem.eq_ignore_ascii_case("npm") {
        if let Some(stripped) = name.strip_prefix('@') {
            if let Some((scope, pkg)) = stripped.split_once('/') {
                return format!("@{}%2f{}", scope, pkg);
            }
        }
        name.to_string()
    } else {
        urlencoding::encode(name).into_owned()
    }
}

/// Build an authed JSON GET: the standard `Accept` / `CORGEA-SOURCE` headers
/// plus the per-call auth header (JWT → `Authorization: Bearer`, otherwise
/// `CORGEA-TOKEN`). The single place auth is attached, shared by every route.
fn build_authed_get(
    client: &reqwest::blocking::Client,
    url: &str,
    token: &str,
) -> reqwest::blocking::RequestBuilder {
    let mut req = client
        .get(url)
        .header("Accept", "application/json")
        .header("CORGEA-SOURCE", "cli");
    if is_jwt(token) {
        req = req.header("Authorization", format!("Bearer {}", token));
    } else {
        req = req.header("CORGEA-TOKEN", token);
    }
    req
}

/// Validate the per-call preconditions shared by every vuln-api request:
/// a non-empty token and a non-empty (trailing-slash-normalized) base URL.
/// Returns the normalized base so callers don't re-derive it.
fn validated_base(token: &str, base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    if token.is_empty() {
        return Err("missing Corgea token for vuln-api request".into());
    }
    let base = normalize_base_url(base_url);
    if base.is_empty() {
        return Err("vuln-api base URL is empty".into());
    }
    Ok(base)
}

/// Format a server error body into a `": <snippet>"` suffix for a single-line
/// CLI error, or an empty string when the body is empty. Consumes the response.
fn error_body_suffix(response: reqwest::blocking::Response) -> String {
    let body = response.text().unwrap_or_default();
    let snippet = body_snippet(&body, ERROR_BODY_SNIPPET_LEN);
    if snippet.is_empty() {
        String::new()
    } else {
        format!(": {}", snippet)
    }
}

/// Collapse whitespace and truncate at `max_chars` so a server error
/// body can be spliced into a single-line CLI error message without
/// dragging in HTML newlines or runaway length. Returns empty string
/// when the body is empty so the caller can format conditionally.
/// Char-boundary safe — operates on `chars()`, never byte slices.
fn body_snippet(body: &str, max_chars: usize) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return String::new();
    }
    let truncated: String = collapsed.chars().take(max_chars).collect();
    if collapsed.chars().count() > max_chars {
        format!("{}…", truncated)
    } else {
        truncated
    }
}

fn retry_after_seconds(response: &reqwest::blocking::Response) -> u64 {
    response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|s| s.clamp(1, 10))
        .unwrap_or(1)
}

fn send_package_check_with_429_retry(
    client: &reqwest::blocking::Client,
    url: &str,
    token: &str,
) -> Result<reqwest::blocking::Response, Box<dyn std::error::Error>> {
    let response = build_authed_get(client, url, token)
        .send()
        .map_err(|e| format!("Failed to send vuln-api request: {}", e))?;

    if response.status().as_u16() == 429 {
        let wait = retry_after_seconds(&response);
        std::thread::sleep(Duration::from_secs(wait));
        return build_authed_get(client, url, token)
            .send()
            .map_err(|e| format!("Failed to send vuln-api request: {}", e).into());
    }
    Ok(response)
}

pub fn check_package_version(
    client: &reqwest::blocking::Client,
    base_url: &str,
    token: &str,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
    let base = validated_base(token, base_url)?;
    let encoded_name = encode_package_name(ecosystem, name);
    let encoded_version = urlencoding::encode(version);
    let url = format!(
        "{}/v1/packages/{}/{}/versions/{}/check",
        base, ecosystem, encoded_name, encoded_version
    );

    debug(&format!("Sending vuln-api request to URL: {}", url));

    let response = send_package_check_with_429_retry(client, &url, token)?;

    let status = response.status();
    match status.as_u16() {
        401 => {
            return Err(
                "vuln-api rejected the Corgea token (run `corgea login` to refresh)".into(),
            );
        }
        403 => {
            return Err("vuln-api access denied (check your Corgea plan/permissions)".into());
        }
        404 => {
            return Ok(VulnCheckResponse {
                ecosystem: ecosystem.to_string(),
                package_name: name.to_string(),
                version: version.to_string(),
                is_vulnerable: false,
                matches: vec![],
            });
        }
        429 => {
            return Err("vuln-api rate-limited this request (retry later)".into());
        }
        500..=599 => {
            return Err(format!("vuln-api unavailable (HTTP {})", status.as_u16()).into());
        }
        code if !status.is_success() => {
            let suffix = error_body_suffix(response);
            return Err(format!("vuln-api returned unexpected HTTP {}{}", code, suffix).into());
        }
        _ => {}
    }

    let response_text = response.text()?;
    let parsed: VulnCheckResponse = serde_json::from_str(&response_text).map_err(|e| {
        debug(&format!(
            "Failed to parse vuln-api response: {}. Body: {}",
            e, response_text
        ));
        format!("Failed to parse vuln-api response: {}", e)
    })?;

    // Confused-deputy guard: refuse to attribute advisories to a different
    // (name, version, ecosystem) than what we asked about. The server is
    // allowed to be silent on identity, but if it answers, it must match.
    if !parsed.ecosystem.is_empty() && !parsed.ecosystem.eq_ignore_ascii_case(ecosystem) {
        return Err(format!(
            "vuln-api response ecosystem '{}' does not match request '{}'",
            parsed.ecosystem, ecosystem
        )
        .into());
    }
    if !parsed.package_name.is_empty() && !parsed.package_name.eq_ignore_ascii_case(name) {
        return Err(format!(
            "vuln-api response package '{}' does not match request '{}'",
            parsed.package_name, name
        )
        .into());
    }
    if !parsed.version.is_empty() && parsed.version != version {
        return Err(format!(
            "vuln-api response version '{}' does not match request '{}'",
            parsed.version, version
        )
        .into());
    }

    // is_vulnerable=true with no matches is contradictory — treat as an
    // error so the caller can surface it rather than silently demoting
    // the dep to "clean".
    if parsed.is_vulnerable && parsed.matches.is_empty() {
        return Err(
            "vuln-api reported is_vulnerable=true with no matches; refusing to interpret".into(),
        );
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    /// `(ecosystem, name, version)` request key for the stub's route table.
    type CheckKey = (String, String, String);
    /// Maps a request key to a canned `(status, body)` response.
    type KeyedResponses = HashMap<CheckKey, (u16, String)>;

    /// Reason phrase for the stub's status line.
    fn status_text(code: u16) -> &'static str {
        match code {
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500..=599 => "Internal Server Error",
            _ => "Error",
        }
    }

    struct PackageCheckStub {
        base_url: String,
        _handle: thread::JoinHandle<()>,
    }

    /// Keys in `retry_after_keys`: first hit → 429 + Retry-After: 1, second hit →
    /// response from `responses` (or clean 200 fallback).
    fn spawn_package_check_stub_with_retry_keys(
        responses: KeyedResponses,
        retry_after_keys: KeyedResponses,
    ) -> PackageCheckStub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let responses = Arc::new(Mutex::new(responses));
        let retry_after_keys = Arc::new(Mutex::new(retry_after_keys));
        let hit_counts: Arc<Mutex<HashMap<CheckKey, u32>>> = Arc::new(Mutex::new(HashMap::new()));

        let handle = thread::spawn(move || {
            for stream in listener.incoming().take(32) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buf = Vec::with_capacity(4096);
                let mut chunk = [0u8; 1024];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&buf);

                let (status_code, status_text, body, extra_headers) = if let Some(path) =
                    req.lines().next().and_then(|l| l.split_whitespace().nth(1))
                {
                    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                    if parts.len() >= 7
                        && parts[0] == "v1"
                        && parts[1] == "packages"
                        && parts[4] == "versions"
                        && parts[6] == "check"
                    {
                        let eco = parts[2].to_string();
                        let name = urlencoding::decode(parts[3])
                            .unwrap_or_default()
                            .into_owned();
                        let ver = urlencoding::decode(parts[5])
                            .unwrap_or_default()
                            .into_owned();
                        let key = (eco.clone(), name.clone(), ver.clone());
                        let hits = {
                            let mut counts = hit_counts.lock().unwrap();
                            let entry = counts.entry(key.clone()).or_insert(0);
                            *entry += 1;
                            *entry
                        };

                        let retry_body = retry_after_keys.lock().unwrap().get(&key).cloned();
                        if retry_body.is_some() && hits == 1 {
                            let (code, body) = (429, r#"{"error":"rate limited"}"#.to_string());
                            let text = "Too Many Requests";
                            (code, text, body, "Retry-After: 1\r\n".to_string())
                        } else {
                            let (code, body) = responses
                                .lock()
                                .unwrap()
                                .get(&key)
                                .cloned()
                                .or(retry_body)
                                .unwrap_or((200, r#"{"is_vulnerable":false,"matches":[]}"#.into()));
                            (code, status_text(code), body, String::new())
                        }
                    } else {
                        (
                            404,
                            "Not Found",
                            r#"{"error":"not found"}"#.into(),
                            String::new(),
                        )
                    }
                } else {
                    (
                        400,
                        "Bad Request",
                        r#"{"error":"bad request"}"#.into(),
                        String::new(),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                    status_code, status_text, extra_headers, body.len(), body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        thread::sleep(Duration::from_millis(50));
        PackageCheckStub {
            base_url,
            _handle: handle,
        }
    }

    fn check_with_stub_status(
        status_code: u16,
        body: &str,
    ) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
        let client = http_client().expect("test client");
        let mut responses = HashMap::new();
        responses.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            (status_code, body.to_string()),
        );
        let stub = spawn_package_check_stub_with_retry_keys(responses, HashMap::new());
        check_package_version(
            &client,
            &stub.base_url,
            "test-token",
            "npm",
            "lodash",
            "4.17.20",
        )
    }

    #[test]
    fn check_package_version_401_returns_actionable_error() {
        let err = check_with_stub_status(401, r#"{"error":"unauthorized"}"#)
            .expect_err("401 should fail");
        assert!(err.to_string().contains("rejected the Corgea token"));
    }

    #[test]
    fn check_package_version_403_returns_actionable_error() {
        let err =
            check_with_stub_status(403, r#"{"error":"forbidden"}"#).expect_err("403 should fail");
        assert!(err.to_string().contains("access denied"));
    }

    #[test]
    fn check_package_version_404_returns_clean() {
        let resp =
            check_with_stub_status(404, r#"{"error":"not found"}"#).expect("404 should be clean");
        assert!(!resp.is_vulnerable);
        assert!(resp.matches.is_empty());
        assert_eq!(resp.package_name, "lodash");
        assert_eq!(resp.version, "4.17.20");
    }

    #[test]
    fn check_package_version_persistent_429_returns_actionable_error() {
        let err = check_with_stub_status(429, r#"{"error":"rate limited"}"#)
            .expect_err("429 should fail");
        assert!(err.to_string().contains("rate-limited"));
    }

    #[test]
    fn check_package_version_429_retries_then_succeeds() {
        let client = http_client().unwrap();
        let vulnerable_body = r#"{
            "ecosystem": "npm",
            "package_name": "lodash",
            "version": "4.17.20",
            "is_vulnerable": true,
            "matches": [{
                "advisory_id": "GHSA-retry-test",
                "severity_level": "high",
                "tier": 1,
                "vulnerable_version_range": "<4.17.21",
                "fixed_version": "4.17.21"
            }]
        }"#;
        let mut retry_after_keys = HashMap::new();
        retry_after_keys.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            (200, vulnerable_body.to_string()),
        );
        let stub = spawn_package_check_stub_with_retry_keys(HashMap::new(), retry_after_keys);
        let resp = check_package_version(
            &client,
            &stub.base_url,
            "test-token",
            "npm",
            "lodash",
            "4.17.20",
        )
        .expect("retry should succeed");
        assert!(resp.is_vulnerable);
    }

    #[test]
    fn check_package_version_500_returns_unavailable() {
        let err =
            check_with_stub_status(500, r#"{"error":"internal"}"#).expect_err("500 should fail");
        assert!(err.to_string().contains("unavailable (HTTP 500)"));
    }

    #[test]
    fn check_package_version_unexpected_status_includes_body_snippet() {
        let err =
            check_with_stub_status(418, r#"{"error":"teapot"}"#).expect_err("418 should fail");
        let msg = err.to_string();
        assert!(msg.contains("unexpected HTTP 418"), "got: {}", msg);
        assert!(
            msg.contains("teapot"),
            "expected body in error; got: {}",
            msg
        );
    }

    #[test]
    fn check_package_version_unexpected_status_omits_body_when_empty() {
        let err = check_with_stub_status(418, "").expect_err("418 should fail");
        let msg = err.to_string();
        assert!(msg.contains("unexpected HTTP 418"), "got: {}", msg);
        // Body is empty → message must end at the status, no dangling ":" or whitespace.
        assert!(
            msg.trim_end().ends_with("418"),
            "expected message to end at status code; got: {:?}",
            msg
        );
    }

    #[test]
    fn body_snippet_truncates_at_char_boundary() {
        // Multi-byte char ("é" is 2 bytes UTF-8). Naïve byte-slicing would
        // panic; we must operate on chars().
        let input = "é".repeat(500);
        let out = body_snippet(&input, ERROR_BODY_SNIPPET_LEN);
        assert!(out.ends_with('…'), "expected ellipsis; got: {:?}", out);
        // 300 "é" chars + the ellipsis.
        assert_eq!(out.chars().count(), ERROR_BODY_SNIPPET_LEN + 1);
    }

    #[test]
    fn body_snippet_collapses_whitespace() {
        assert_eq!(body_snippet("foo\n  bar\t\tbaz", 100), "foo bar baz");
    }

    #[test]
    fn body_snippet_empty_returns_empty() {
        assert_eq!(body_snippet("", 100), "");
        assert_eq!(body_snippet("   \n\t  ", 100), "");
    }

    #[test]
    fn encode_package_name_scoped_npm() {
        assert_eq!(encode_package_name("npm", "@types/node"), "@types%2fnode");
        assert_eq!(encode_package_name("npm", "lodash"), "lodash");
    }

    #[test]
    fn encode_package_name_pypi() {
        assert_eq!(encode_package_name("PyPI", "requests"), "requests");
    }

    #[test]
    fn encode_package_name_npm_case_insensitive() {
        // Defends against vuln_api_ecosystem() casing changes.
        assert_eq!(encode_package_name("NPM", "@types/node"), "@types%2fnode");
    }

    #[test]
    fn deserialize_vuln_check_response() {
        let body = r#"{
            "ecosystem": "npm",
            "package_name": "lodash",
            "version": "4.17.20",
            "is_vulnerable": true,
            "matches": [{
                "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                "severity_level": "high",
                "tier": 1,
                "vulnerable_version_range": "<4.17.21",
                "fixed_version": "4.17.21"
            }]
        }"#;
        let parsed: VulnCheckResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.is_vulnerable);
        assert_eq!(parsed.matches.len(), 1);
        assert_eq!(parsed.matches[0].advisory_id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(parsed.matches[0].tier, 1);
    }

    #[test]
    fn normalize_base_url_strips_trailing_slash() {
        assert_eq!(
            normalize_base_url("http://localhost:8080/"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn is_jwt_detection() {
        assert!(is_jwt("a.b.c"));
        assert!(!is_jwt("plain-token"));
        assert!(!is_jwt("a.b"));
        assert!(!is_jwt("a..c"));
    }

    // Fixture-based deserialization tests — committed JSON under tests/fixtures/vuln_api/,
    // built to the authoritative server serialization (vuln-api/cve_worker/src/worker.js).
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/vuln_api/",
                $name
            ))
        };
    }

    #[test]
    fn fixture_check_clean_deserializes() {
        let parsed: VulnCheckResponse = serde_json::from_str(fixture!("check_clean.json")).unwrap();
        assert!(!parsed.is_vulnerable);
        assert!(parsed.matches.is_empty());
        assert_eq!(parsed.ecosystem, "pypi");
        assert_eq!(parsed.package_name, "requests");
        assert_eq!(parsed.version, "2.31.0");
    }

    #[test]
    fn fixture_check_unknown_deserializes_as_clean() {
        // /check returns 200 is_vulnerable:false matches:[] for an unknown package;
        // the 404 {"error":"Package not found"} body is the profile route, not /check.
        let parsed: VulnCheckResponse =
            serde_json::from_str(fixture!("check_unknown.json")).unwrap();
        assert!(!parsed.is_vulnerable);
        assert!(parsed.matches.is_empty());
    }

    #[test]
    fn fixture_check_vulnerable_deserializes() {
        let parsed: VulnCheckResponse =
            serde_json::from_str(fixture!("check_vulnerable.json")).unwrap();
        assert!(parsed.is_vulnerable);
        assert_eq!(parsed.matches.len(), 1);
        let m = &parsed.matches[0];
        assert_eq!(m.advisory_id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(m.severity_level, "high");
        assert_eq!(m.tier, 1);
        assert_eq!(m.vulnerable_version_range.as_deref(), Some(">=3.2,<3.2.5"));
        assert_eq!(m.fixed_version.as_deref(), Some("3.2.5"));
    }

    #[test]
    fn fixture_check_malware_deserializes() {
        // Malware surfaces through /check as an ordinary is_vulnerable:true match
        // (MAL-* id); /malware items carry no version, so /check is the per-version signal.
        let parsed: VulnCheckResponse =
            serde_json::from_str(fixture!("check_malware.json")).unwrap();
        assert!(parsed.is_vulnerable);
        assert_eq!(parsed.matches.len(), 1);
        let m = &parsed.matches[0];
        assert!(m.advisory_id.starts_with("MAL-"));
        assert!(m.vulnerable_version_range.is_none());
        assert!(m.fixed_version.is_none());
    }
}
