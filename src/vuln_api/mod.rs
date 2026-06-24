//! Corgea vuln-api client.
//!
//! Deliberately separate from `utils::api::SHARED_CLIENT`, not duplication
//! by accident: the vuln-api host is user-configurable via
//! `CORGEA_VULN_API_URL`, so this client must never silently replay Corgea
//! credentials there — cookies, or the non-JWT `CORGEA-TOKEN` header — via
//! redirect following or the shared cookie jar. It uses no cookie jar,
//! follows no redirects, and returns HTTP errors instead of exiting on 410
//! like the shared client. `public_check_sends_no_auth_headers` guards the
//! no-silent-credential invariant.
//!
//! The auth header is attached explicitly per call from a caller-owned
//! token (no global state); `token: None` is the public, unauthenticated
//! mode (sufficient against staging, which runs
//! `VULN_API_REQUIRE_AUTH=false`; the production /check route requires a
//! token). A token is never sent to a user-configured host without
//! explicit opt-in.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

use crate::log::debug;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on how much of an error response body we splice into the
/// user-facing error message. Fits a CLI line, captures
/// `{"error":"…"}`-class messages comfortably, and truncates
/// Cloudflare HTML before it gets ugly.
const ERROR_BODY_SNIPPET_LEN: usize = 300;

/// Registry ecosystem a package check targets. Typed so the URL path
/// segment and the per-ecosystem name encoding can't drift apart on a
/// string spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    pub fn path_segment(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
        }
    }

    /// Canonical package name for IDENTITY COMPARISONS: PEP 503 for pypi
    /// (shared with `deps`), verbatim for npm. The server lowercases every
    /// ecosystem for lookup (worker.js `normalizePackageName`) and the
    /// identity check below compares case-insensitively, so npm casing is
    /// not load-bearing. Not the wire spelling — see `request_name`.
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Ecosystem::Npm => name.to_string(),
            Ecosystem::Pypi => crate::deps::ecosystems::pypi::normalize_pypi_name(name),
        }
    }

    /// Wire spelling for the request path. The server normalizes lookups
    /// with lowercase + trim only (worker.js `normalizePackageName`), NOT
    /// PEP 503 — collapsing `zope.interface` to `zope-interface` here
    /// would miss the stored advisory row and read a vulnerable package
    /// as clean. Match the server's rule exactly.
    pub fn request_name(self, name: &str) -> String {
        match self {
            Ecosystem::Npm => name.to_string(),
            Ecosystem::Pypi => name.trim().to_lowercase(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
    pub tier: Option<u8>,
    pub vulnerable_version_range: Option<String>,
    pub fixed_version: Option<String>,
}

/// `corgea-cli/<version> (<label>)` user-agent string.
pub(crate) fn user_agent(label: &str) -> String {
    format!("corgea-cli/{} ({label})", env!("CARGO_PKG_VERSION"))
}

/// Build (once) and clone the shared vuln-api client. A blocking reqwest
/// client owns a runtime thread, and a gate run checks many packages —
/// cache it. `Client` clones share the same pool, so the clone is cheap.
pub fn http_client() -> Result<reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::blocking::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .user_agent(user_agent("vuln-api"))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| format!("failed to build vuln-api http client: {}", e))
        })
        .clone()
}

/// Whether `token` looks like a JWT (three non-empty dot-separated parts).
fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

/// The auth header for a Corgea token: JWT → `Authorization: Bearer`,
/// otherwise the opaque `CORGEA-TOKEN` header. The one definition of the
/// header shape, shared with the binary crate's `utils/api.rs`.
pub fn auth_header(token: &str) -> (&'static str, String) {
    if is_jwt(token) {
        ("Authorization", format!("Bearer {token}"))
    } else {
        ("CORGEA-TOKEN", token.to_string())
    }
}

/// URL-encode an npm package name for a URL path segment. Scoped names
/// (`@scope/pkg`) keep the readable `@…%2f…` shape, but every component is
/// percent-encoded so a name carrying other reserved characters can't break
/// out of its path segment (pypi already encodes the whole segment).
pub(crate) fn encode_npm_name(name: &str) -> String {
    if let Some(stripped) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = stripped.split_once('/') {
            return format!(
                "@{}%2f{}",
                urlencoding::encode(scope),
                urlencoding::encode(pkg)
            );
        }
    }
    urlencoding::encode(name).into_owned()
}

/// Encode package name for the vuln-api path segment.
/// npm scoped names: `@scope/pkg` → `@scope%2fpkg`.
fn encode_package_name(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Npm => encode_npm_name(name),
        Ecosystem::Pypi => urlencoding::encode(name).into_owned(),
    }
}

/// Value for the `CORGEA-SOURCE` header: the `CORGEA_SOURCE` env override,
/// otherwise `cli`. Read once and cached, then borrowed (no per-request
/// clone) — it's attached per request from concurrent pool workers, and
/// `std::env::var` takes the process-global env lock.
pub fn source() -> &'static str {
    static SOURCE: OnceLock<String> = OnceLock::new();
    SOURCE
        .get_or_init(|| std::env::var("CORGEA_SOURCE").unwrap_or_else(|_| "cli".to_string()))
        .as_str()
}

/// Build a JSON GET: the standard `Accept` / `CORGEA-SOURCE` headers plus,
/// when present, the per-call auth header (JWT → `Authorization: Bearer`,
/// otherwise `CORGEA-TOKEN`). The single place auth is attached, shared by
/// every route.
fn build_json_get(
    client: &reqwest::blocking::Client,
    url: &str,
    token: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let mut req = client
        .get(url)
        .header("Accept", "application/json")
        .header("CORGEA-SOURCE", source());
    if let Some(token) = token {
        let (name, value) = auth_header(token);
        req = req.header(name, value);
    }
    req
}

/// Validate the per-call preconditions shared by every vuln-api request:
/// a non-empty (trailing-slash-normalized) base URL. Returns the normalized
/// base so callers don't re-derive it.
fn validated_base(base_url: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let base = base_url.trim_end_matches('/');
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

/// Send the package-check GET, retrying transient failures within a single
/// budget of `MAX_SENDS` sends total:
///   * any `send()` error (connect, reset, timeout) retries up to twice with
///     500ms / 1500ms backoff — the request is an idempotent GET, so a
///     blanket retry is safe and simpler than classifying error kinds;
///   * HTTP 429 honors `Retry-After` (clamped 1–10s) and retries once, then
///     surfaces the 429 to the caller's status mapping.
///
/// The sleeps block the calling verdict-pool worker thread. Deliberate:
/// bounded at ≤3 sends and ≤2 sleeps per package, that costs less at CLI
/// scale than a non-blocking reschedule would in queue machinery.
fn send_package_check_with_retry(
    client: &reqwest::blocking::Client,
    url: &str,
    token: Option<&str>,
) -> Result<reqwest::blocking::Response, Box<dyn std::error::Error>> {
    const MAX_SENDS: usize = 3;
    const SEND_ERROR_BACKOFF: [Duration; 2] =
        [Duration::from_millis(500), Duration::from_millis(1500)];

    let mut rate_limit_retried = false;
    let mut sends = 0;
    loop {
        sends += 1;
        match build_json_get(client, url, token).send() {
            Ok(response) => {
                if response.status().as_u16() == 429 && !rate_limit_retried && sends < MAX_SENDS {
                    rate_limit_retried = true;
                    std::thread::sleep(Duration::from_secs(retry_after_seconds(&response)));
                    continue;
                }
                return Ok(response);
            }
            Err(e) if sends < MAX_SENDS => {
                debug(&format!(
                    "vuln-api send failed (attempt {}/{}), retrying: {}",
                    sends, MAX_SENDS, e
                ));
                std::thread::sleep(SEND_ERROR_BACKOFF[sends - 1]);
            }
            Err(e) => return Err(format!("Failed to send vuln-api request: {}", e).into()),
        }
    }
}

/// One HTTP request per `(name, version)`. A 1000-package lockfile makes
/// 1000 requests (through the verdict pool's bounded concurrency); the
/// future optimization is a server-side batch endpoint, not client tricks.
pub fn check_package_version(
    client: &reqwest::blocking::Client,
    base_url: &str,
    token: Option<&str>,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
    let base = validated_base(base_url)?;
    // The server keys advisories by lowercase+trim of the canonical
    // registry spelling and normalizes lookups the same way — it does
    // NOT apply PEP 503 (worker.js `normalizePackageName`). Sending a
    // PEP 503-collapsed name would miss dotted/underscored canonical
    // names (`zope.interface`) and read them as clean. The client owns
    // request-time normalization so no caller can forget it; PEP 503 is
    // reserved for the identity comparison below.
    let name = &ecosystem.request_name(name);
    let encoded_name = encode_package_name(ecosystem, name);
    let encoded_version = urlencoding::encode(version);
    let url = format!(
        "{}/v1/packages/{}/{}/versions/{}/check",
        base,
        ecosystem.path_segment(),
        encoded_name,
        encoded_version
    );

    debug(&format!("Sending vuln-api request to URL: {}", url));

    let response = send_package_check_with_retry(client, &url, token)?;

    let status = response.status();
    // Fixed messages for recognized statuses — tests assert these strings,
    // keep them stable. The /check route answers 200 (empty matches) for
    // unknown packages; a 404 can only mean a wrong base URL or route, and
    // treating it as "clean" would silently disable the gate on a
    // misconfigured endpoint.
    match status.as_u16() {
        401 if token.is_some() => {
            return Err(
                "vuln-api rejected the Corgea token (run `corgea login` to refresh)".into(),
            );
        }
        401 => return Err("vuln-api requires authentication".into()),
        403 => return Err("vuln-api access denied (check your Corgea plan/permissions)".into()),
        429 => return Err("vuln-api rate-limited this request (retry later)".into()),
        code @ 500..=599 => return Err(format!("vuln-api unavailable (HTTP {})", code).into()),
        404 => {
            return Err("vuln-api route not found (HTTP 404) — check CORGEA_VULN_API_URL".into());
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
            e,
            body_snippet(&response_text, ERROR_BODY_SNIPPET_LEN)
        ));
        format!("Failed to parse vuln-api response: {}", e)
    })?;

    // Confused-deputy guard: refuse to attribute advisories to a different
    // (name, version, ecosystem) than what we asked about. The current
    // server echoes ecosystem/name/version verbatim from the request path
    // (worker.js `packageVersionCheckCliHandler`), so this can only fire on
    // a tampering or misbehaving intermediary — defense in depth, not a live
    // server contract. Comparisons stay case-insensitive to tolerate a
    // future server that echoes a stored spelling/casing instead.
    if !parsed.ecosystem.is_empty()
        && !parsed
            .ecosystem
            .eq_ignore_ascii_case(ecosystem.path_segment())
    {
        return Err(format!(
            "vuln-api response ecosystem '{}' does not match request '{}'",
            parsed.ecosystem,
            ecosystem.path_segment()
        )
        .into());
    }
    // Apply the ecosystem's canonical-name rule (PEP 503) to BOTH sides
    // before comparing: `name` carries the wire spelling (dots/underscores
    // preserved), and a response that echoes the registry/stored spelling
    // (`flask_cors` for a `flask-cors` request, PEP 503-equivalent) must
    // not be a hard failure — that would fail the gate closed for valid
    // pypi packages with `_`/`.` in their names.
    if !parsed.package_name.is_empty()
        && !ecosystem
            .normalize_name(&parsed.package_name)
            .eq_ignore_ascii_case(&ecosystem.normalize_name(name))
    {
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

    // `is_vulnerable` must agree with the presence of matches in BOTH
    // directions. true+empty is a contradictory verdict; false+non-empty is
    // the dangerous one — a caller keying "clean" off `is_vulnerable` would
    // silently drop real advisories. Refuse either rather than guess.
    if parsed.is_vulnerable == parsed.matches.is_empty() {
        return Err(format!(
            "vuln-api verdict is contradictory (is_vulnerable={}, matches={}); refusing to interpret",
            parsed.is_vulnerable,
            parsed.matches.len()
        )
        .into());
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln_api_stub::{self, header_value, spawn_capturing_vuln_api_stub, PackageKey};
    use std::collections::{HashMap, HashSet};

    fn lodash_key() -> PackageKey {
        vuln_api_stub::key("npm", "lodash", "4.17.20")
    }

    fn check_lodash(
        stub: &vuln_api_stub::VulnApiStub,
        token: Option<&str>,
    ) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
        let client = http_client().expect("test client");
        check_package_version(
            &client,
            &stub.base_url,
            token,
            Ecosystem::Npm,
            "lodash",
            "4.17.20",
        )
    }

    fn check_with_stub_status(
        status_code: u16,
        body: &str,
    ) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
        let stub = vuln_api_stub::spawn_with_statuses(
            HashMap::from([(lodash_key(), body.to_string())]),
            HashMap::from([(lodash_key(), status_code)]),
        );
        check_lodash(&stub, Some("test-token"))
    }

    fn check_with_stub_body(body: &str) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
        let stub = vuln_api_stub::spawn_with_statuses(
            HashMap::from([(lodash_key(), body.to_string())]),
            HashMap::new(),
        );
        check_lodash(&stub, Some("test-token"))
    }

    fn captured_request(auth_token: Option<&str>) -> String {
        let (base_url, requests) = spawn_capturing_vuln_api_stub();
        let client = http_client().expect("test client");
        check_package_version(
            &client,
            &base_url,
            auth_token,
            Ecosystem::Npm,
            "lodash",
            "4.17.20",
        )
        .expect("captured request should succeed");
        let requests = requests.lock().unwrap();
        requests[0].clone()
    }

    #[test]
    fn pypi_response_alternate_spelling_passes_identity_guard() {
        // The wire name for `Flask_Cors` is `flask_cors` (lowercase + trim,
        // the server's rule); a response that echoes a PEP 503-equivalent
        // spelling (`Flask-Cors`) must NOT trip the identity guard (which
        // would fail the gate closed for a valid package).
        let key = vuln_api_stub::key("pypi", "flask_cors", "1.0.0");
        let body = r#"{"ecosystem":"PyPI","package_name":"Flask-Cors","version":"1.0.0","is_vulnerable":false,"matches":[]}"#;
        let stub = vuln_api_stub::spawn_with_statuses(
            HashMap::from([(key, body.to_string())]),
            HashMap::new(),
        );
        let client = http_client().expect("test client");
        let resp = check_package_version(
            &client,
            &stub.base_url,
            None,
            Ecosystem::Pypi,
            "Flask_Cors",
            "1.0.0",
        )
        .expect("alternate pypi spelling must pass the identity guard");
        assert!(!resp.is_vulnerable);
    }

    #[test]
    fn pypi_wire_name_is_lowercased_not_pep503_collapsed() {
        // The server keys advisories lowercase+trim, NOT PEP 503: collapsing
        // `Zope.Interface` to `zope-interface` on the wire would miss the
        // stored `zope.interface` row and read a vulnerable package as
        // clean. The request path must carry the dot.
        let (base_url, requests) = spawn_capturing_vuln_api_stub();
        let client = http_client().expect("test client");
        check_package_version(
            &client,
            &base_url,
            None,
            Ecosystem::Pypi,
            "Zope.Interface",
            "5.0.0",
        )
        .expect("captured request should succeed");
        let requests = requests.lock().unwrap();
        let path = requests[0].lines().next().unwrap_or_default().to_string();
        assert!(
            path.contains("/pypi/zope.interface/"),
            "wire name must be lowercased with separators preserved; got: {path}"
        );
        assert!(
            !path.contains("zope-interface"),
            "wire name must not be PEP 503-collapsed; got: {path}"
        );
    }

    #[test]
    fn public_check_sends_no_auth_headers() {
        // The host is user-configurable; without a caller-owned token the
        // client must never attach a Corgea credential or cookie.
        let request = captured_request(None);
        assert!(header_value(&request, "Authorization").is_none());
        assert!(header_value(&request, "CORGEA-TOKEN").is_none());
        assert!(header_value(&request, "Cookie").is_none());
        assert_eq!(
            header_value(&request, "CORGEA-SOURCE").as_deref(),
            Some("cli")
        );
    }

    #[test]
    fn jwt_auth_sends_authorization_bearer() {
        let request = captured_request(Some("aaa.bbb.ccc"));
        assert_eq!(
            header_value(&request, "Authorization").as_deref(),
            Some("Bearer aaa.bbb.ccc")
        );
        assert!(header_value(&request, "CORGEA-TOKEN").is_none());
    }

    #[test]
    fn opaque_auth_sends_corgea_token() {
        let request = captured_request(Some("opaque-token"));
        assert_eq!(
            header_value(&request, "CORGEA-TOKEN").as_deref(),
            Some("opaque-token")
        );
        assert!(header_value(&request, "Authorization").is_none());
    }

    #[test]
    fn check_package_version_401_returns_actionable_error() {
        let err = check_with_stub_status(401, r#"{"error":"unauthorized"}"#)
            .expect_err("401 should fail");
        assert!(err.to_string().contains("rejected the Corgea token"));
    }

    #[test]
    fn check_package_version_429_retries_then_succeeds() {
        let vulnerable_body = vuln_api_stub::vulnerable_body(
            "npm",
            "lodash",
            "4.17.20",
            "GHSA-retry-test",
            Some("4.17.21"),
        );
        let stub = vuln_api_stub::spawn_with_retry_once(
            HashMap::from([(lodash_key(), vulnerable_body)]),
            HashMap::new(),
            HashSet::from([lodash_key()]),
        );
        let resp = check_lodash(&stub, Some("test-token")).expect("retry should succeed");
        assert!(resp.is_vulnerable);
    }

    /// Run a check against a stub that drops the connection (reads the
    /// request, closes without responding) for the first `drops` hits on
    /// lodash, then serves a vulnerable verdict.
    fn check_with_drops(drops: usize) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
        let vulnerable_body = vuln_api_stub::vulnerable_body(
            "npm",
            "lodash",
            "4.17.20",
            "GHSA-drop-test",
            Some("4.17.21"),
        );
        let stub = vuln_api_stub::spawn_with_drops(
            HashMap::from([(lodash_key(), vulnerable_body)]),
            HashMap::new(),
            HashMap::from([(lodash_key(), drops)]),
        );
        check_lodash(&stub, Some("test-token"))
    }

    #[test]
    fn check_package_version_retries_dropped_connection_then_succeeds() {
        let resp = check_with_drops(1).expect("one dropped connection should be retried");
        assert!(resp.is_vulnerable);
    }

    #[test]
    fn check_package_version_retries_two_dropped_connections_then_succeeds() {
        let resp = check_with_drops(2).expect("two dropped connections fit the 2-retry budget");
        assert!(resp.is_vulnerable);
    }

    #[test]
    fn check_package_version_fails_after_three_dropped_connections() {
        let err = check_with_drops(3).expect_err("three drops exhaust the 3-send budget");
        assert!(
            err.to_string().contains("Failed to send vuln-api request"),
            "got: {}",
            err
        );
    }

    #[test]
    fn is_jwt_detection() {
        assert!(is_jwt("a.b.c"));
        assert!(!is_jwt("plain-token"));
        assert!(!is_jwt(""));
        assert!(!is_jwt("a.b"));
        assert!(!is_jwt("a.b.c.d"));
        assert!(!is_jwt("a..c"));
        assert!(!is_jwt(".b.c"));
        assert!(!is_jwt("a.b."));
    }

    #[test]
    fn check_package_version_403_returns_actionable_error() {
        let err =
            check_with_stub_status(403, r#"{"error":"forbidden"}"#).expect_err("403 should fail");
        assert!(err.to_string().contains("access denied"));
    }

    #[test]
    fn check_package_version_404_is_an_error_not_clean() {
        // The real /check route 200s for unknown packages; 404 means the
        // base URL/route is wrong. Synthesizing "clean" here would turn a
        // misconfigured CORGEA_VULN_API_URL into a silent all-clear.
        let err = check_with_stub_status(404, r#"{"error":"not found"}"#)
            .expect_err("404 should be an error");
        assert!(err.to_string().contains("CORGEA_VULN_API_URL"));
    }

    #[test]
    fn check_package_version_429_returns_actionable_error() {
        let err = check_with_stub_status(429, r#"{"error":"rate limited"}"#)
            .expect_err("429 should fail");
        assert!(err.to_string().contains("rate-limited"));
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
    fn mismatched_package_name_is_an_error() {
        let body = r#"{"ecosystem":"npm","package_name":"left-pad","version":"4.17.20","is_vulnerable":false,"matches":[]}"#;
        let err = check_with_stub_body(body).expect_err("identity mismatch should fail");
        assert!(err.to_string().contains("does not match request"));
    }

    #[test]
    fn mismatched_version_is_an_error() {
        let body = r#"{"ecosystem":"npm","package_name":"lodash","version":"9.9.9","is_vulnerable":false,"matches":[]}"#;
        let err = check_with_stub_body(body).expect_err("identity mismatch should fail");
        assert!(err.to_string().contains("does not match request"));
    }

    #[test]
    fn ecosystem_comparison_is_case_insensitive() {
        // Staging spells pypi "PyPI"; that must not trip the identity guard.
        let body = r#"{"ecosystem":"NPM","package_name":"lodash","version":"4.17.20","is_vulnerable":false,"matches":[]}"#;
        let parsed = check_with_stub_body(body).expect("case difference is not a mismatch");
        assert!(!parsed.is_vulnerable);
    }

    #[test]
    fn vulnerable_without_matches_is_an_error() {
        let body = r#"{"ecosystem":"npm","package_name":"lodash","version":"4.17.20","is_vulnerable":true,"matches":[]}"#;
        let err = check_with_stub_body(body).expect_err("contradictory verdict should fail");
        assert!(err.to_string().contains("refusing to interpret"));
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
        assert_eq!(
            encode_package_name(Ecosystem::Npm, "@types/node"),
            "@types%2fnode"
        );
        assert_eq!(encode_package_name(Ecosystem::Npm, "lodash"), "lodash");
    }

    #[test]
    fn encode_package_name_pypi() {
        assert_eq!(encode_package_name(Ecosystem::Pypi, "requests"), "requests");
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
        assert_eq!(parsed.matches[0].tier, Some(1));
    }

    #[test]
    fn validated_base_strips_trailing_slash() {
        assert_eq!(
            validated_base("http://localhost:8080/").unwrap(),
            "http://localhost:8080"
        );
        assert!(validated_base("").is_err());
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
        assert_eq!(m.tier, Some(1));
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
