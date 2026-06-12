use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

pub type PackageKey = (String, String, String);

/// `(ecosystem, name, version)` key for the stub's route tables. Applies the
/// client's canonical-name rule (`Ecosystem::normalize_name`) on both the
/// fixture and lookup sides, so a fixture keyed under an alternate pypi
/// spelling can't silently miss and read as clean.
pub fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    let name = match eco {
        "pypi" => crate::vuln_api::Ecosystem::Pypi.normalize_name(name),
        _ => name.to_string(),
    };
    (eco.to_string(), name, ver.to_string())
}

/// Single-match vulnerable verdict body; `fixed: None` renders
/// `"fixed_version":null`. Shared by the in-crate unit tests and the
/// integration tests (via `tests/common`).
pub fn vulnerable_body(
    ecosystem: &str,
    name: &str,
    version: &str,
    advisory: &str,
    fixed: Option<&str>,
) -> String {
    let fixed = fixed.map_or("null".to_string(), |f| format!(r#""{f}""#));
    format!(
        r#"{{"ecosystem":"{ecosystem}","package_name":"{name}","version":"{version}","is_vulnerable":true,
        "matches":[{{"advisory_id":"{advisory}","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":{fixed}}}]}}"#
    )
}

const NOT_FOUND_BODY: &str = r#"{"error":"not found"}"#;

pub struct VulnApiStub {
    pub base_url: String,
    _handle: thread::JoinHandle<()>,
}

/// Minimal TCP vuln-api stub for CLI integration tests. Binds an ephemeral
/// 127.0.0.1 port; unknown packages get a synthesized clean 200.
pub fn spawn_with_statuses(
    package_checks: HashMap<PackageKey, String>,
    status_overrides: HashMap<PackageKey, u16>,
) -> VulnApiStub {
    spawn_with_retry_once(package_checks, status_overrides, HashSet::new())
}

/// Like [`spawn_with_statuses`], but keys in `retry_once` answer their first
/// hit with 429 + `Retry-After: 1` and fall through to the scripted response
/// from the second hit on — for exercising the client's retry path.
pub fn spawn_with_retry_once(
    package_checks: HashMap<PackageKey, String>,
    status_overrides: HashMap<PackageKey, u16>,
    retry_once: HashSet<PackageKey>,
) -> VulnApiStub {
    spawn(
        package_checks,
        status_overrides,
        retry_once,
        HashMap::new(),
        None,
    )
}

/// Like [`spawn_with_statuses`], but keys in `drops` have their first N hits
/// answered by reading the request and closing the connection without
/// writing a response — the client surfaces each as a `send()` error
/// (`connection closed before message completed`). Falls through to the
/// scripted response once the drops are spent. For exercising the client's
/// transient-failure retry path hermetically.
pub fn spawn_with_drops(
    package_checks: HashMap<PackageKey, String>,
    status_overrides: HashMap<PackageKey, u16>,
    drops: HashMap<PackageKey, usize>,
) -> VulnApiStub {
    spawn(
        package_checks,
        status_overrides,
        HashSet::new(),
        drops,
        None,
    )
}

/// Vuln-api stub that records raw requests and answers every package check
/// with a clean verdict (echoing the eco/name/version from the path). Used
/// to assert auth-header behavior, both in-crate and from the CLI.
pub fn spawn_capturing_vuln_api_stub() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stub = spawn(
        HashMap::new(),
        HashMap::new(),
        HashSet::new(),
        HashMap::new(),
        Some(std::sync::Arc::clone(&requests)),
    );
    // Dropping the stub's join handle detaches the listener thread; the
    // base URL keeps working for the caller's lifetime.
    (stub.base_url, requests)
}

fn spawn(
    package_checks: HashMap<PackageKey, String>,
    status_overrides: HashMap<PackageKey, u16>,
    retry_once: HashSet<PackageKey>,
    drops: HashMap<PackageKey, usize>,
    capture: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
) -> VulnApiStub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let bound_port = listener.local_addr().expect("stub local_addr").port();
    let base_url = format!("http://127.0.0.1:{bound_port}");

    let handle = thread::spawn(move || {
        let mut pending_retries = retry_once;
        let mut pending_drops = drops;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            handle_connection(
                &mut stream,
                &package_checks,
                &status_overrides,
                &mut pending_retries,
                &mut pending_drops,
                capture.as_deref(),
            );
        }
    });

    VulnApiStub {
        base_url,
        _handle: handle,
    }
}

/// One-shot JSON HTTP response. `Connection: close` is load-bearing: the
/// stubs serve one response per connection, so without it reqwest pools the
/// socket and a second request (the gate's tree pass makes several per run)
/// races the close and fails. `extra_headers` must be empty or end in `\r\n`.
pub fn http_response(status_line: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_line,
        extra_headers,
        body.len(),
        body
    )
}

/// The value of header `name` in a raw captured HTTP request, if present.
pub fn header_value(request: &str, name: &str) -> Option<String> {
    request
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
}

/// Read one HTTP request's bytes (through the header terminator) off `stream`.
pub fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
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
    buf
}

fn handle_connection(
    stream: &mut std::net::TcpStream,
    package_checks: &HashMap<PackageKey, String>,
    status_overrides: &HashMap<PackageKey, u16>,
    pending_retries: &mut HashSet<PackageKey>,
    pending_drops: &mut HashMap<PackageKey, usize>,
    capture: Option<&std::sync::Mutex<Vec<String>>>,
) {
    let buf = read_http_request(stream);
    let req = String::from_utf8_lossy(&buf);
    if let Some(capture) = capture {
        capture.lock().unwrap().push(req.clone().into_owned());
    }

    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1));

    let (status_code, response_body, retry_after) = match path {
        Some(path) => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if parts.len() >= 7
                && parts[0] == "v1"
                && parts[1] == "packages"
                && parts[4] == "versions"
                && parts[6] == "check"
            {
                let key = key(
                    parts[2],
                    &urlencoding::decode(parts[3]).unwrap_or_default(),
                    &urlencoding::decode(parts[5]).unwrap_or_default(),
                );
                if let Some(remaining) = pending_drops.get_mut(&key) {
                    // Close without writing: the request was read, so the
                    // client sees its connection die mid-exchange — the
                    // transient `send()` error this mode exists to script.
                    *remaining -= 1;
                    if *remaining == 0 {
                        pending_drops.remove(&key);
                    }
                    return;
                }
                if pending_retries.remove(&key) {
                    (429, r#"{"error":"rate limited"}"#.to_string(), true)
                } else {
                    let body = package_checks
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| default_clean_response(&key.0, &key.1, &key.2));
                    let status = status_overrides.get(&key).copied().unwrap_or(200);
                    (status, body, false)
                }
            } else {
                (404, NOT_FOUND_BODY.to_string(), false)
            }
        }
        None => (400, r#"{"error":"bad request"}"#.to_string(), false),
    };

    let response = http_response(
        &format!("{} {}", status_code, status_text(status_code)),
        if retry_after {
            "Retry-After: 1\r\n"
        } else {
            ""
        },
        &response_body,
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Reason phrase for a stub status line. Shared with the in-crate test
/// stubs so the mapping lives once.
fn status_text(status_code: u16) -> &'static str {
    match status_code {
        404 => "Not Found",
        401 => "Unauthorized",
        403 => "Forbidden",
        429 => "Too Many Requests",
        500..=599 => "Internal Server Error",
        _ if status_code >= 400 => "Error",
        _ => "OK",
    }
}

fn default_clean_response(eco: &str, name: &str, ver: &str) -> String {
    format!(
        r#"{{"ecosystem":"{eco}","package_name":"{name}","version":"{ver}","is_vulnerable":false,"matches":[]}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn get(base_url: &str, path: &str) -> String {
        let addr = base_url.trim_start_matches("http://");
        let mut stream = TcpStream::connect(addr).expect("connect stub");
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        resp
    }

    #[test]
    fn scripted_package_check_and_status_override() {
        let mut checks = HashMap::new();
        checks.insert(
            key("pypi", "evil", "1.0.0"),
            r#"{"ecosystem":"pypi","package_name":"evil","version":"1.0.0","is_vulnerable":true,"matches":[]}"#.to_string(),
        );
        checks.insert(key("pypi", "flaky", "1.0.0"), "{}".to_string());
        let mut statuses = HashMap::new();
        statuses.insert(key("pypi", "flaky", "1.0.0"), 503u16);
        let stub = spawn_with_statuses(checks, statuses);

        let resp = get(
            &stub.base_url,
            "/v1/packages/pypi/evil/versions/1.0.0/check",
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "resp: {resp}");
        assert!(resp.contains(r#""is_vulnerable":true"#), "resp: {resp}");

        let resp = get(
            &stub.base_url,
            "/v1/packages/pypi/flaky/versions/1.0.0/check",
        );
        assert!(resp.starts_with("HTTP/1.1 503"), "resp: {resp}");

        // Unknown package → synthesized clean 200.
        let resp = get(
            &stub.base_url,
            "/v1/packages/pypi/unknown/versions/2.0.0/check",
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "resp: {resp}");
        assert!(resp.contains(r#""is_vulnerable":false"#), "resp: {resp}");
    }
}
