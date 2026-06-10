mod fixtures;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub use fixtures::load_from_file;

pub type PackageKey = (String, String, String);

const NOT_FOUND_BODY: &str = r#"{"error":"not found"}"#;

/// Loaded fixture data for the vuln-api stub server.
#[derive(Debug, Clone, Default)]
pub struct StubFixtures {
    pub package_checks: HashMap<PackageKey, String>,
    pub advisories: HashMap<String, String>,
    pub status_overrides: HashMap<PackageKey, u16>,
}

pub struct VulnApiStub {
    pub base_url: String,
    _handle: thread::JoinHandle<()>,
}

impl VulnApiStub {
    /// Block until the stub server thread exits (normally never, unless the listener fails).
    pub fn block(self) {
        let _ = self._handle.join();
    }
}

/// Minimal TCP vuln-api stub for CLI integration tests and e2e dogfood.
pub fn spawn(fixtures: HashMap<PackageKey, String>) -> VulnApiStub {
    spawn_with_statuses(fixtures, HashMap::new())
}

pub fn spawn_with_statuses(
    fixtures: HashMap<PackageKey, String>,
    status_overrides: HashMap<PackageKey, u16>,
) -> VulnApiStub {
    spawn_on_port(
        StubFixtures {
            package_checks: fixtures,
            advisories: HashMap::new(),
            status_overrides,
        },
        0,
    )
}

/// Bind stub on `port` (`0` = ephemeral). Returns base URL `http://127.0.0.1:{port}`.
pub fn spawn_on_port(fixtures: StubFixtures, port: u16) -> VulnApiStub {
    let addr = if port == 0 {
        "127.0.0.1:0".to_string()
    } else {
        format!("127.0.0.1:{port}")
    };
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind stub on {addr}: {e}"));
    let bound_port = listener.local_addr().expect("stub local_addr").port();
    let base_url = format!("http://127.0.0.1:{bound_port}");

    let package_checks = Arc::new(fixtures.package_checks);
    let advisories = Arc::new(fixtures.advisories);
    let status_overrides = Arc::new(fixtures.status_overrides);

    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            handle_connection(&mut stream, &package_checks, &advisories, &status_overrides);
        }
    });

    thread::sleep(Duration::from_millis(50));

    VulnApiStub {
        base_url,
        _handle: handle,
    }
}

pub fn spawn_from_file(path: &Path) -> VulnApiStub {
    let fixtures =
        load_from_file(path).unwrap_or_else(|e| panic!("load stub fixtures {path:?}: {e}"));
    spawn_on_port(fixtures, 0)
}

fn handle_connection(
    stream: &mut std::net::TcpStream,
    package_checks: &Arc<HashMap<PackageKey, String>>,
    advisories: &Arc<HashMap<String, String>>,
    status_overrides: &Arc<HashMap<PackageKey, u16>>,
) {
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

    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1));

    let (status_code, response_body) = match path {
        Some(path) => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if parts.len() >= 7
                && parts[0] == "v1"
                && parts[1] == "packages"
                && parts[4] == "versions"
                && parts[6] == "check"
            {
                let key = (
                    parts[2].to_string(),
                    urlencoding::decode(parts[3])
                        .unwrap_or_default()
                        .into_owned(),
                    urlencoding::decode(parts[5])
                        .unwrap_or_default()
                        .into_owned(),
                );
                let body = package_checks
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| default_clean_response(&key.0, &key.1, &key.2));
                let status = status_overrides.get(&key).copied().unwrap_or(200);
                (status, body)
            } else if parts.len() >= 3 && parts[0] == "v1" && parts[1] == "advisories" {
                let id = urlencoding::decode(parts[2])
                    .unwrap_or_default()
                    .into_owned();
                match advisories.get(&id) {
                    Some(body) => (200, body.clone()),
                    None => (404, NOT_FOUND_BODY.to_string()),
                }
            } else {
                (404, NOT_FOUND_BODY.to_string())
            }
        }
        None => (400, r#"{"error":"bad request"}"#.to_string()),
    };

    let status_text = status_text(status_code);
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_code,
        status_text,
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
}

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

    fn key(eco: &str, name: &str, ver: &str) -> super::PackageKey {
        (eco.to_string(), name.to_string(), ver.to_string())
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

    #[test]
    fn advisory_route_and_fixture_file_loading() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixtures.json");
        std::fs::write(
            &path,
            r#"{
              "package_checks": {
                "npm/left-pad/1.0.0": {"ecosystem":"npm","package_name":"left-pad","version":"1.0.0","is_vulnerable":true,"matches":[]}
              },
              "advisories": {"MAL-2024-0001": {"id":"MAL-2024-0001"}}
            }"#,
        )
        .unwrap();
        let stub = spawn_from_file(&path);

        let resp = get(
            &stub.base_url,
            "/v1/packages/npm/left-pad/versions/1.0.0/check",
        );
        assert!(resp.contains(r#""is_vulnerable":true"#), "resp: {resp}");

        let resp = get(&stub.base_url, "/v1/advisories/MAL-2024-0001");
        assert!(resp.starts_with("HTTP/1.1 200"), "resp: {resp}");
        let resp = get(&stub.base_url, "/v1/advisories/NOPE");
        assert!(resp.starts_with("HTTP/1.1 404"), "resp: {resp}");
    }
}
