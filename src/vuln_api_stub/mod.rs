mod fixtures;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub use fixtures::load_from_file;

type PackageKey = (String, String, String);

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

pub fn lodash_vulnerable_response() -> String {
    r#"{
        "ecosystem": "npm",
        "package_name": "lodash",
        "version": "4.17.20",
        "is_vulnerable": true,
        "matches": [{
            "advisory_id": "GHSA-integration-test",
            "severity_level": "high",
            "tier": 2,
            "vulnerable_version_range": "< 4.17.21",
            "fixed_version": "4.17.21"
        }]
    }"#
    .to_string()
}

/// One critical + one high match on a single advisory. Used to exercise
/// `--severity critical` and `--severity critical,high` gating.
pub fn lodash_critical_and_high_response() -> String {
    r#"{
        "ecosystem": "npm",
        "package_name": "lodash",
        "version": "4.17.20",
        "is_vulnerable": true,
        "matches": [
            {
                "advisory_id": "GHSA-test-critical",
                "severity_level": "critical",
                "tier": 1,
                "vulnerable_version_range": "< 4.17.21",
                "fixed_version": "4.17.21"
            },
            {
                "advisory_id": "GHSA-test-high",
                "severity_level": "high",
                "tier": 2,
                "vulnerable_version_range": "< 4.17.21",
                "fixed_version": "4.17.21"
            }
        ]
    }"#
    .to_string()
}

/// One critical + one high + one medium match. Used to exercise
/// `--severity critical,high` `OneOf` semantics (the medium match
/// renders but is below-floor).
pub fn lodash_critical_high_and_medium_response() -> String {
    r#"{
        "ecosystem": "npm",
        "package_name": "lodash",
        "version": "4.17.20",
        "is_vulnerable": true,
        "matches": [
            {
                "advisory_id": "GHSA-test-critical",
                "severity_level": "critical",
                "tier": 1,
                "vulnerable_version_range": "< 4.17.21",
                "fixed_version": "4.17.21"
            },
            {
                "advisory_id": "GHSA-test-high",
                "severity_level": "high",
                "tier": 2,
                "vulnerable_version_range": "< 4.17.21",
                "fixed_version": "4.17.21"
            },
            {
                "advisory_id": "GHSA-test-medium",
                "severity_level": "medium",
                "tier": 2,
                "vulnerable_version_range": "< 4.17.21",
                "fixed_version": "4.17.21"
            }
        ]
    }"#
    .to_string()
}

/// Single match at the server's `unknown` fallback severity. Locks the
/// fail-open `Info` mapping so unknown strings never silently drop from
/// the gate.
pub fn lodash_unknown_severity_response() -> String {
    r#"{
        "ecosystem": "npm",
        "package_name": "lodash",
        "version": "4.17.20",
        "is_vulnerable": true,
        "matches": [{
            "advisory_id": "GHSA-test-unknown",
            "severity_level": "unknown",
            "tier": 2,
            "vulnerable_version_range": "< 4.17.21",
            "fixed_version": "4.17.21"
        }]
    }"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn dogfood_fixture_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/deps/vuln-api-stub.json")
    }

    #[test]
    fn load_dogfood_fixture_file() {
        let fixtures = load_from_file(&dogfood_fixture_path()).expect("load dogfood fixture");
        assert!(fixtures.package_checks.contains_key(&(
            "npm".into(),
            "lodash".into(),
            "4.17.20".into()
        )));
        assert!(fixtures.advisories.contains_key("CVE-2019-10744"));
    }

    #[test]
    fn stub_serves_package_check_from_file() {
        let stub = spawn_from_file(&dogfood_fixture_path());
        let port: u16 = stub.base_url.rsplit(':').next().unwrap().parse().unwrap();
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect stub");
        let req = "GET /v1/packages/npm/lodash/versions/4.17.20/check HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("is_vulnerable"));
        assert!(resp.contains("CVE-2019-10744"));
    }
}
