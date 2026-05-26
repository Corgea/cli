use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct VulnApiStub {
    pub base_url: String,
    _handle: thread::JoinHandle<()>,
}

/// Minimal TCP vuln-api stub for CLI integration tests.
pub fn spawn(fixtures: HashMap<(String, String, String), String>) -> VulnApiStub {
    spawn_with_statuses(fixtures, HashMap::new())
}

pub fn spawn_with_statuses(
    fixtures: HashMap<(String, String, String), String>,
    status_overrides: HashMap<(String, String, String), u16>,
) -> VulnApiStub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{}", port);
    let fixtures = Arc::new(Mutex::new(fixtures));
    let status_overrides = Arc::new(Mutex::new(status_overrides));

    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(64) {
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

            let package_check = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|path| {
                    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                    if parts.len() >= 7
                        && parts[0] == "v1"
                        && parts[1] == "packages"
                        && parts[4] == "versions"
                        && parts[6] == "check"
                    {
                        Some((
                            parts[2].to_string(),
                            urlencoding::decode(parts[3])
                                .unwrap_or_default()
                                .into_owned(),
                            urlencoding::decode(parts[5])
                                .unwrap_or_default()
                                .into_owned(),
                        ))
                    } else {
                        None
                    }
                });

            let (status_code, response_body) = match package_check {
                Some((eco, name, ver)) => {
                    let key = (eco.clone(), name.clone(), ver.clone());
                    let body = fixtures
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| {
                            format!(
                                r#"{{"ecosystem":"{eco}","package_name":"{name}","version":"{ver}","is_vulnerable":false,"matches":[]}}"#
                            )
                        });
                    let status = status_overrides
                        .lock()
                        .unwrap()
                        .get(&key)
                        .copied()
                        .unwrap_or(200);
                    (status, body)
                }
                None if req.lines().next().is_some() => {
                    (404, r#"{"error":"not found"}"#.to_string())
                }
                None => (400, r#"{"error":"bad request"}"#.to_string()),
            };

            let status_text = match status_code {
                404 => "Not Found",
                401 => "Unauthorized",
                403 => "Forbidden",
                429 => "Too Many Requests",
                500..=599 => "Internal Server Error",
                _ if status_code >= 400 => "Error",
                _ => "OK",
            };

            let response = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                status_code,
                status_text,
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    thread::sleep(Duration::from_millis(50));

    VulnApiStub {
        base_url,
        _handle: handle,
    }
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
