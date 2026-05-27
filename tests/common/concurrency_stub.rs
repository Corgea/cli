use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct ConcurrencyStub {
    pub base_url: String,
    peak_in_flight: Arc<AtomicUsize>,
    _handle: thread::JoinHandle<()>,
}

pub struct StubConfig {
    pub per_request_sleep: Duration,
    pub retry_after_mode: bool,
    pub default_body: String,
}

impl ConcurrencyStub {
    pub fn spawn(config: StubConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));
        let hit_counts: Arc<Mutex<HashMap<(String, String, String), u32>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let in_flight_listener = in_flight.clone();
        let peak_listener = peak_in_flight.clone();

        let handle = thread::spawn(move || {
            let mut worker_handles = Vec::new();
            for stream in listener.incoming().take(256) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let in_flight = in_flight_listener.clone();
                let peak = peak_listener.clone();
                let hit_counts = hit_counts.clone();
                let per_request_sleep = config.per_request_sleep;
                let retry_after_mode = config.retry_after_mode;
                let default_body = config.default_body.clone();

                worker_handles.push(thread::spawn(move || {
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

                    let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(cur, Ordering::SeqCst);
                    thread::sleep(per_request_sleep);
                    in_flight.fetch_sub(1, Ordering::SeqCst);

                    let (status_code, status_text, response_body, extra_headers) =
                        if let Some(path) =
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
                                let key = (eco, name, ver);

                                if retry_after_mode {
                                    let hits = {
                                        let mut counts = hit_counts.lock().unwrap();
                                        let entry = counts.entry(key).or_insert(0);
                                        *entry += 1;
                                        *entry
                                    };
                                    if hits == 1 {
                                        (
                                            429,
                                            "Too Many Requests",
                                            r#"{"error":"rate limited"}"#.to_string(),
                                            "Retry-After: 1\r\n".to_string(),
                                        )
                                    } else {
                                        (200, "OK", default_body, String::new())
                                    }
                                } else {
                                    (200, "OK", default_body, String::new())
                                }
                            } else {
                                (
                                    404,
                                    "Not Found",
                                    r#"{"error":"not found"}"#.to_string(),
                                    String::new(),
                                )
                            }
                        } else {
                            (
                                400,
                                "Bad Request",
                                r#"{"error":"bad request"}"#.to_string(),
                                String::new(),
                            )
                        };

                    let response = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                        status_code,
                        status_text,
                        extra_headers,
                        response_body.len(),
                        response_body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }));
            }
            for worker in worker_handles {
                let _ = worker.join();
            }
        });

        thread::sleep(Duration::from_millis(50));

        ConcurrencyStub {
            base_url,
            peak_in_flight,
            _handle: handle,
        }
    }

    pub fn peak_concurrency(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }
}
