mod common;

use common::concurrency_stub::{ConcurrencyStub, StubConfig};
use common::{corgea_cmd, stub_env};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static CVE_INTEGRATION_LOCK: Mutex<()> = Mutex::new(());

fn integration_lock() -> MutexGuard<'static, ()> {
    CVE_INTEGRATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_n_dep_lockfile(dir: &Path, n: usize) {
    let mut entries = String::new();
    for i in 0..n {
        if !entries.is_empty() {
            entries.push(',');
        }
        entries.push_str(&format!(r#""node_modules/pkg-{i}": {{"version":"1.0.0"}}"#));
    }
    let lock = format!(
        r#"{{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{{{entries}}}}}"#
    );
    std::fs::write(dir.join("package-lock.json"), lock).unwrap();
}

#[test]
fn invalid_cve_concurrency_exits_2() {
    let _lock = integration_lock();
    for bad in ["0", "100"] {
        let output = corgea_cmd()
            .args(["deps", "--check-cve", "--cve-concurrency", bad])
            .output()
            .expect("spawn");
        assert_eq!(output.status.code(), Some(2), "bad={bad}");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
        assert!(
            combined.contains("invalid value") || combined.contains("1..=32"),
            "expected clap range error, got: {combined}"
        );
    }
}

#[test]
fn peak_concurrency_capped_at_default() {
    let _lock = integration_lock();
    let dir = tempfile::tempdir().unwrap();
    write_n_dep_lockfile(dir.path(), 50);

    let stub = ConcurrencyStub::spawn(StubConfig {
        per_request_sleep: Duration::from_millis(200),
        retry_after_mode: false,
        default_body: r#"{"is_vulnerable":false,"matches":[]}"#.into(),
    });

    let start = Instant::now();
    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "--cve-concurrency",
            "8",
            "-e",
            "npm",
            "-p",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "expected parallel speedup, took {:?}",
        elapsed
    );
    assert!(
        stub.peak_concurrency() <= 8,
        "peak was {}",
        stub.peak_concurrency()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("[CVE check]"));
}

#[test]
fn retry_after_429_produces_finding() {
    let _lock = integration_lock();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{
            "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" }
            }
        }"#,
    )
    .unwrap();

    let stub = ConcurrencyStub::spawn(StubConfig {
        per_request_sleep: Duration::from_millis(10),
        retry_after_mode: true,
        default_body: common::vuln_api_stub::lodash_vulnerable_response(),
    });

    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        body["cve_summary"]["vulnerable"].as_u64(),
        Some(1),
        "{}",
        body
    );
}
