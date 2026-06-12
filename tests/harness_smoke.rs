//! Phase 0 smoke test for the `GateHarness` scaffold.
//!
//! The harness is a Phase 0 exit criterion ("another phase can write an
//! integration test in under 20 lines"), but Phase 0 ships no install
//! command to drive it through. This test exercises the three wiring points
//! directly — the fake package manager on a private PATH, the registry stub,
//! and the vuln-api stub — so the scaffold can't silently regress and leave
//! the next phase failing for harness reasons rather than gate logic.

#![cfg(unix)]

mod common;

use common::GateHarness;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, Write};

fn env_of(cmd: &std::process::Command, key: &str) -> Option<String> {
    cmd.get_envs()
        .find(|(k, _)| *k == OsStr::new(key))
        .and_then(|(_, v)| v)
        .map(|v| v.to_string_lossy().into_owned())
}

/// Raw one-shot HTTP GET against a `127.0.0.1` stub (responses carry
/// `Connection: close`, so `read_to_string` terminates).
fn http_get(base: &str, path: &str) -> String {
    let addr = base.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(addr).expect("connect stub");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    buf
}

#[test]
fn gate_harness_wires_stubs_and_fake_manager() {
    let checks = HashMap::from([(
        common::key("pypi", "evil", "1.0.0"),
        common::vulnerable_body("pypi", "evil", "1.0.0", "MAL-SMOKE-0001", None),
    )]);
    let h = GateHarness::new()
        .fake_recorder("pip", 0)
        .wildcard_pypi_registry()
        .vuln_checks(checks)
        .build();

    // 1. vuln-api stub: the scripted vulnerable verdict is served at the URL
    //    the harness exported to the corgea invocation.
    let vuln_url = env_of(&h.cmd, "CORGEA_VULN_API_URL").expect("CORGEA_VULN_API_URL wired");
    let client = corgea::vuln_api::http_client().expect("vuln-api client");
    let verdict = corgea::vuln_api::check_package_version(
        &client,
        &vuln_url,
        corgea::vuln_api::Ecosystem::Pypi,
        "evil",
        "1.0.0",
    )
    .expect("vuln-api stub must be reachable");
    assert!(
        verdict.is_vulnerable && verdict.matches[0].advisory_id == "MAL-SMOKE-0001",
        "the scripted vulnerable verdict must come back through the wired stub"
    );

    // 2. registry stub: the wildcard pypi stub answers for any package name.
    let registry = env_of(&h.cmd, "CORGEA_PYPI_REGISTRY").expect("CORGEA_PYPI_REGISTRY wired");
    let body = http_get(&registry, "/pypi/anything/json");
    assert!(
        body.starts_with("HTTP/1.1 200") && body.contains("\"info\""),
        "registry stub must serve pypi release json: {body}"
    );

    // 3. fake package manager: an executable recorder is on the private PATH
    //    the harness exported (so a later phase's install actually finds it).
    let path = env_of(&h.cmd, "PATH").expect("PATH wired");
    let pip = std::path::Path::new(&path).join("pip");
    assert!(
        pip.is_file(),
        "the fake pip recorder must exist on the harness PATH: {}",
        pip.display()
    );
}
