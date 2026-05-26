pub mod concurrency_stub;
pub mod vuln_api_stub;

use std::process::Command;

pub fn corgea_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_corgea"))
}

pub fn stub_env(stub_url: &str) -> [(&'static str, String); 3] {
    [
        ("CORGEA_VULN_API_URL", stub_url.to_string()),
        ("CORGEA_TOKEN", "test-token".to_string()),
        ("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1".to_string()),
    ]
}
