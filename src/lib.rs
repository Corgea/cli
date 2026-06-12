pub mod deps;
pub mod precheck;
pub mod verify_deps;
// Also declared in the binary crate (src/main.rs); re-declared here so library modules
// (e.g. vuln_api) can use `crate::log::debug`. src/log.rs is a thin `::log` facade that
// compiles cleanly in both crates.
mod log;
pub mod vuln_api;
// Test-only HTTP stub for the vuln-api. Gated out of release builds; the
// `test-stub` feature is enabled for every test build by the self
// dev-dependency in Cargo.toml, so integration tests can use it too.
#[cfg(any(test, feature = "test-stub"))]
pub mod vuln_api_stub;
