pub mod deps;
pub mod precheck;
pub mod verify_deps;
// Also declared in the binary crate (src/main.rs); re-declared here so library modules
// (e.g. vuln_api) can use `crate::log::debug`. src/log.rs is a thin `::log` facade that
// compiles cleanly in both crates.
mod log;
pub mod vuln_api;
