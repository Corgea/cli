//! npm / yarn / pnpm lockfile parsing — to be lifted from the binary freshness engine
//! (`src/verify_deps/npm.rs`) in Slice 3.
//!
//! Planned exports:
//! - `parse_package_lock_v3`
//! - `parse_yarn_lock`
//! - `parse_pnpm_lock`
//! - `NpmLockPackage` (name, version, integrity, declared range)

#![allow(dead_code)]

use std::path::Path;

/// Placeholder until Slice 3 extraction from `src/verify_deps/npm.rs`.
pub fn parse_package_lock(_path: &Path) -> Result<(), String> {
    unimplemented!("deps::parse::npm_lock — PRD_DEPS_TESTING.md §4.5 / Slice 3")
}
