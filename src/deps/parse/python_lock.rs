//! Python lockfile parsing — to be lifted from the binary freshness engine
//! (`src/verify_deps/python.rs`) in Slice 3.
//!
//! Planned exports:
//! - `parse_poetry_lock`
//! - `parse_uv_lock`
//! - `parse_requirements_pinned`

#![allow(dead_code)]

use std::path::Path;

/// Placeholder until Slice 3 extraction from `src/verify_deps/python.rs`.
pub fn parse_poetry_lock(_path: &Path) -> Result<(), String> {
    unimplemented!("deps::parse::python_lock — PRD_DEPS_TESTING.md §4.5 / Slice 3")
}
