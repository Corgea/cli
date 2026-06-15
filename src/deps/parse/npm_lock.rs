//! npm / yarn / pnpm lockfile parsing — shared-parser module boundary placeholder.

#![allow(dead_code)]

use std::path::Path;

/// Placeholder for the shared npm lockfile parser (not yet extracted).
pub fn parse_package_lock(_path: &Path) -> Result<(), String> {
    unimplemented!("deps::parse::npm_lock")
}
