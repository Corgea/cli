use std::path::PathBuf;

use crate::deps::policy::Policy;
use crate::deps::{scan, Inventory};

pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

pub fn scan_fixture(name: &str) -> Inventory {
    scan(&fixture(name), &Policy::default())
        .unwrap_or_else(|e| panic!("scan of fixture {name} failed: {e:?}"))
}
