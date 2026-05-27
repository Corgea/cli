//! Shared lockfile and manifest parsers for `corgea deps` inventory and `deps verify`.
//!
//! **Slice 0:** module boundary only — npm/Python lockfile parsers still live in the
//! binary crate freshness engine at [`src/verify_deps/npm.rs`](../../verify_deps/npm.rs)
//! and [`src/verify_deps/python.rs`](../../verify_deps/python.rs) (used by
//! `corgea deps verify`, not exposed as a top-level command).
//!
//! **Slice 3:** move parsers here and have the freshness engine re-export or delegate:
//!
//! | Source (today) | Target (Slice 3) | Used for |
//! |---|---|---|
//! | `src/verify_deps/npm.rs` lockfile parsers | `parse/npm_lock.rs` | Graph, DEP002/008 |
//! | `src/verify_deps/python.rs` lockfile parsers | `parse/python_lock.rs` | DEP001/007, graph |
//! | freshness engine discover file order | `parse/discover.rs` | `detect_dependency_files` |

pub mod npm_lock;
pub mod python_lock;
