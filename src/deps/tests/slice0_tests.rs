//! Slice 0 → 1 handoff: classification tests target `classify_constraint` in
//! `src/deps/ecosystems/mod.rs`.

use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::Npm};

#[test]
fn slice1_classify_boundary_is_implemented() {
    // When stubbing for Slice 0-only PRs, this test fails at classify_constraint
    // with `unimplemented!()` — the correct red state for Slice 1.
    assert_eq!(classify_constraint(Npm, "*"), ConstraintKind::Unbounded);
    assert_eq!(
        classify_constraint(Npm, "^4.18.2"),
        ConstraintKind::BoundedRange
    );
}
