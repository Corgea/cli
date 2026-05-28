use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::Npm};

#[test]
fn npm_classify_exact_version() {
    assert_eq!(classify_constraint(Npm, "4.18.2"), ConstraintKind::Exact);
}

#[test]
fn npm_classify_caret_is_bounded_range() {
    assert_eq!(
        classify_constraint(Npm, "^4.18.2"),
        ConstraintKind::BoundedRange
    );
}

#[test]
fn npm_classify_wildcard_is_unbounded() {
    assert_eq!(classify_constraint(Npm, "*"), ConstraintKind::Unbounded);
}

#[test]
fn npm_classify_latest_is_unbounded() {
    assert_eq!(
        classify_constraint(Npm, "latest"),
        ConstraintKind::Unbounded
    );
}

#[test]
fn npm_classify_git_branch_is_mutable_ref() {
    assert_eq!(
        classify_constraint(Npm, "git+https://github.com/acme/x.git#main"),
        ConstraintKind::GitRef { mutable: true }
    );
}

#[test]
fn npm_classify_git_commit_sha_is_immutable_ref() {
    let sha = "git+https://github.com/acme/x.git#0bc1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    assert_eq!(
        classify_constraint(Npm, sha),
        ConstraintKind::GitRef { mutable: false }
    );
}

use super::common::scan_fixture;
use crate::deps::model::{PackageId, Scope, Severity, SourceType};

#[test]
fn npm_graph_classifies_express_as_direct_production() {
    let inv = scan_fixture("node-app");
    let express = inv.node("express").expect("express node missing");
    assert!(express.is_direct());
    assert_eq!(express.scope(), Scope::Production);
    assert_eq!(express.version(), Some("4.18.2"));
}

#[test]
fn npm_graph_classifies_qs_as_transitive() {
    let inv = scan_fixture("node-app");
    let qs = inv.node("qs").expect("qs node missing");
    assert!(!qs.is_direct());
    assert!(qs.depth() >= 2);
}

#[test]
fn npm_graph_classifies_jest_as_development_scope() {
    let inv = scan_fixture("node-app");
    assert_eq!(
        inv.node("jest").expect("jest node missing").scope(),
        Scope::Development
    );
}

#[test]
fn npm_graph_marks_git_dep_source_type() {
    let inv = scan_fixture("node-app");
    let git_dep = inv
        .node("internal-utils")
        .expect("internal-utils node missing");
    assert_eq!(git_dep.source_type(), SourceType::GitBranch);
}

#[test]
fn npm_purl_identity_is_canonical() {
    let inv = scan_fixture("node-app");
    assert_eq!(
        *inv.node("lodash").unwrap().id(),
        PackageId("pkg:npm/lodash@4.17.21".into())
    );
}

#[test]
fn npm_caret_direct_dep_is_dep003() {
    let inv = scan_fixture("node-app");
    assert!(
        !inv.findings_for("express").is_empty()
            && inv.findings_for("express").iter().any(|f| f.id == "DEP003")
    );
}

#[test]
fn npm_exact_dev_dep_has_no_pinning_finding() {
    let inv = scan_fixture("node-app");
    assert!(inv
        .findings_for("jest")
        .iter()
        .all(|f| f.id != "DEP003" && f.id != "DEP004"));
}

#[test]
fn npm_wildcard_direct_dep_is_dep004_high() {
    let inv = scan_fixture("node-app");
    let f = inv
        .findings_for("lodash")
        .into_iter()
        .find(|f| f.id == "DEP004")
        .expect("lodash `*` must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn npm_latest_direct_dep_is_dep004() {
    let inv = scan_fixture("node-app");
    assert!(
        inv.findings_for("left-pad")
            .iter()
            .any(|f| f.id == "DEP004"),
        "left-pad `latest` must raise DEP004"
    );
}

#[test]
fn npm_git_branch_dep_is_dep005() {
    let inv = scan_fixture("node-app");
    let f = inv
        .findings_for("internal-utils")
        .into_iter()
        .find(|f| f.id == "DEP005")
        .expect("internal-utils @ #main is DEP005");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn git_commit_sha_is_not_dep005() {
    let pinned = "git+https://github.com/acme/x.git#0bc1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    assert_eq!(
        classify_constraint(Npm, pinned),
        ConstraintKind::GitRef { mutable: false }
    );
}

#[test]
fn npm_url_dep_without_checksum_is_dep006() {
    assert_eq!(
        classify_constraint(Npm, "https://example.com/pkg/foo-1.0.0.tgz"),
        ConstraintKind::Url { checksum: false }
    );
}

#[test]
fn npm_lock_entry_without_integrity_is_dep008() {
    let inv = scan_fixture("node-app");
    assert!(
        inv.findings_for("left-pad")
            .iter()
            .any(|f| f.id == "DEP008"),
        "left-pad lacks integrity — DEP008"
    );
}

#[test]
fn npm_lock_entry_with_integrity_no_dep008() {
    let inv = scan_fixture("node-app");
    for pkg in ["express", "qs", "lodash"] {
        assert!(
            inv.findings_for(pkg).iter().all(|f| f.id != "DEP008"),
            "{pkg} has integrity — no DEP008"
        );
    }
}

#[test]
fn node_manifest_dep_missing_from_lock_is_dep002() {
    let inv = scan_fixture("node-stale");
    let f = inv.with_code("DEP002");
    assert!(!f.is_empty(), "manifest/lock drift must raise DEP002");
    assert_eq!(f[0].severity, Severity::High);
}

#[test]
fn node_app_lock_in_sync_no_dep002() {
    let inv = scan_fixture("node-app");
    assert!(inv.with_code("DEP002").is_empty());
}
