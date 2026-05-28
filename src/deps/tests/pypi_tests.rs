use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::PyPI};

#[test]
fn pypi_classify_exact_pin() {
    assert_eq!(classify_constraint(PyPI, "==2.3.3"), ConstraintKind::Exact);
}

#[test]
fn pypi_classify_bare_name_is_unbounded() {
    assert_eq!(
        classify_constraint(PyPI, "requests"),
        ConstraintKind::Unbounded
    );
}

#[test]
fn pypi_classify_open_greater_equal_is_unbounded() {
    assert_eq!(
        classify_constraint(PyPI, ">=1.26"),
        ConstraintKind::Unbounded
    );
}

#[test]
fn pypi_classify_compatible_release_is_bounded_range() {
    assert_eq!(
        classify_constraint(PyPI, "~=2.3"),
        ConstraintKind::BoundedRange
    );
}

#[test]
fn pypi_classify_git_branch_is_mutable_ref() {
    assert_eq!(
        classify_constraint(PyPI, "git+https://github.com/acme/x.git@main"),
        ConstraintKind::GitRef { mutable: true }
    );
}

use super::common::scan_fixture;
use crate::deps::model::Scope;

#[test]
fn pypi_graph_classifies_pytest_as_development_scope() {
    assert_eq!(
        scan_fixture("python-poetry")
            .node("pytest")
            .expect("pytest node missing")
            .scope(),
        Scope::Development
    );
}

#[test]
fn pypi_graph_resolves_transitive_urllib3_version() {
    let inv = scan_fixture("python-poetry");
    let urllib3 = inv.node("urllib3").expect("urllib3 should be in the graph");
    assert!(!urllib3.is_direct());
    assert_eq!(urllib3.version(), Some("2.0.7"));
}

#[test]
fn pypi_exact_pin_has_no_pinning_finding() {
    let inv = scan_fixture("python-pip-nolock");
    assert!(inv
        .findings_for("flask")
        .iter()
        .all(|f| f.id != "DEP003" && f.id != "DEP004"));
}

#[test]
fn pypi_bare_name_is_dep004() {
    assert!(scan_fixture("python-pip-nolock")
        .findings_for("requests")
        .iter()
        .any(|f| f.id == "DEP004"));
}

#[test]
fn pypi_open_ended_range_is_dep004_high() {
    use crate::deps::model::Severity;
    let inv = scan_fixture("python-pip-nolock");
    let f = inv
        .findings_for("urllib3")
        .into_iter()
        .find(|f| f.id == "DEP004")
        .expect("urllib3>=1.26 must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn pypi_git_branch_dep_is_dep005() {
    assert!(scan_fixture("python-pip-nolock")
        .findings_for("internal-lib")
        .iter()
        .any(|f| f.id == "DEP005"));
}
