use super::common::scan_fixture;
use crate::deps::model::Severity;

#[test]
fn node_locked_transitive_range_yields_no_finding() {
    let inv = scan_fixture("node-app");
    assert!(
        inv.findings_for("qs")
            .iter()
            .all(|f| f.id != "DEP003" && f.id != "DEP004"),
        "locked transitive qs must not raise pinning finding"
    );
}

#[test]
fn node_direct_locked_range_is_medium_not_high() {
    let inv = scan_fixture("node-app");
    let dep003 = inv
        .findings_for("express")
        .into_iter()
        .find(|f| f.id == "DEP003")
        .expect("expected DEP003 for express");
    assert_eq!(dep003.severity, Severity::Medium);
    assert!(dep003.reproducible);
}

#[test]
fn pypi_locked_transitive_range_yields_no_finding() {
    let inv = scan_fixture("python-poetry");
    assert!(
        inv.findings_for("urllib3").is_empty(),
        "locked transitive urllib3 must produce no findings"
    );
}

#[test]
fn gradle_locked_dynamic_version_is_reproducible() {
    let inv = scan_fixture("java-gradle");
    let dep003 = inv
        .findings_for("commons-lang3")
        .into_iter()
        .find(|f| f.id == "DEP003")
        .expect("dynamic direct version should warn DEP003");
    assert_eq!(dep003.severity, Severity::Medium);
    assert!(dep003.reproducible);
}
