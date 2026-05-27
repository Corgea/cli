use super::common::{fixture, scan_fixture};
use crate::deps::findings::FindingSource;
use crate::deps::model::Severity;
use crate::deps::vuln::VulnerabilitySource;

fn vuln_source() -> VulnerabilitySource {
    VulnerabilitySource::from_json_file(&fixture("vuln-db.json")).expect("vuln-db.json loads")
}

#[test]
fn vuln_known_vulnerable_transitive_version_is_dep010() {
    let inv = scan_fixture("node-app");
    let findings = vuln_source().enrich(&inv.graph);
    assert!(findings
        .iter()
        .any(|f| { f.id == "DEP010" && f.package.as_ref().is_some_and(|p| p.name() == "qs") }));
}

#[test]
fn vuln_safe_version_is_not_dep010() {
    let inv = scan_fixture("node-app");
    let findings = vuln_source().enrich(&inv.graph);
    for safe in ["express", "lodash"] {
        assert!(findings
            .iter()
            .all(|f| { f.package.as_ref().map(|p| p.name()) != Some(safe) }));
    }
}

#[test]
fn vuln_dep010_severity_comes_from_advisory() {
    let inv = scan_fixture("node-app");
    let f = vuln_source()
        .enrich(&inv.graph)
        .into_iter()
        .find(|f| f.id == "DEP010")
        .expect("expected DEP010");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn vuln_dep010_carries_dependency_path() {
    let inv = scan_fixture("node-app");
    let f = vuln_source()
        .enrich(&inv.graph)
        .into_iter()
        .find(|f| f.id == "DEP010")
        .expect("expected DEP010");
    let path = f.paths.first().expect("DEP010 must carry path");
    assert_eq!(path.first().map(|id| id.0.as_str()), Some("root"));
    assert_eq!(path.last().map(|id| id.name()), Some("qs"));
}

#[test]
fn vuln_scan_without_source_yields_no_dep010() {
    assert!(scan_fixture("node-app").with_code("DEP010").is_empty());
}
