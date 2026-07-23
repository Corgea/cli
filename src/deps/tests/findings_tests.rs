use super::common::scan_fixture;
use crate::deps::catalog::emitted_definition;
use crate::deps::ecosystems::evaluate::add_pinning_finding;
use crate::deps::model::Severity;

#[test]
fn pip_no_lockfile_is_dep001() {
    let inv = scan_fixture("python-pip-nolock");
    let f = inv.with_code("DEP001");
    assert!(!f.is_empty());
    assert_eq!(f[0].severity, Severity::High);
}

#[test]
fn poetry_lock_present_no_dep001() {
    assert!(scan_fixture("python-poetry").with_code("DEP001").is_empty());
}

#[test]
fn maven_no_lockfile_is_dep001() {
    assert!(!scan_fixture("java-maven").with_code("DEP001").is_empty());
}

#[test]
fn gradle_lock_present_no_dep001() {
    assert!(scan_fixture("java-gradle").with_code("DEP001").is_empty());
}

#[test]
fn fixture_findings_match_emitted_catalog_definitions() {
    for fixture in [
        "node-app",
        "node-stale",
        "node-yarn",
        "python-pip-nolock",
        "java-maven",
    ] {
        let inventory = scan_fixture(fixture);
        for finding in &inventory.findings {
            let definition = emitted_definition(&finding.id)
                .expect("every dependency finding must use an emitted definition");
            assert_eq!(finding.title, definition.title);
            assert_eq!(finding.severity, definition.severity);
        }
        assert!(inventory.with_code("DEP010").is_empty());
    }
}

#[test]
fn unresolved_bounded_range_uses_resolution_neutral_dep003_metadata() {
    let inventory = scan_fixture("node-stale");
    let finding = inventory
        .with_code("DEP003")
        .into_iter()
        .find(|finding| finding.resolved_version.is_none())
        .expect("node-stale should emit DEP003 for unresolved chalk");
    let definition = emitted_definition("DEP003").expect("DEP003 must be emitted");

    assert!(finding.package.is_none());
    assert!(!finding.reproducible);
    assert_eq!(
        definition.description,
        "A direct dependency uses a bounded version range."
    );
    assert_eq!(
        definition.remediation,
        "Pin an exact version or explicitly allow the range by policy."
    );
}

#[test]
#[should_panic(expected = "dependency finding code must be registered and emitted: DEP010")]
fn add_pinning_finding_rejects_reserved_codes_before_appending() {
    let mut findings = Vec::new();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        add_pinning_finding(
            &mut findings,
            "DEP010",
            None,
            "manifest",
            None,
            None,
            false,
            "reserved findings cannot be emitted",
        );
    }))
    .expect_err("reserved finding must panic");

    assert!(findings.is_empty());
    std::panic::resume_unwind(panic);
}
