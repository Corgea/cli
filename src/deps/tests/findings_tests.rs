use super::common::scan_fixture;
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
