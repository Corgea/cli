use super::common::{fixture, scan_fixture};
use crate::deps::policy::Policy;
use crate::deps::scan;

#[test]
fn default_policy_fails_on_wildcard() {
    assert!(!scan_fixture("node-app").with_code("DEP004").is_empty());
}

#[test]
fn policy_from_yaml_parses_prd_example() {
    let yaml = r#"
dependency_policy:
  require_lockfile: true
  fail_on_missing_lockfile: true
  fail_on_stale_lockfile: true
  direct_dependencies:
    fail_on_wildcard: true
    fail_on_latest: true
    warn_on_semver_range: true
    allow_exact_versions: true
  ci:
    fail_on_new_findings_only: true
    severity_threshold: high
"#;
    assert!(Policy::from_yaml(yaml).is_ok());
}

#[test]
fn policy_disabling_rule_silences_finding() {
    let yaml = r#"
dependency_policy:
  direct_dependencies:
    fail_on_wildcard: false
    fail_on_latest: false
"#;
    let policy = Policy::from_yaml(yaml).expect("policy parses");
    let inv = scan(&fixture("node-app"), &policy).expect("scan");
    assert!(inv.with_code("DEP004").is_empty());
}
