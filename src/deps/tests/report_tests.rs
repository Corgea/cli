use super::common::scan_fixture;
use crate::deps::report::{to_cyclonedx, to_json, to_sarif};

#[test]
fn report_json_has_findings_and_graph() {
    let v = to_json(&scan_fixture("node-app"));
    assert!(v.get("nodes").and_then(|n| n.as_array()).is_some());
    assert!(v.get("findings").and_then(|f| f.as_array()).is_some());
}

#[test]
fn report_sarif_has_rules_and_results() {
    let v = to_sarif(&scan_fixture("node-app"));
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "corgea-deps");
    let results = v["runs"][0]["results"].as_array().expect("results array");
    assert!(results.iter().any(|r| r["ruleId"] == "DEP004"));
}

#[test]
fn report_cyclonedx_has_components_and_deps() {
    let inv = scan_fixture("node-app");
    let v = to_cyclonedx(&inv.graph);
    assert_eq!(v["bomFormat"], "CycloneDX");
    let components = v["components"].as_array().expect("components array");
    assert!(components
        .iter()
        .any(|c| c["purl"] == "pkg:npm/express@4.18.2"));
    assert!(v.get("dependencies").is_some());
}
