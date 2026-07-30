use super::common::scan_fixture;
use crate::deps::catalog::emitted_definition;
use crate::deps::model::{DependencyEdge, DependencyGraph, DependencyNode, PackageId, Scope};
use crate::deps::report::{table_output, to_cyclonedx, to_json, to_sarif};
use crate::deps::Inventory;

/// Inventory built straight from nodes/edges, for emitter cases the
/// on-disk fixtures don't produce (unresolved versions, duplicates).
fn inventory_with(nodes: Vec<DependencyNode>, edges: Vec<DependencyEdge>) -> Inventory {
    Inventory {
        root: std::path::PathBuf::from("."),
        detected_files: vec![],
        graph: DependencyGraph { nodes, edges },
        findings: vec![],
    }
}

fn root_edge(to: &PackageId) -> DependencyEdge {
    DependencyEdge {
        from: PackageId::root(),
        to: to.clone(),
        declared_constraint: String::new(),
        resolved_version: None,
        scope: Scope::Production,
        source_file: String::new(),
    }
}

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
fn dep004_report_values_remain_catalog_hydrated_and_dynamic() {
    let inv = scan_fixture("node-app");
    let definition = emitted_definition("DEP004").unwrap();
    let finding = inv
        .with_code("DEP004")
        .into_iter()
        .next()
        .expect("node-app emits DEP004");
    let expected_recommendation =
        "Pin to an exact version instead of using wildcard, latest, or unbounded ranges.";

    assert_eq!(finding.title, definition.title);
    assert_eq!(finding.recommendation, expected_recommendation);

    let json = to_json(&inv);
    let json_finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "DEP004")
        .expect("JSON contains DEP004");
    assert_eq!(json_finding["severity"], "High");
    assert_eq!(json_finding["title"], definition.title);
    assert_eq!(json_finding["recommendation"], finding.recommendation);
    assert!(json_finding.get("description").is_none());
    assert!(json_finding.get("remediation").is_none());

    let table = table_output(&inv);
    assert!(table.contains("DEP004  High  Wildcard or latest dependency"));
    assert!(table.contains("package: lodash"));
    assert!(table.contains(expected_recommendation));

    let sarif = to_sarif(&inv);
    let sarif_rule = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == "DEP004")
        .expect("SARIF contains DEP004 rule");
    let sarif_result = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["ruleId"] == "DEP004")
        .expect("SARIF contains DEP004 result");
    assert_eq!(sarif_rule["shortDescription"]["text"], definition.title);
    assert_eq!(sarif_result["level"], "error");
    assert_eq!(sarif_result["message"]["text"], finding.recommendation);
}

#[test]
fn report_cyclonedx_has_components_and_deps() {
    let inv = scan_fixture("node-app");
    let v = to_cyclonedx(&inv);
    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.7");
    let components = v["components"].as_array().expect("components array");
    assert!(components
        .iter()
        .any(|c| c["purl"] == "pkg:npm/express@4.18.2"));
    assert!(components
        .iter()
        .all(|c| c["bom-ref"] == c["purl"] && c["bom-ref"] != "root"));
    assert!(v.get("dependencies").is_some());
}

#[test]
fn report_cyclonedx_has_metadata_and_serial_number() {
    let inv = scan_fixture("node-app");
    let v = to_cyclonedx(&inv);
    let serial = v["serialNumber"].as_str().expect("serialNumber");
    assert!(serial.starts_with("urn:uuid:"));
    assert!(v["metadata"]["timestamp"].as_str().is_some());
    assert_eq!(v["metadata"]["tools"]["components"][0]["name"], "corgea");
    assert_eq!(
        v["metadata"]["tools"]["components"][0]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(v["metadata"]["component"]["type"], "application");
    assert_eq!(v["metadata"]["component"]["name"], "node-app");
}

/// Unresolved versions (`?` placeholder, `${...}` Maven properties) must not
/// surface as a `version` or a fabricated purl — both fail 1.7 validation.
#[test]
fn report_cyclonedx_omits_unresolved_versions_and_purls() {
    let unresolved = DependencyNode::new_npm("left-pad", "?");
    let inv = inventory_with(vec![unresolved], vec![]);
    let v = to_cyclonedx(&inv);
    let c = &v["components"][0];
    assert_eq!(c["name"], "left-pad");
    assert!(
        c.get("version").is_none(),
        "unresolved version must be omitted"
    );
    assert!(
        c.get("purl").is_none(),
        "fabricated @? purl must be omitted"
    );
    assert_eq!(
        c["bom-ref"], "pkg:npm/left-pad@?",
        "bom-ref still identifies the node"
    );
}

/// Multi-module trees list the same package once per manifest; the schema
/// sets uniqueItems on components and dependsOn, so both must deduplicate.
#[test]
fn report_cyclonedx_dedups_components_and_depends_on() {
    let a = DependencyNode::new_npm("express", "4.18.2");
    let b = DependencyNode::new_npm("express", "4.18.2");
    let id = a.id().clone();
    let inv = inventory_with(vec![a, b], vec![root_edge(&id), root_edge(&id)]);
    let v = to_cyclonedx(&inv);
    let components = v["components"].as_array().unwrap();
    assert_eq!(components.len(), 1, "duplicate components must collapse");
    let deps = v["dependencies"].as_array().unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(
        deps[0]["dependsOn"].as_array().unwrap().len(),
        1,
        "duplicate dependsOn entries must collapse"
    );
}

#[test]
fn report_cyclonedx_groups_depends_on_per_ref() {
    let inv = scan_fixture("node-app");
    let v = to_cyclonedx(&inv);
    let deps = v["dependencies"].as_array().expect("dependencies array");
    let mut refs: Vec<&str> = deps.iter().filter_map(|d| d["ref"].as_str()).collect();
    let total = refs.len();
    refs.sort();
    refs.dedup();
    assert_eq!(refs.len(), total, "each ref appears exactly once");
    assert!(deps
        .iter()
        .all(|d| d["dependsOn"].as_array().is_some_and(|a| !a.is_empty())));
}
