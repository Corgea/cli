use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::Maven};

#[test]
fn maven_classify_hard_version_is_exact() {
    assert_eq!(
        classify_constraint(Maven, "32.1.3-jre"),
        ConstraintKind::Exact
    );
}

#[test]
fn maven_classify_version_range_is_bounded_range() {
    assert_eq!(
        classify_constraint(Maven, "[3.0,4.0)"),
        ConstraintKind::BoundedRange
    );
}

#[test]
fn maven_classify_latest_keyword_is_unbounded() {
    assert_eq!(
        classify_constraint(Maven, "LATEST"),
        ConstraintKind::Unbounded
    );
    assert_eq!(
        classify_constraint(Maven, "RELEASE"),
        ConstraintKind::Unbounded
    );
}

#[test]
fn maven_classify_snapshot_is_mutable() {
    assert_eq!(
        classify_constraint(Maven, "2.0-SNAPSHOT"),
        ConstraintKind::Mutable
    );
}

#[test]
fn gradle_classify_dynamic_plus_is_bounded_range() {
    assert_eq!(
        classify_constraint(Maven, "3.+"),
        ConstraintKind::BoundedRange
    );
}

#[test]
fn gradle_classify_latest_release_is_unbounded() {
    assert_eq!(
        classify_constraint(Maven, "latest.release"),
        ConstraintKind::Unbounded
    );
}

use super::common::scan_fixture;
use crate::deps::model::{PackageId, Severity};

#[test]
fn maven_graph_lists_all_direct_dependencies() {
    let inv = scan_fixture("java-maven");
    for name in ["guava", "commons-lang3", "slf4j-api", "internal-bom"] {
        let n = inv
            .node(name)
            .unwrap_or_else(|| panic!("{name} node missing"));
        assert!(n.is_direct(), "{name} is direct");
    }
}

#[test]
fn maven_purl_identity_includes_group() {
    assert_eq!(
        *scan_fixture("java-gradle").node("guava").unwrap().id(),
        PackageId("pkg:maven/com.google.guava/guava@32.1.3-jre".into())
    );
}

#[test]
fn gradle_graph_resolves_dynamic_version_from_lockfile() {
    assert_eq!(
        scan_fixture("java-gradle")
            .node("commons-lang3")
            .expect("commons-lang3 node missing")
            .version(),
        Some("3.14.0")
    );
}

#[test]
fn maven_range_direct_dep_is_dep003() {
    assert!(scan_fixture("java-maven")
        .findings_for("commons-lang3")
        .iter()
        .any(|f| f.id == "DEP003"));
}

#[test]
fn maven_exact_dep_has_no_pinning_finding() {
    assert!(scan_fixture("java-maven")
        .findings_for("guava")
        .iter()
        .all(|f| f.id != "DEP003" && f.id != "DEP004"));
}

#[test]
fn maven_latest_keyword_is_dep004() {
    let inv = scan_fixture("java-maven");
    let f = inv
        .findings_for("slf4j-api")
        .into_iter()
        .find(|f| f.id == "DEP004")
        .expect("slf4j-api LATEST must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn maven_property_version_resolves_in_graph_and_purl() {
    let inv = scan_fixture("java-maven-props");
    let n = inv.node("guava").expect("guava node missing");
    assert_eq!(n.version(), Some("32.1.3-jre"));
    assert_eq!(
        *n.id(),
        PackageId("pkg:maven/com.google.guava/guava@32.1.3-jre".into())
    );
}

#[test]
fn maven_project_version_placeholder_resolves() {
    let inv = scan_fixture("java-maven-props");
    let n = inv.node("acme-core").expect("acme-core node missing");
    assert_eq!(n.version(), Some("1.2.3"));
    assert_eq!(
        *n.id(),
        PackageId("pkg:maven/com.acme/acme-core@1.2.3".into())
    );
}

#[test]
fn maven_unresolvable_placeholder_passes_through() {
    let inv = scan_fixture("java-maven-props");
    let n = inv.node("mystery-lib").expect("mystery-lib node missing");
    assert_eq!(n.version(), Some("${undefined.version}"));
}

#[test]
fn maven_property_version_resolves_in_cyclonedx_purl() {
    let inv = scan_fixture("java-maven-props");
    let v = crate::deps::report::to_cyclonedx(&inv);
    let components = v["components"].as_array().expect("components array");
    assert!(components
        .iter()
        .any(|c| c["purl"] == "pkg:maven/com.google.guava/guava@32.1.3-jre"));
    assert!(components
        .iter()
        .all(|c| !c["purl"].as_str().unwrap().contains("${guava.version}")));
}

#[test]
fn maven_scan_yields_root_edges() {
    let inv = scan_fixture("java-maven");
    assert!(!inv.graph.edges.is_empty(), "maven graph must carry edges");
    for name in ["guava", "commons-lang3", "slf4j-api", "internal-bom"] {
        let id = inv.node(name).unwrap().id().clone();
        assert!(
            inv.graph
                .edges
                .iter()
                .any(|e| e.from == PackageId::root() && e.to == id),
            "root -> {name} edge missing"
        );
    }
}

#[test]
fn maven_cyclonedx_dependencies_refs_resolve_to_components() {
    let inv = scan_fixture("java-maven");
    let v = crate::deps::report::to_cyclonedx(&inv);
    let deps = v["dependencies"].as_array().expect("dependencies array");
    assert!(!deps.is_empty(), "dependencies array must be non-empty");
    let components = v["components"].as_array().expect("components array");
    let bom_refs: Vec<&str> = components
        .iter()
        .filter_map(|c| c["bom-ref"].as_str())
        .collect();
    for d in deps {
        let from = d["ref"].as_str().expect("ref");
        assert!(from == "root" || bom_refs.contains(&from));
        for to in d["dependsOn"].as_array().expect("dependsOn") {
            assert!(bom_refs.contains(&to.as_str().unwrap()));
        }
    }
}

#[test]
fn maven_snapshot_is_dep021_high() {
    let inv = scan_fixture("java-maven");
    let f = inv
        .findings_for("internal-bom")
        .into_iter()
        .find(|f| f.id == "DEP021")
        .expect("2.0-SNAPSHOT must raise DEP021");
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.recommendation.to_lowercase().contains("snapshot"),
        "recommendation should name SNAPSHOT"
    );
}
