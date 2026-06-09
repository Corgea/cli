use super::common::scan_fixture;
use crate::deps::explain::explain;

#[test]
fn explain_transitive_shows_path() {
    let inv = scan_fixture("node-app");
    let e = explain(&inv.graph, "qs").expect("qs should be explainable");
    assert!(!e.direct);
    assert_eq!(e.depth, 2);
    let path = e.paths.first().expect("at least one path");
    assert_eq!(path.first().map(|id| id.0.as_str()), Some("root"));
    assert!(path.iter().any(|id| id.name() == "express"));
    assert_eq!(path.last().map(|id| id.name()), Some("qs"));
}

#[test]
fn explain_unknown_package_is_none() {
    let inv = scan_fixture("node-app");
    assert!(explain(&inv.graph, "does-not-exist").is_none());
}
