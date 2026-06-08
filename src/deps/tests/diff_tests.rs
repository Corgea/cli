use crate::deps::diff::diff_graphs;
use crate::deps::model::{DependencyGraph, DependencyNode};

fn graph(nodes: Vec<DependencyNode>) -> DependencyGraph {
    DependencyGraph {
        nodes,
        edges: vec![],
    }
}

fn npm_with_artifact(
    name: &str,
    version: &str,
    resolved: Option<&str>,
    integrity: Option<&str>,
) -> DependencyNode {
    let mut node = DependencyNode::new_npm(name, version);
    node.lock_resolved = resolved.map(str::to_string);
    node.lock_integrity_hash = integrity.map(str::to_string);
    node
}

#[test]
fn diff_detects_added_removed_changed() {
    let base = graph(vec![
        DependencyNode::new_npm("lodash", "4.17.20"),
        DependencyNode::new_npm("request", "2.88.2"),
    ]);
    let head = graph(vec![
        DependencyNode::new_npm("lodash", "4.17.21"),
        DependencyNode::new_npm("axios", "1.8.2"),
    ]);
    let d = diff_graphs(&base, &head);
    assert!(d.added.iter().any(|n| n.name() == "axios"));
    assert!(d.removed.iter().any(|n| n.name() == "request"));
    assert!(d
        .changed
        .iter()
        .any(|c| c.name == "lodash" && c.from == "4.17.20" && c.to == "4.17.21"));
    assert!(d.added.iter().all(|n| n.name() != "lodash"));
}

#[test]
fn diff_detects_same_version_integrity_change() {
    let base = graph(vec![npm_with_artifact(
        "lodash",
        "4.17.21",
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        Some("sha512-old"),
    )]);
    let head = graph(vec![npm_with_artifact(
        "lodash",
        "4.17.21",
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        Some("sha512-new"),
    )]);

    let d = diff_graphs(&base, &head);

    assert!(d.changed.is_empty());
    assert_eq!(d.artifact_changed.len(), 1);
    let change = &d.artifact_changed[0];
    assert_eq!(change.name, "lodash");
    assert_eq!(change.version, "4.17.21");
    assert_eq!(change.old_integrity.as_deref(), Some("sha512-old"));
    assert_eq!(change.new_integrity.as_deref(), Some("sha512-new"));
}

#[test]
fn diff_detects_same_version_resolved_change() {
    let base = graph(vec![npm_with_artifact(
        "lodash",
        "4.17.21",
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        Some("sha512-same"),
    )]);
    let head = graph(vec![npm_with_artifact(
        "lodash",
        "4.17.21",
        Some("https://mirror.example/lodash/-/lodash-4.17.21.tgz"),
        Some("sha512-same"),
    )]);

    let d = diff_graphs(&base, &head);

    assert!(d.changed.is_empty());
    assert_eq!(d.artifact_changed.len(), 1);
    let change = &d.artifact_changed[0];
    assert_eq!(
        change.old_resolved.as_deref(),
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
    );
    assert_eq!(
        change.new_resolved.as_deref(),
        Some("https://mirror.example/lodash/-/lodash-4.17.21.tgz")
    );
}
