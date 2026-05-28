use crate::deps::diff::diff_graphs;
use crate::deps::model::{DependencyGraph, DependencyNode};

fn graph(nodes: Vec<DependencyNode>) -> DependencyGraph {
    DependencyGraph {
        nodes,
        edges: vec![],
    }
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
