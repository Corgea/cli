use crate::deps::model::{DependencyGraph, DependencyNode};

#[derive(Debug)]
pub struct VersionChange {
    pub name: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug)]
pub struct GraphDiff {
    pub added: Vec<DependencyNode>,
    pub removed: Vec<DependencyNode>,
    pub changed: Vec<VersionChange>,
}

pub fn diff_graphs(base: &DependencyGraph, head: &DependencyGraph) -> GraphDiff {
    let mut base_map: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for n in &base.nodes {
        if let Some(v) = &n.version {
            base_map.insert(n.name.clone(), v.clone());
        }
    }
    let mut head_map: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for n in &head.nodes {
        if let Some(v) = &n.version {
            head_map.insert(n.name.clone(), v.clone());
        }
    }

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for n in &head.nodes {
        match base_map.get(&n.name) {
            None => added.push(n.clone()),
            Some(old) if n.version.as_deref() != Some(old.as_str()) => {
                if let Some(new_v) = &n.version {
                    changed.push(VersionChange {
                        name: n.name.clone(),
                        from: old.clone(),
                        to: new_v.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    let mut removed = Vec::new();
    for n in &base.nodes {
        if !head_map.contains_key(&n.name) {
            removed.push(n.clone());
        }
    }

    GraphDiff {
        added,
        removed,
        changed,
    }
}
