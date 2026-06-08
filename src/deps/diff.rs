use crate::deps::model::{DependencyGraph, DependencyNode};

#[derive(Debug)]
pub struct VersionChange {
    pub name: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug)]
pub struct ArtifactChange {
    pub name: String,
    pub version: String,
    pub old_resolved: Option<String>,
    pub new_resolved: Option<String>,
    pub old_integrity: Option<String>,
    pub new_integrity: Option<String>,
}

#[derive(Debug)]
pub struct GraphDiff {
    pub added: Vec<DependencyNode>,
    pub removed: Vec<DependencyNode>,
    pub changed: Vec<VersionChange>,
    pub artifact_changed: Vec<ArtifactChange>,
}

pub fn diff_graphs(base: &DependencyGraph, head: &DependencyGraph) -> GraphDiff {
    let mut base_map: std::collections::BTreeMap<String, &DependencyNode> =
        std::collections::BTreeMap::new();
    for n in &base.nodes {
        if n.version.is_some() {
            base_map.insert(n.name.clone(), n);
        }
    }
    let mut head_map: std::collections::BTreeMap<String, &DependencyNode> =
        std::collections::BTreeMap::new();
    for n in &head.nodes {
        if n.version.is_some() {
            head_map.insert(n.name.clone(), n);
        }
    }

    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut artifact_changed = Vec::new();
    for n in &head.nodes {
        match base_map.get(&n.name) {
            None => added.push(n.clone()),
            Some(old) if n.version != old.version => {
                if let Some(new_v) = &n.version {
                    changed.push(VersionChange {
                        name: n.name.clone(),
                        from: old.version.clone().unwrap_or_default(),
                        to: new_v.clone(),
                    });
                }
            }
            Some(old) if artifact_metadata_changed(old, n) => {
                if let Some(version) = &n.version {
                    artifact_changed.push(ArtifactChange {
                        name: n.name.clone(),
                        version: version.clone(),
                        old_resolved: old.lock_resolved.clone(),
                        new_resolved: n.lock_resolved.clone(),
                        old_integrity: old.lock_integrity_hash.clone(),
                        new_integrity: n.lock_integrity_hash.clone(),
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
        artifact_changed,
    }
}

fn artifact_metadata_changed(base: &DependencyNode, head: &DependencyNode) -> bool {
    base.lock_resolved != head.lock_resolved || base.lock_integrity_hash != head.lock_integrity_hash
}
