use std::collections::{BTreeMap, HashSet};

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
    let mut base_map: BTreeMap<String, &DependencyNode> = BTreeMap::new();
    for n in &base.nodes {
        if n.version.is_some() {
            base_map.insert(n.id().0.clone(), n);
        }
    }
    let mut head_map: BTreeMap<String, &DependencyNode> = BTreeMap::new();
    for n in &head.nodes {
        if n.version.is_some() {
            head_map.insert(n.id().0.clone(), n);
        }
    }

    let mut added = Vec::new();
    let mut artifact_changed = Vec::new();
    for n in &head.nodes {
        if n.version.is_none() {
            continue;
        }
        match base_map.get(&n.id().0) {
            None => added.push(n.clone()),
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
        if n.version.is_some() && !head_map.contains_key(&n.id().0) {
            removed.push(n.clone());
        }
    }

    let (added, removed, changed) = pair_version_changes(added, removed);

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

fn pair_version_changes(
    added: Vec<DependencyNode>,
    removed: Vec<DependencyNode>,
) -> (Vec<DependencyNode>, Vec<DependencyNode>, Vec<VersionChange>) {
    let mut added_by_package: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, node) in added.iter().enumerate() {
        added_by_package
            .entry(versionless_identity(node))
            .or_default()
            .push(idx);
    }

    let mut removed_by_package: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, node) in removed.iter().enumerate() {
        removed_by_package
            .entry(versionless_identity(node))
            .or_default()
            .push(idx);
    }

    let mut paired_added = HashSet::new();
    let mut paired_removed = HashSet::new();
    let mut changed = Vec::new();
    for (key, removed_indices) in &removed_by_package {
        let Some(added_indices) = added_by_package.get(key) else {
            continue;
        };
        if removed_indices.len() != 1 || added_indices.len() != 1 {
            continue;
        }
        let removed_idx = removed_indices[0];
        let added_idx = added_indices[0];
        let old = &removed[removed_idx];
        let new = &added[added_idx];
        changed.push(VersionChange {
            name: new.name().to_string(),
            from: old.version().unwrap_or("").to_string(),
            to: new.version().unwrap_or("").to_string(),
        });
        paired_removed.insert(removed_idx);
        paired_added.insert(added_idx);
    }

    let added = added
        .into_iter()
        .enumerate()
        .filter_map(|(idx, node)| (!paired_added.contains(&idx)).then_some(node))
        .collect();
    let removed = removed
        .into_iter()
        .enumerate()
        .filter_map(|(idx, node)| (!paired_removed.contains(&idx)).then_some(node))
        .collect();
    (added, removed, changed)
}

fn versionless_identity(node: &DependencyNode) -> String {
    node.id()
        .0
        .rsplit_once('@')
        .map(|(package, _)| package.to_string())
        .unwrap_or_else(|| node.id().0.clone())
}
