use std::collections::{HashMap, VecDeque};

use crate::deps::model::{DependencyGraph, PackageId};

#[derive(Debug)]
pub struct Explanation {
    pub package: PackageId,
    pub direct: bool,
    pub depth: u32,
    pub paths: Vec<Vec<PackageId>>,
}

pub fn explain(graph: &DependencyGraph, package: &str) -> Option<Explanation> {
    let node = graph.node(package)?;
    let paths = find_paths_for(graph, package);
    Some(Explanation {
        package: node.id.clone(),
        direct: node.is_direct(),
        depth: node.depth(),
        paths,
    })
}

pub fn find_paths_for(graph: &DependencyGraph, package: &str) -> Vec<Vec<PackageId>> {
    find_paths(graph, package)
}

fn find_paths(graph: &DependencyGraph, target: &str) -> Vec<Vec<PackageId>> {
    let target_id = graph.node(target).map(|n| n.id.clone());
    let Some(target_id) = target_id else {
        return vec![];
    };

    let mut adj: HashMap<String, Vec<PackageId>> = HashMap::new();
    for edge in &graph.edges {
        let from_key = if edge.from.0 == "root" {
            "root".to_string()
        } else {
            edge.from.name().to_string()
        };
        adj.entry(from_key).or_default().push(edge.to.clone());
    }

    let mut paths = Vec::new();
    let mut queue: VecDeque<Vec<PackageId>> = VecDeque::new();
    queue.push_back(vec![PackageId::root()]);

    while let Some(path) = queue.pop_front() {
        let last = path.last().unwrap();
        if last.name() == target || &target_id == last {
            paths.push(path);
            continue;
        }
        if path.len() > 10 {
            continue;
        }
        let key = if last.0 == "root" {
            "root".to_string()
        } else {
            last.name().to_string()
        };
        if let Some(children) = adj.get(&key) {
            for child in children {
                if path.iter().any(|p| p == child) {
                    continue;
                }
                let mut next = path.clone();
                next.push(child.clone());
                queue.push_back(next);
            }
        } else if last.name() == target {
            paths.push(path);
        }
    }

    if paths.is_empty() && graph.node(target).is_some() {
        paths.push(vec![PackageId::root(), target_id]);
    }

    paths.sort_by_key(|a| a.len());
    paths
}
