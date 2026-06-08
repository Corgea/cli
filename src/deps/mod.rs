//! Offline dependency inventory, policy evaluation, and graph analysis.

#![allow(dead_code)] // library surface exceeds current bin wiring (Slice 8 vuln-api deferred)

pub mod detect;
pub mod diff;
pub mod ecosystems;
pub mod explain;
pub mod findings;
pub mod model;
pub mod parse;
pub mod policy;
pub mod report;
pub mod run;
pub mod skill;

use std::path::{Path, PathBuf};

use detect::DetectedFile;
use ecosystems::evaluate::ScanContext;
use findings::Finding;
use model::DependencyGraph;
use policy::Policy;

#[derive(Debug)]
pub struct DepsError(pub String);

impl std::fmt::Display for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DepsError {}

/// Full result of a dependency scan of one directory tree.
#[derive(Debug)]
pub struct Inventory {
    pub root: PathBuf,
    pub detected_files: Vec<DetectedFile>,
    pub graph: DependencyGraph,
    pub findings: Vec<Finding>,
}

impl Inventory {
    pub fn with_code(&self, code: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.id == code).collect()
    }

    pub fn findings_for(&self, name: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.package.as_ref().is_some_and(|p| p.name() == name))
            .collect()
    }

    pub fn node(&self, name: &str) -> Option<&model::DependencyNode> {
        self.graph.node(name)
    }
}

/// Scan a directory tree: detect files, build the graph, evaluate policy.
pub fn scan(root: &Path, policy: &Policy) -> Result<Inventory, DepsError> {
    let detected = detect::detect_dependency_files(root);
    let mut graph = DependencyGraph::default();
    let mut findings = Vec::new();

    // Invalid npm lockfile in tree
    for f in &detected {
        if f.kind == detect::DepFileKind::NpmLockfile {
            ecosystems::evaluate::read_json(&f.path)?;
        }
    }

    let mut ctx = ScanContext {
        root,
        policy,
        detected: &detected,
        graph: &mut graph,
        findings: &mut findings,
    };
    ecosystems::scan_all(&mut ctx)?;

    ecosystems::evaluate::dep014(&mut findings, &graph);

    Ok(Inventory {
        root: root.to_path_buf(),
        detected_files: detected,
        graph,
        findings,
    })
}

#[cfg(test)]
mod tests;
