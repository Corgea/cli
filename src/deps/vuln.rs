use std::path::Path;

use serde::Deserialize;

use crate::deps::explain;
use crate::deps::findings::{Finding, FindingSource};
use crate::deps::model::{DependencyGraph, Severity};
use crate::deps::DepsError;

#[derive(Debug, Clone)]
pub struct Advisory {
    pub name: String,
    pub vulnerable_versions: Vec<String>,
    pub id: String,
    pub severity: String,
    pub summary: String,
}

pub struct VulnerabilitySource {
    advisories: Vec<Advisory>,
}

#[derive(Deserialize)]
struct VulnDbFile {
    advisories: Vec<AdvisoryRecord>,
}

#[derive(Deserialize)]
struct AdvisoryRecord {
    name: String,
    vulnerable_versions: Vec<String>,
    id: String,
    severity: String,
    summary: String,
}

impl VulnerabilitySource {
    pub fn from_json_file(path: &Path) -> Result<Self, DepsError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| DepsError(format!("read vuln-db: {e}")))?;
        let parsed: VulnDbFile =
            serde_json::from_str(&content).map_err(|e| DepsError(format!("parse vuln-db: {e}")))?;
        Ok(Self {
            advisories: parsed
                .advisories
                .into_iter()
                .map(|a| Advisory {
                    name: a.name,
                    vulnerable_versions: a.vulnerable_versions,
                    id: a.id,
                    severity: a.severity,
                    summary: a.summary,
                })
                .collect(),
        })
    }
}

impl FindingSource for VulnerabilitySource {
    fn enrich(&self, graph: &DependencyGraph) -> Vec<Finding> {
        let mut findings = Vec::new();
        for node in &graph.nodes {
            let Some(version) = &node.version else {
                continue;
            };
            for adv in &self.advisories {
                if adv.name != node.name {
                    continue;
                }
                if !adv.vulnerable_versions.iter().any(|v| v == version) {
                    continue;
                }
                let paths = explain::find_paths_for(graph, &node.name);
                findings.push(Finding {
                    id: "DEP010".into(),
                    severity: parse_advisory_severity(&adv.severity),
                    title: format!("Vulnerable resolved package: {}", adv.id),
                    package: Some(node.id.clone()),
                    source_file: node
                        .manifest_file
                        .clone()
                        .unwrap_or_else(|| "lockfile".into()),
                    declared_constraint: node.declared_constraint.clone(),
                    resolved_version: Some(version.clone()),
                    recommendation: adv.summary.clone(),
                    reproducible: true,
                    paths,
                });
            }
        }
        findings
    }
}

fn parse_advisory_severity(s: &str) -> Severity {
    Severity::parse(s).unwrap_or(Severity::High)
}
