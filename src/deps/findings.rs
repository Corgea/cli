use crate::deps::model::{PackageId, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub package: Option<PackageId>,
    pub source_file: String,
    pub declared_constraint: Option<String>,
    pub resolved_version: Option<String>,
    pub recommendation: String,
    pub reproducible: bool,
    pub paths: Vec<Vec<PackageId>>,
}

pub trait FindingSource {
    fn enrich(&self, graph: &crate::deps::model::DependencyGraph) -> Vec<Finding>;
}

pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| {
                a.package
                    .as_ref()
                    .map(|p| p.name().to_string())
                    .unwrap_or_default()
                    .cmp(
                        &b.package
                            .as_ref()
                            .map(|p| p.name().to_string())
                            .unwrap_or_default(),
                    )
            })
    });
}
