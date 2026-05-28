use std::cmp::Ordering;
use std::fmt;

/// Canonical package identity: a Package URL, e.g. `pkg:npm/express@4.18.2`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageId(pub String);

impl PackageId {
    pub fn npm(name: &str, version: &str) -> Self {
        Self(format!("pkg:npm/{name}@{version}"))
    }

    pub fn pypi(name: &str, version: &str) -> Self {
        Self(format!("pkg:pypi/{name}@{version}"))
    }

    pub fn maven(group: &str, artifact: &str, version: &str) -> Self {
        Self(format!("pkg:maven/{group}/{artifact}@{version}"))
    }

    pub fn root() -> Self {
        Self("root".into())
    }

    /// The package-name component (`express`, `guava`, `commons-lang3`).
    pub fn name(&self) -> &str {
        if self.0 == "root" {
            return "root";
        }
        let before_at = self.0.rsplit_once('@').map(|(l, _)| l).unwrap_or(&self.0);
        before_at
            .rsplit_once('/')
            .map(|(_, r)| r)
            .unwrap_or(before_at)
    }

    /// The resolved-version component, if the purl carries one.
    pub fn version(&self) -> Option<&str> {
        self.0.rsplit_once('@').map(|(_, v)| v)
    }
}

impl From<String> for PackageId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Maven,
    Go,
    Cargo,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    Production,
    Development,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    Registry,
    PrivateRegistry,
    GitCommit,
    GitBranch,
    GitTag,
    LocalPath,
    RemoteTarball,
    Url,
    Workspace,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn at_least(self, threshold: Severity) -> bool {
        self >= threshold
    }
}

/// How a declared version constraint behaves — drives finding classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintKind {
    Exact,
    BoundedRange,
    Unbounded,
    Mutable,
    GitRef { mutable: bool },
    Url { checksum: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyNode {
    pub(crate) id: PackageId,
    pub(crate) name: String,
    pub(crate) ecosystem: Ecosystem,
    pub(crate) version: Option<String>,
    pub(crate) direct: bool,
    pub(crate) scope: Scope,
    pub(crate) depth: u32,
    pub(crate) source_type: SourceType,
    pub(crate) manifest_file: Option<String>,
    pub(crate) lockfile: Option<String>,
    pub(crate) declared_constraint: Option<String>,
    pub(crate) lock_integrity: Option<bool>,
}

impl DependencyNode {
    pub fn new_npm(name: &str, version: &str) -> Self {
        Self {
            id: PackageId::npm(name, version),
            name: name.to_string(),
            ecosystem: Ecosystem::Npm,
            version: Some(version.to_string()),
            direct: true,
            scope: Scope::Production,
            depth: 1,
            source_type: SourceType::Registry,
            manifest_file: None,
            lockfile: None,
            declared_constraint: None,
            lock_integrity: None,
        }
    }

    pub fn id(&self) -> &PackageId {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_direct(&self) -> bool {
        self.direct
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn source_type(&self) -> SourceType {
        self.source_type
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdge {
    pub(crate) from: PackageId,
    pub(crate) to: PackageId,
    pub(crate) declared_constraint: String,
    pub(crate) resolved_version: Option<String>,
    pub(crate) scope: Scope,
    pub(crate) source_file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyGraph {
    pub(crate) nodes: Vec<DependencyNode>,
    pub(crate) edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    pub fn node(&self, name: &str) -> Option<&DependencyNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn nodes_named(&self, name: &str) -> Vec<&DependencyNode> {
        self.nodes.iter().filter(|n| n.name == name).collect()
    }

    pub fn node_by_id(&self, id: &PackageId) -> Option<&DependencyNode> {
        self.nodes.iter().find(|n| &n.id == id)
    }

    pub fn sort_nodes(&mut self) {
        self.nodes.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        self.edges
            .sort_by(|a, b| a.from.0.cmp(&b.from.0).then_with(|| a.to.0.cmp(&b.to.0)));
    }
}

pub fn compare_versions(a: &str, b: &str) -> Ordering {
    a.cmp(b)
}
