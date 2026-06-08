use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Subcommand};
use serde_json::{json, Value};

use crate::deps::findings::Finding;
use crate::deps::model::{DependencyNode, Severity};
use crate::deps::policy::Policy;
use crate::deps::report::{graph_nodes_json, table_output, to_cyclonedx, to_json, to_sarif};
use crate::deps::{scan, DepsError};

#[derive(Subcommand, Debug, Clone)]
pub enum DepsSubcommand {
    /// Scan manifests and lockfiles, build inventory, evaluate policy
    #[command(
        after_help = "Examples:\n  corgea deps scan --format agent\n  corgea deps scan --format quiet --fail-on high\n  corgea deps scan --out-format sarif --out-file deps.sarif"
    )]
    Scan {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, help = "Fail (exit 1) at or above this severity")]
        fail_on: Option<String>,
        #[arg(long, help = "Output format: table, json, sarif")]
        out_format: Option<String>,
        #[arg(long, help = "Write output to this file")]
        out_file: Option<String>,
        #[command(flatten)]
        render: RenderArgs,
    },
    /// Print the dependency graph
    #[command(
        after_help = "Examples:\n  corgea deps graph --format agent\n  corgea deps graph tests/fixtures/node-app --format json"
    )]
    Graph {
        #[arg(default_value = ".")]
        path: String,
        #[command(flatten)]
        render: RenderArgs,
    },
    /// Explain why a package is present
    #[command(
        after_help = "Examples:\n  corgea deps explain lodash --format agent\n  corgea deps explain left-pad tests/fixtures/node-app --format json"
    )]
    Explain {
        package: String,
        #[arg(default_value = ".")]
        path: String,
        #[command(flatten)]
        render: RenderArgs,
    },
    /// Compare dependency graph against a git ref
    #[command(
        after_help = "Examples:\n  corgea deps diff --base origin/main --format json\n  corgea deps diff --base HEAD . --fail-on-new high"
    )]
    Diff {
        #[arg(long)]
        base: String,
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        fail_on_new: Option<String>,
        #[command(flatten)]
        render: RenderArgs,
    },
    /// Generate an SBOM
    #[command(
        after_help = "Examples:\n  corgea deps sbom --format cyclonedx\n  corgea deps sbom --format cyclonedx --out bom.json"
    )]
    Sbom {
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: DepsPolicySubcommand,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum DepsPolicySubcommand {
    /// Write a starter `.corgea/deps.yml` policy file
    #[command(
        after_help = "Examples:\n  corgea deps policy init\n  corgea deps policy init --exist-ok --format quiet"
    )]
    Init {
        #[arg(default_value = ".")]
        path: String,
        #[arg(
            long,
            help = "Succeed without rewriting when .corgea/deps.yml already exists"
        )]
        exist_ok: bool,
        #[command(flatten)]
        render: RenderArgs,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct RenderArgs {
    #[arg(
        long,
        value_name = "human|agent|json|quiet",
        help = "Render output for humans, agents, JSON parsers, or suppress stdout"
    )]
    format: Option<String>,
}

impl RenderArgs {
    fn is_set(&self) -> bool {
        self.format.is_some()
    }

    fn resolve(&self) -> Result<RenderFormat, DepsError> {
        RenderFormat::resolve(self.format.as_deref())
    }
}

pub fn run(sub: DepsSubcommand) -> u8 {
    match run_inner(sub) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("deps failed: {e}");
            2
        }
    }
}

fn run_inner(sub: DepsSubcommand) -> Result<u8, DepsError> {
    match sub {
        DepsSubcommand::Scan {
            path,
            fail_on,
            out_format,
            out_file,
            render,
        } => {
            if out_format.is_some() && render.is_set() {
                return Err(DepsError(
                    "--format cannot be used with --out-format; choose one output selector"
                        .to_string(),
                ));
            }
            let fail_threshold = fail_on
                .as_deref()
                .map(|threshold| parse_severity(threshold, "--fail-on"))
                .transpose()?;
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            let render_format = if out_format.is_some() {
                None
            } else {
                Some(render.resolve()?)
            };
            let output = if let Some(out_format) = out_format.as_deref() {
                match ReportFormat::parse(out_format)? {
                    ReportFormat::Table => table_output(&inv),
                    ReportFormat::Json => json_line(to_json(&inv)),
                    ReportFormat::Sarif => json_line(to_sarif(&inv)),
                }
            } else {
                render_scan(&inv, render_format.expect("render format resolved"))
            };

            emit_output(&output, out_file.as_deref())?;
            if let Some(format) = render_format {
                emit_scan_hints(&path, &inv, format);
            }

            if let Some(threshold) = fail_threshold {
                if should_fail(&inv, threshold) {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        DepsSubcommand::Graph { path, render } => {
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            let output = render_graph(&inv, render.resolve()?);
            emit_output(&output, None)?;
            Ok(0)
        }
        DepsSubcommand::Explain {
            package,
            path,
            render,
        } => {
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            match crate::deps::explain::explain(&inv.graph, &package) {
                Some(e) => {
                    let output = render_explanation(&package, &e, render.resolve()?);
                    emit_output(&output, None)?;
                }
                None => {
                    return Err(DepsError(format!("package not found: {package}")));
                }
            }
            Ok(0)
        }
        DepsSubcommand::Diff {
            base,
            path,
            fail_on_new,
            render,
        } => {
            let new_threshold = fail_on_new
                .as_deref()
                .map(|threshold| parse_severity(threshold, "--fail-on-new"))
                .transpose()?;
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let head = scan(root, &policy)?;
            let base_inv = scan_base_ref(root, &base)?;
            let diff = crate::deps::diff::diff_graphs(&base_inv.graph, &head.graph);
            let output = render_diff(&base, &diff, render.resolve()?);
            emit_output(&output, None)?;
            if let Some(threshold) = new_threshold {
                if has_new_findings_at_or_above(&base_inv, &head, threshold) {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        DepsSubcommand::Sbom { format, path, out } => {
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            if format != "cyclonedx" {
                return Err(DepsError(format!("unsupported SBOM format: {format}")));
            }
            let sbom = to_cyclonedx(&inv.graph).to_string();
            if let Some(out_path) = out {
                std::fs::write(&out_path, sbom)
                    .map_err(|e| DepsError(format!("write sbom: {e}")))?;
            } else {
                println!("{sbom}");
            }
            Ok(0)
        }
        DepsSubcommand::Policy { command } => match command {
            DepsPolicySubcommand::Init {
                path,
                exist_ok,
                render,
            } => {
                let render_format = render.resolve()?;
                let dir = PathBuf::from(&path).join(".corgea");
                std::fs::create_dir_all(&dir)
                    .map_err(|e| DepsError(format!("create .corgea: {e}")))?;
                let policy_path = dir.join("deps.yml");
                let created = if policy_path.exists() && exist_ok {
                    false
                } else {
                    std::fs::write(&policy_path, Policy::default_yaml())
                        .map_err(|e| DepsError(format!("write policy: {e}")))?;
                    true
                };
                let output = render_policy_init(&policy_path, created, render_format);
                emit_output(&output, None)?;
                emit_policy_init_hint(&path, render_format);
                Ok(0)
            }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportFormat {
    Table,
    Json,
    Sarif,
}

impl ReportFormat {
    fn parse(value: &str) -> Result<Self, DepsError> {
        match value {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            other => Err(DepsError(format!(
                "unsupported --out-format: {other}; expected table, json, or sarif"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderFormat {
    Human,
    Agent,
    Json,
    Quiet,
}

impl RenderFormat {
    fn resolve(value: Option<&str>) -> Result<Self, DepsError> {
        match value {
            Some("human") => Ok(Self::Human),
            Some("agent") => Ok(Self::Agent),
            Some("json") => Ok(Self::Json),
            Some("quiet") => Ok(Self::Quiet),
            Some(other) => Err(DepsError(format!(
                "unsupported --format: {other}; expected human, agent, json, or quiet"
            ))),
            None if agent_env_detected() => Ok(Self::Agent),
            None => Ok(Self::Human),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Json => "json",
            Self::Quiet => "quiet",
        }
    }
}

fn agent_env_detected() -> bool {
    [
        "AI_AGENT",
        "CODEX_SANDBOX",
        "CLAUDECODE",
        "CLAUDE_CODE",
        "CURSOR_AGENT",
        "CURSOR_TRACE_ID",
        "GEMINI_CLI",
        "PI_AGENT",
    ]
    .iter()
    .any(|name| match std::env::var(name) {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty() && normalized != "0" && normalized != "false"
        }
        Err(_) => false,
    })
}

fn emit_output(output: &str, out_file: Option<&str>) -> Result<(), DepsError> {
    if let Some(file) = out_file {
        std::fs::write(file, output).map_err(|e| DepsError(format!("write out-file: {e}")))?;
    } else if !output.is_empty() {
        print!("{output}");
    }
    Ok(())
}

fn json_line(value: Value) -> String {
    format!("{value}\n")
}

fn emit_scan_hints(path: &str, inv: &crate::deps::Inventory, format: RenderFormat) {
    if format == RenderFormat::Quiet {
        return;
    }

    let format = format.as_str();
    if let Some(package) = inv
        .findings
        .iter()
        .filter_map(|finding| finding.package.as_ref())
        .map(|package| package.name())
        .find(|name| *name != "project")
    {
        eprintln!(
            "Hint: Run `corgea deps explain {} {} --format {}` to inspect why this package is present.",
            shell_word(package),
            shell_word(path),
            format
        );
    }

    eprintln!(
        "Hint: Run `corgea deps diff --base origin/main {} --format {}` before merging dependency changes.",
        shell_word(path),
        format
    );
}

fn emit_policy_init_hint(path: &str, format: RenderFormat) {
    if format == RenderFormat::Quiet {
        return;
    }

    eprintln!(
        "Hint: Run `corgea deps scan {} --format json` to verify the policy.",
        shell_word(path)
    );
}

fn render_scan(inv: &crate::deps::Inventory, format: RenderFormat) -> String {
    match format {
        RenderFormat::Human => table_output(inv),
        RenderFormat::Agent => agent_scan_output(inv),
        RenderFormat::Json => json_line(to_json(inv)),
        RenderFormat::Quiet => String::new(),
    }
}

fn agent_scan_output(inv: &crate::deps::Inventory) -> String {
    let mut out = String::new();
    out.push_str("record\troot\tdetected_files\tpackages\tfindings\n");
    out.push_str(&format!(
        "summary\t{}\t{}\t{}\t{}\n",
        tsv_cell(&inv.root.display().to_string()),
        inv.detected_files.len(),
        inv.graph.nodes.len(),
        inv.findings.len()
    ));
    out.push_str("record\tid\tseverity\tpackage\ttitle\trecommendation\n");
    for finding in &inv.findings {
        let package = finding
            .package
            .as_ref()
            .map(|package| package.0.as_str())
            .unwrap_or("project");
        out.push_str(&format!(
            "finding\t{}\t{:?}\t{}\t{}\t{}\n",
            tsv_cell(&finding.id),
            finding.severity,
            tsv_cell(package),
            tsv_cell(&finding.title),
            tsv_cell(&finding.recommendation)
        ));
    }
    out
}

fn render_graph(inv: &crate::deps::Inventory, format: RenderFormat) -> String {
    match format {
        RenderFormat::Human => human_graph_output(inv),
        RenderFormat::Agent => agent_graph_output(inv),
        RenderFormat::Json => json_line(json!({ "nodes": graph_nodes_json(&inv.graph) })),
        RenderFormat::Quiet => String::new(),
    }
}

fn human_graph_output(inv: &crate::deps::Inventory) -> String {
    let mut out = String::new();
    for node in &inv.graph.nodes {
        out.push_str(&format!(
            "{} {} direct={} scope={:?} depth={}\n",
            node.name(),
            node.version().unwrap_or("?"),
            node.is_direct(),
            node.scope(),
            node.depth()
        ));
    }
    out
}

fn agent_graph_output(inv: &crate::deps::Inventory) -> String {
    let mut out = String::from("id\tname\tversion\tdirect\tscope\tdepth\n");
    for node in &inv.graph.nodes {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{:?}\t{}\n",
            tsv_cell(&node.id().0),
            tsv_cell(node.name()),
            tsv_cell(node.version().unwrap_or("")),
            node.is_direct(),
            node.scope(),
            node.depth()
        ));
    }
    out
}

fn render_explanation(
    package: &str,
    explanation: &crate::deps::explain::Explanation,
    format: RenderFormat,
) -> String {
    match format {
        RenderFormat::Human => human_explanation_output(package, explanation),
        RenderFormat::Agent => agent_explanation_output(package, explanation),
        RenderFormat::Json => json_line(explanation_json(package, explanation)),
        RenderFormat::Quiet => String::new(),
    }
}

fn human_explanation_output(
    package: &str,
    explanation: &crate::deps::explain::Explanation,
) -> String {
    let mut out = format!(
        "{} direct={} depth={}\n",
        package, explanation.direct, explanation.depth
    );
    for path in &explanation.paths {
        let line: Vec<_> = path.iter().map(|package| package.name()).collect();
        out.push_str(&format!("  path: {}\n", line.join(" -> ")));
    }
    out
}

fn agent_explanation_output(
    package: &str,
    explanation: &crate::deps::explain::Explanation,
) -> String {
    let mut out = String::from("record\tpackage\tdirect\tdepth\tpath\n");
    for path in &explanation.paths {
        let line: Vec<_> = path.iter().map(|package| package.name()).collect();
        out.push_str(&format!(
            "path\t{}\t{}\t{}\t{}\n",
            tsv_cell(package),
            explanation.direct,
            explanation.depth,
            tsv_cell(&line.join(" -> "))
        ));
    }
    out
}

fn explanation_json(package: &str, explanation: &crate::deps::explain::Explanation) -> Value {
    let paths: Vec<Vec<&str>> = explanation
        .paths
        .iter()
        .map(|path| path.iter().map(|package| package.name()).collect())
        .collect();
    json!({
        "package": package,
        "direct": explanation.direct,
        "depth": explanation.depth,
        "paths": paths,
    })
}

fn render_diff(base: &str, diff: &crate::deps::diff::GraphDiff, format: RenderFormat) -> String {
    match format {
        RenderFormat::Human => human_diff_output(base, diff),
        RenderFormat::Agent => agent_diff_output(diff),
        RenderFormat::Json => json_line(diff_json(base, diff)),
        RenderFormat::Quiet => String::new(),
    }
}

fn human_diff_output(base: &str, diff: &crate::deps::diff::GraphDiff) -> String {
    let mut out = format!("Dependency diff against {base}\n");
    for node in &diff.added {
        out.push_str(&format!(
            "  + {}@{}\n",
            node.name(),
            node.version().unwrap_or("?")
        ));
    }
    for node in &diff.removed {
        out.push_str(&format!(
            "  - {}@{}\n",
            node.name(),
            node.version().unwrap_or("?")
        ));
    }
    for change in &diff.changed {
        out.push_str(&format!(
            "  ~ {} {} -> {}\n",
            change.name, change.from, change.to
        ));
    }
    out
}

fn agent_diff_output(diff: &crate::deps::diff::GraphDiff) -> String {
    let mut out = String::from("change\tname\tfrom\tto\n");
    for node in &diff.added {
        out.push_str(&format!(
            "added\t{}\t\t{}\n",
            tsv_cell(node.name()),
            tsv_cell(node.version().unwrap_or(""))
        ));
    }
    for node in &diff.removed {
        out.push_str(&format!(
            "removed\t{}\t{}\t\n",
            tsv_cell(node.name()),
            tsv_cell(node.version().unwrap_or(""))
        ));
    }
    for change in &diff.changed {
        out.push_str(&format!(
            "changed\t{}\t{}\t{}\n",
            tsv_cell(&change.name),
            tsv_cell(&change.from),
            tsv_cell(&change.to)
        ));
    }
    out
}

fn diff_json(base: &str, diff: &crate::deps::diff::GraphDiff) -> Value {
    let changed: Vec<Value> = diff
        .changed
        .iter()
        .map(|change| {
            json!({
                "name": change.name,
                "from": change.from,
                "to": change.to,
            })
        })
        .collect();
    json!({
        "base": base,
        "added": diff_nodes_json(&diff.added),
        "removed": diff_nodes_json(&diff.removed),
        "changed": changed,
    })
}

fn diff_nodes_json(nodes: &[DependencyNode]) -> Vec<Value> {
    nodes
        .iter()
        .map(|node| {
            json!({
                "name": node.name(),
                "version": node.version(),
            })
        })
        .collect()
}

fn render_policy_init(path: &Path, created: bool, format: RenderFormat) -> String {
    let path = path.display().to_string();
    match format {
        RenderFormat::Human if created => format!("Wrote {path}\n"),
        RenderFormat::Human => format!("Exists {path}\n"),
        RenderFormat::Agent => format!("path\n{}\n", tsv_cell(&path)),
        RenderFormat::Json => json_line(json!({ "path": path, "created": created })),
        RenderFormat::Quiet => String::new(),
    }
}

fn tsv_cell(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '@'))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

fn load_policy(root: &Path) -> Result<Policy, DepsError> {
    let policy_path = root.join(".corgea").join("deps.yml");
    if !policy_path.exists() {
        return Ok(Policy::default());
    }
    let yaml = std::fs::read_to_string(&policy_path)
        .map_err(|e| DepsError(format!("read policy {}: {e}", policy_path.display())))?;
    Policy::from_yaml(&yaml)
        .map_err(|e| DepsError(format!("load policy {}: {}", policy_path.display(), e.0)))
}

fn parse_severity(value: &str, option: &str) -> Result<Severity, DepsError> {
    Severity::parse(value).ok_or_else(|| {
        DepsError(format!(
            "unsupported severity for {option}: {value}; expected info, low, medium, high, or critical"
        ))
    })
}

fn should_fail(inv: &crate::deps::Inventory, threshold: Severity) -> bool {
    inv.findings.iter().any(|f| f.severity.at_least(threshold))
}

fn has_new_findings_at_or_above(
    base: &crate::deps::Inventory,
    head: &crate::deps::Inventory,
    threshold: Severity,
) -> bool {
    let base_keys: HashSet<String> = base.findings.iter().map(finding_key).collect();
    head.findings
        .iter()
        .any(|f| f.severity.at_least(threshold) && !base_keys.contains(&finding_key(f)))
}

fn finding_key(finding: &Finding) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}",
        finding.id,
        finding.package.as_ref().map(|p| p.0.as_str()).unwrap_or(""),
        finding.source_file,
        finding.declared_constraint.as_deref().unwrap_or(""),
        finding.resolved_version.as_deref().unwrap_or("")
    )
}

fn scan_base_ref(path: &Path, base: &str) -> Result<crate::deps::Inventory, DepsError> {
    let head_path = std::fs::canonicalize(path)
        .map_err(|e| DepsError(format!("resolve scan path {}: {e}", path.display())))?;
    let repo_root_raw = git_output(&head_path, &["rev-parse", "--show-toplevel"])?;
    let repo_root = std::fs::canonicalize(PathBuf::from(repo_root_raw.trim()))
        .map_err(|e| DepsError(format!("resolve git root: {e}")))?;
    let rel_path = head_path.strip_prefix(&repo_root).map_err(|_| {
        DepsError(format!(
            "scan path {} is outside git root {}",
            head_path.display(),
            repo_root.display()
        ))
    })?;

    let temp = tempfile::TempDir::new()
        .map_err(|e| DepsError(format!("create temporary worktree directory: {e}")))?;
    let worktree = temp.path().join("base");
    git_output_os(
        &repo_root,
        vec![
            OsString::from("worktree"),
            OsString::from("add"),
            OsString::from("--detach"),
            OsString::from("--quiet"),
            worktree.as_os_str().to_os_string(),
            OsString::from(base),
        ],
    )?;

    let base_path = if rel_path.as_os_str().is_empty() {
        worktree.clone()
    } else {
        worktree.join(rel_path)
    };
    let result = if base_path.exists() {
        load_policy(&base_path).and_then(|policy| scan(&base_path, &policy))
    } else {
        Err(DepsError(format!(
            "path {} does not exist at base ref {base}",
            path.display()
        )))
    };
    let cleanup = git_output_os(
        &repo_root,
        vec![
            OsString::from("worktree"),
            OsString::from("remove"),
            OsString::from("--force"),
            worktree.as_os_str().to_os_string(),
        ],
    );

    match (result, cleanup) {
        (Ok(inv), Ok(_)) => Ok(inv),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(DepsError(format!("cleanup base worktree: {e}"))),
    }
}

fn git_output(repo: &Path, args: &[&str]) -> Result<String, DepsError> {
    git_output_os(repo, args.iter().map(OsString::from).collect())
}

fn git_output_os(repo: &Path, args: Vec<OsString>) -> Result<String, DepsError> {
    let mut command = Command::new("git");
    for var in GIT_LOCAL_ENV_VARS {
        command.env_remove(var);
    }
    let output = command
        .current_dir(repo)
        .args(args)
        .output()
        .map_err(|e| DepsError(format!("run git: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DepsError(format!("git failed: {}", stderr.trim())));
    }
    String::from_utf8(output.stdout).map_err(|e| DepsError(format!("read git output: {e}")))
}

const GIT_LOCAL_ENV_VARS: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];
