use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Subcommand;

use crate::deps::findings::Finding;
use crate::deps::model::Severity;
use crate::deps::policy::Policy;
use crate::deps::report::{print_table, table_output, to_cyclonedx, to_json, to_sarif};
use crate::deps::{scan, DepsError};

#[derive(Subcommand, Debug, Clone)]
pub enum DepsSubcommand {
    /// Scan manifests and lockfiles, build inventory, evaluate policy
    Scan {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, help = "Fail (exit 1) at or above this severity")]
        fail_on: Option<String>,
        #[arg(long, help = "Output format: table, json, sarif")]
        out_format: Option<String>,
        #[arg(long, help = "Write output to this file")]
        out_file: Option<String>,
    },
    /// Print the dependency graph
    Graph {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Explain why a package is present
    Explain {
        package: String,
        #[arg(default_value = ".")]
        path: String,
    },
    /// Compare dependency graph against a git ref
    Diff {
        #[arg(long)]
        base: String,
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        fail_on_new: Option<String>,
    },
    /// Generate an SBOM
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
    Init {
        #[arg(default_value = ".")]
        path: String,
    },
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
        } => {
            let format = OutputFormat::parse(out_format.as_deref())?;
            let fail_threshold = fail_on
                .as_deref()
                .map(|threshold| parse_severity(threshold, "--fail-on"))
                .transpose()?;
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            let output = match format {
                OutputFormat::Table => table_output(&inv),
                OutputFormat::Json => to_json(&inv).to_string(),
                OutputFormat::Sarif => to_sarif(&inv).to_string(),
            };

            if let Some(ref file) = out_file {
                std::fs::write(file, &output)
                    .map_err(|e| DepsError(format!("write out-file: {e}")))?;
            } else if format == OutputFormat::Table {
                print_table(&inv);
            } else {
                println!("{output}");
            }

            if let Some(threshold) = fail_threshold {
                if should_fail(&inv, threshold) {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        DepsSubcommand::Graph { path } => {
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            for n in &inv.graph.nodes {
                println!(
                    "{} {} direct={} scope={:?} depth={}",
                    n.name(),
                    n.version().unwrap_or("?"),
                    n.is_direct(),
                    n.scope(),
                    n.depth()
                );
            }
            Ok(0)
        }
        DepsSubcommand::Explain { package, path } => {
            let root = Path::new(&path);
            let policy = load_policy(root)?;
            let inv = scan(root, &policy)?;
            match crate::deps::explain::explain(&inv.graph, &package) {
                Some(e) => {
                    println!("{} direct={} depth={}", package, e.direct, e.depth);
                    for path in &e.paths {
                        let line: Vec<_> = path.iter().map(|p| p.name()).collect();
                        println!("  path: {}", line.join(" -> "));
                    }
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
            println!("Dependency diff against {base}");
            for n in &diff.added {
                println!("  + {}@{}", n.name(), n.version().unwrap_or("?"));
            }
            for n in &diff.removed {
                println!("  - {}@{}", n.name(), n.version().unwrap_or("?"));
            }
            for c in &diff.changed {
                println!("  ~ {} {} -> {}", c.name, c.from, c.to);
            }
            if let Some(threshold) = new_threshold {
                if has_new_findings_at_or_above(&base_inv, &head, threshold) {
                    return Ok(1);
                }
            }
            let _ = diff;
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
            DepsPolicySubcommand::Init { path } => {
                let dir = PathBuf::from(path).join(".corgea");
                std::fs::create_dir_all(&dir)
                    .map_err(|e| DepsError(format!("create .corgea: {e}")))?;
                let policy_path = dir.join("deps.yml");
                std::fs::write(&policy_path, Policy::default_yaml())
                    .map_err(|e| DepsError(format!("write policy: {e}")))?;
                println!("Wrote {}", policy_path.display());
                Ok(0)
            }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
}

impl OutputFormat {
    fn parse(value: Option<&str>) -> Result<Self, DepsError> {
        match value.unwrap_or("table") {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            other => Err(DepsError(format!(
                "unsupported --out-format: {other}; expected table, json, or sarif"
            ))),
        }
    }
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
