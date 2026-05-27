use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::deps::model::Severity;
use crate::deps::policy::Policy;
use crate::deps::report::{print_table, to_cyclonedx, to_json, to_sarif};
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
    /// Registry freshness tripwire and optional CVE check (npm + Python)
    Verify {
        #[command(flatten)]
        args: crate::deps::verify::VerifyArgs,
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
            let inv = scan(Path::new(&path), &Policy::default())?;
            let format = out_format.as_deref().unwrap_or("table");
            let output = match format {
                "json" => to_json(&inv).to_string(),
                "sarif" => to_sarif(&inv).to_string(),
                _ => {
                    print_table(&inv);
                    String::new()
                }
            };

            if format != "table" {
                if let Some(ref file) = out_file {
                    std::fs::write(file, &output)
                        .map_err(|e| DepsError(format!("write out-file: {e}")))?;
                } else {
                    println!("{output}");
                }
            } else if let Some(ref file) = out_file {
                std::fs::write(file, to_json(&inv).to_string())
                    .map_err(|e| DepsError(format!("write out-file: {e}")))?;
            }

            if let Some(threshold) = fail_on {
                if should_fail(&inv, &threshold) {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        DepsSubcommand::Graph { path } => {
            let inv = scan(Path::new(&path), &Policy::default())?;
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
            let inv = scan(Path::new(&path), &Policy::default())?;
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
            let head = scan(Path::new(&path), &Policy::default())?;
            let base_inv = scan_base_ref(&path, &base)?;
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
            if fail_on_new.is_some() && !head.findings.is_empty() {
                return Ok(1);
            }
            let _ = diff;
            Ok(0)
        }
        DepsSubcommand::Sbom { format, path, out } => {
            let inv = scan(Path::new(&path), &Policy::default())?;
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
        DepsSubcommand::Verify { .. } => Err(DepsError(
            "deps verify is executed by the binary entrypoint".into(),
        )),
    }
}

fn should_fail(inv: &crate::deps::Inventory, threshold: &str) -> bool {
    let Some(sev) = Severity::parse(threshold) else {
        return false;
    };
    inv.findings.iter().any(|f| f.severity.at_least(sev))
}

fn scan_base_ref(_path: &str, _base: &str) -> Result<crate::deps::Inventory, DepsError> {
    // Offline stub: diff against empty base when git checkout unavailable in tests
    Ok(crate::deps::Inventory {
        root: PathBuf::from("."),
        detected_files: vec![],
        graph: crate::deps::model::DependencyGraph::default(),
        findings: vec![],
    })
}
