//! `corgea uv` routing: `uv pip install` / `uv add` reuse the parsed-install
//! gate; `uv sync` is gated from `uv.lock`.

use super::{
    corgea_cmd, detect, exec, parse, tree, verdict, PackageManager, PrecheckOptions,
    PrecheckReport, TreeOrigin, TreeOutcome, TreeReport,
};

pub(super) fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    let json = opts.json;
    let exec = move || exec::exec_command_with_stdio("uv", cmd, json);

    if matches!(cmd.first().map(String::as_str), Some("install" | "i")) {
        eprintln!("{}", unsupported_uv_install_message(&cmd[1..]));
        return 1;
    }

    match parse::classify_uv_command(cmd) {
        // Passthrough is a transparent shim: no report, untouched stdio.
        parse::UvCommand::Passthrough => exec::exec_command("uv", cmd),
        parse::UvCommand::PipInstall { install_args } => {
            let parsed = match parse::parse_pip_install_args(install_args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to parse install args: {}", e);
                    return 2;
                }
            };
            super::run_parsed_install(
                PackageManager::Uv,
                "pip install",
                install_args,
                parsed,
                exec,
                opts,
            )
        }
        parse::UvCommand::Add { add_args } => {
            let parsed = parse::parse_pypi_positionals_args(add_args);
            if let Some(message) =
                detect::wrong_package_manager_message(PackageManager::Uv, add_args, &parsed)
            {
                eprintln!("{message}");
                return 1;
            }
            super::run_parsed_install(PackageManager::Uv, "add", add_args, parsed, exec, opts)
        }
        parse::UvCommand::Sync => run_uv_sync(cmd, opts, exec),
    }
}

fn unsupported_uv_install_message(rest: &[String]) -> String {
    format!(
        "error: uv does not support top-level `install`.\nDid you mean `{}`?",
        corgea_cmd(&["uv", "pip", "install"], rest)
    )
}

/// Gate `uv sync` from the project's `uv.lock`. The lockfile is the full
/// locked universe (all groups/extras) — a superset of what sync installs,
/// conservative in the blocking direction; a stale lock that sync would
/// re-resolve is gated as written. Recency isn't checked (locked versions
/// aren't newly chosen by this command); the verdict pass is the gate. We
/// never run `uv lock` ourselves — locking can build sdists, which would
/// execute package code before any verdict.
fn run_uv_sync(cmd: &[String], opts: PrecheckOptions, exec: impl FnOnce() -> i32) -> i32 {
    let Some(cfg) = &opts.verdict else {
        // Direct callers may still disable verdicts completely.
        return exec();
    };
    let lock = match std::fs::read_to_string("uv.lock") {
        Ok(content) => content,
        Err(_) => {
            eprintln!(
                "note: no uv.lock here — 'uv sync' is not gated; dependencies install unchecked (run 'uv lock' first to enable the gate)"
            );
            return exec();
        }
    };
    let jobs = match parse_uv_lock(&lock) {
        Ok(jobs) => jobs,
        Err(e) if opts.force => {
            eprintln!("warning: cannot verify 'uv sync' ({e}); proceeding under --force");
            return exec();
        }
        Err(e) => {
            // The single documented bypass of the "all blocking goes through
            // `verdict::block_reason`" invariant: an unparsable
            // uv.lock means there is no report to feed the predicate, so the
            // gate refuses directly (--force above is the only escape).
            eprintln!("error: cannot verify 'uv sync': {e} (pass --force to proceed unchecked)");
            return 1;
        }
    };

    let resolved_count = jobs.len();
    let results = verdict::verdict_pool(jobs, cfg, PackageManager::Uv);
    let transitive = results
        .into_iter()
        .map(|(pkg, verdict)| TreeOutcome {
            name: pkg.name,
            version: pkg.version,
            origin: TreeOrigin::Locked,
            verdict,
        })
        .collect();
    let report = PrecheckReport {
        manager: PackageManager::Uv,
        subcommand: "sync".to_string(),
        original_args: cmd[1..].to_vec(),
        outcomes: Vec::new(),
        threshold: opts.threshold,
        tree: Some(TreeReport::Full {
            resolved_count,
            transitive,
        }),
        bare_install: true,
    };

    super::report_and_exec(&report, &opts, exec)
}

/// Packages from `uv.lock` that `uv sync` installs from an index. Local
/// stanzas (the project itself and path deps: editable / virtual /
/// directory / path sources) carry no registry identity and are skipped.
fn parse_uv_lock(content: &str) -> Result<Vec<tree::TreePackage>, String> {
    #[derive(serde::Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Pkg>,
    }
    #[derive(serde::Deserialize)]
    struct Pkg {
        name: String,
        version: Option<String>,
        #[serde(default)]
        source: std::collections::BTreeMap<String, toml::Value>,
    }
    const LOCAL_SOURCES: [&str; 4] = ["editable", "virtual", "directory", "path"];

    let lock: Lock = toml::from_str(content).map_err(|e| format!("parse uv.lock: {e}"))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| !LOCAL_SOURCES.iter().any(|k| p.source.contains_key(*k)))
        .filter_map(|p| {
            Some(tree::TreePackage {
                name: p.name,
                version: p.version?,
                requested: false,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uv_lock_keeps_index_packages_and_skips_local_sources() {
        let lock = r#"
version = 1

[[package]]
name = "proj"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "evildep"
version = "0.4.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gitdep"
version = "1.2.3"
source = { git = "https://example.com/repo?rev=abc#abc" }
"#;
        let pkgs = parse_uv_lock(lock).expect("parse uv.lock");
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["evildep", "gitdep"]);
        assert_eq!(pkgs[0].version, "0.4.2");
    }

    #[test]
    fn parse_uv_lock_rejects_invalid_toml() {
        let err = parse_uv_lock("not = [valid").expect_err("invalid toml");
        assert!(err.contains("parse uv.lock"), "got: {err}");
    }
}
