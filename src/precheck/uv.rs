//! `corgea uv` routing: `uv pip install` / `uv add` / `uv pip sync` reuse
//! the parsed-install gate; `uv sync` is gated from `uv.lock`.

use super::{corgea_cmd, detect, exec, parse, tree, PackageManager, PrecheckOptions};

pub(super) fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    let json = opts.json;
    let exec = move || exec::exec_command_with_stdio("uv", cmd, json);

    if matches!(cmd.first().map(String::as_str), Some("install" | "i")) {
        return super::refuse_guard(&opts, unsupported_uv_install_message(&cmd[1..]), 1);
    }

    match parse::classify_uv_command(cmd) {
        // Passthrough is a transparent shim: no report, untouched stdio.
        parse::UvCommand::Passthrough => exec::exec_command("uv", cmd),
        parse::UvCommand::PipInstall { install_args } => {
            let parsed = match parse::parse_pip_install_args(install_args) {
                Ok(p) => p,
                Err(e) => {
                    return super::refuse_guard(
                        &opts,
                        format!("failed to parse install args: {}", e),
                        2,
                    );
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
        parse::UvCommand::PipSync { sync_args } => {
            // `uv pip sync reqs.txt` installs exactly the given requirements
            // set — gate it like `uv pip install -r reqs.txt`.
            let parsed = parse::parse_pip_sync_args(sync_args);
            if parsed.requirements_files.is_empty() {
                // No files named: uv errors on its own.
                return exec::exec_command("uv", cmd);
            }
            super::run_parsed_install(
                PackageManager::Uv,
                "pip sync",
                sync_args,
                parsed,
                exec,
                opts,
            )
        }
        parse::UvCommand::Add { add_args } => {
            let parsed = parse::parse_pypi_positionals_args(add_args);
            if !opts.force {
                if let Some(message) =
                    detect::wrong_package_manager_message(PackageManager::Uv, add_args, &parsed)
                {
                    return super::refuse_guard(&opts, message, 1);
                }
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
    if opts.verdict.is_none() {
        // Direct callers may still disable verdicts completely.
        return exec();
    }
    // uv discovers the project by walking up from the CWD — find `uv.lock`
    // the same way, so a sync run from a project subdirectory stays gated.
    let Some(lock_path) = tree::find_up("uv.lock") else {
        eprintln!(
            "note: no uv.lock here — 'uv sync' is not gated; dependencies install unchecked (run 'uv lock' first to enable the gate)"
        );
        return exec();
    };
    let lock = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("read {}: {e}", lock_path.display()))
        .and_then(|content| parse_uv_lock(&content));
    super::run_locked_install(
        PackageManager::Uv,
        "sync",
        cmd[1..].to_vec(),
        lock,
        &opts,
        exec,
    )
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
