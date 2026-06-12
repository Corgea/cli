//! `corgea uv` routing: `uv pip install` / `uv add` / `uv pip sync` reuse
//! the parsed-install gate; `uv sync` is gated from `uv.lock`.

use super::{corgea_cmd, detect, exec, parse, tree, PackageManager, PrecheckOptions};

pub(super) fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    let json = opts.json;
    let exec = move || exec::exec_command_with_stdio("uv", cmd, json);

    // Classify on the subcommand, skipping any leading uv global flags
    // (`uv --project ./app sync` is still a gated sync). The exec path always
    // forwards the original `cmd`, global flags included.
    let sub = parse::uv_subcommand(cmd);

    if matches!(sub.first().map(String::as_str), Some("install" | "i")) {
        return super::refuse_guard(&opts, unsupported_uv_install_message(&sub[1..]), 1);
    }

    match parse::classify_uv_command(sub) {
        // Passthrough is a transparent shim: no report, untouched stdio —
        // but uv subcommands that install packages get an honesty note
        // first, mirroring the bare yarn/pnpm disclosure.
        parse::UvCommand::Passthrough => {
            uv_ungated_install_note(sub);
            exec::exec_command("uv", cmd)
        }
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
            // No wrong-manager guard here: `uv pip install` IS uv's
            // pip-compatible interface, so using it in a requirements/pip
            // project is correct, not a wrong-manager mistake — and it is
            // fully gated by the tree pass below regardless.
            super::warn_registry_override(PackageManager::Uv, install_args);
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
            super::warn_registry_override(PackageManager::Uv, sync_args);
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
            // `uv add` is project management (writes pyproject); using it in a
            // pip/requirements project IS a wrong-manager mistake.
            let parsed = parse::parse_pypi_positionals_args(add_args);
            super::warn_registry_override(PackageManager::Uv, add_args);
            if !opts.force {
                if let Some(message) =
                    detect::wrong_package_manager_message(PackageManager::Uv, add_args, &parsed)
                {
                    return super::refuse_guard(&opts, message, 1);
                }
            }
            super::run_parsed_install(PackageManager::Uv, "add", add_args, parsed, exec, opts)
        }
        parse::UvCommand::Sync => run_uv_sync(sub, opts, exec),
    }
}

fn unsupported_uv_install_message(rest: &[String]) -> String {
    format!(
        "error: uv does not support top-level `install`.\nDid you mean `{}`?",
        corgea_cmd(&["uv", "pip", "install"], rest)
    )
}

/// Honesty note for passthrough uv subcommands that install packages:
/// `uv run` syncs the project environment on first run (and `--with`
/// installs arbitrary packages); `uv tool install` / `uv tool run` install
/// from the index. None are gated — say so instead of passing silently,
/// matching the bare yarn/pnpm note.
fn uv_ungated_install_note(sub: &[String]) {
    let label = match sub.first().map(String::as_str) {
        Some("run") => "uv run",
        Some("tool")
            if matches!(
                sub.get(1).map(String::as_str),
                Some("install" | "run" | "upgrade")
            ) =>
        {
            "uv tool"
        }
        _ => return,
    };
    eprintln!(
        "note: '{label}' may install packages (project sync / --with / tool installs); these are not gated"
    );
}

/// Gate `uv sync` from the project's `uv.lock`. The lockfile is the full
/// locked universe (all groups/extras) — a superset of what sync installs,
/// conservative in the blocking direction; a stale lock that sync would
/// re-resolve is gated as written. Recency isn't checked (locked versions
/// aren't newly chosen by this command); the verdict pass is the gate. We
/// never run `uv lock` ourselves — locking can build sdists, which would
/// execute package code before any verdict.
fn run_uv_sync(sub: &[String], opts: PrecheckOptions, exec: impl FnOnce() -> i32) -> i32 {
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
        .and_then(|content| parse_uv_lock(&content))
        .map(|set| {
            set.print_notes();
            set.packages
        });
    // `sub` starts at the sync verb (global flags already skipped), so the
    // echoed command renders `uv sync <args>` — not the verb twice.
    super::run_locked_install(
        PackageManager::Uv,
        "sync",
        sub[1..].to_vec(),
        lock,
        &opts,
        exec,
    )
}

/// Parsed `uv.lock` verdict set plus the honesty notes the lock carried:
/// how many locked packages have no registry identity (skipped), and any
/// non-default registries the pins resolve from.
#[derive(Debug)]
struct UvLockSet {
    packages: Vec<tree::TreePackage>,
    skipped_non_registry: usize,
    non_default_registries: std::collections::BTreeSet<String>,
}

impl UvLockSet {
    fn print_notes(&self) {
        if self.skipped_non_registry > 0 {
            eprintln!(
                "note: {} non-registry locked package(s) (git/url/path/workspace) are not verified",
                self.skipped_non_registry
            );
        }
        for registry in &self.non_default_registries {
            eprintln!(
                "warning: uv.lock pins resolve from {registry} — the gate verdicts name@version against the public PyPI data and cannot vouch that registry's artifacts match"
            );
        }
    }
}

/// Packages from `uv.lock` that `uv sync` installs from an index. Only
/// registry-sourced packages carry a name@version the public vuln-api can
/// verify, so:
///   * non-registry sources (editable / virtual / directory / path — local;
///     git / url — direct artifacts) are skipped, with a count so the skip
///     is disclosed (the named-target path warns for the same shapes);
///   * a registry package missing a `version` is a parse error (fail closed)
///     rather than a silent omission that installs unchecked;
///   * non-default registry URLs are collected for a warning — the gate
///     verdicts against public PyPI data and can't vouch a private index's
///     artifact matches.
fn parse_uv_lock(content: &str) -> Result<UvLockSet, String> {
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
    // Sources that are NOT a registry/index: skip them entirely.
    const NON_REGISTRY_SOURCES: [&str; 6] =
        ["editable", "virtual", "directory", "path", "git", "url"];
    const DEFAULT_REGISTRY: &str = "https://pypi.org/simple";

    let lock: Lock = toml::from_str(content).map_err(|e| format!("parse uv.lock: {e}"))?;
    let mut set = UvLockSet {
        packages: Vec::new(),
        skipped_non_registry: 0,
        non_default_registries: std::collections::BTreeSet::new(),
    };
    for p in lock.package {
        if NON_REGISTRY_SOURCES
            .iter()
            .any(|k| p.source.contains_key(*k))
        {
            set.skipped_non_registry += 1;
            continue;
        }
        if let Some(registry) = p.source.get("registry").and_then(|v| v.as_str()) {
            if !registry
                .trim_end_matches('/')
                .eq_ignore_ascii_case(DEFAULT_REGISTRY)
            {
                set.non_default_registries.insert(registry.to_string());
            }
        }
        // Registry (or default-index) package — it must carry a version.
        let version = p.version.ok_or_else(|| {
            format!(
                "uv.lock registry package '{}' has no version; cannot verify",
                p.name
            )
        })?;
        set.packages.push(tree::TreePackage {
            name: p.name,
            version,
            requested: false,
        });
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uv_lock_keeps_only_registry_packages() {
        // Only the registry-sourced `evildep` is verifiable; the local
        // (editable) project and the git source carry no PyPI identity and
        // must be skipped — sending the git package's name@version to the
        // public vuln-api would verdict an unrelated package.
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
        let set = parse_uv_lock(lock).expect("parse uv.lock");
        let names: Vec<&str> = set.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["evildep"]);
        assert_eq!(set.packages[0].version, "0.4.2");
        // The two skipped sources are counted so the gate can disclose them.
        assert_eq!(set.skipped_non_registry, 2);
        // pypi.org/simple is the default index — no registry warning.
        assert!(set.non_default_registries.is_empty());
    }

    #[test]
    fn parse_uv_lock_collects_non_default_registries() {
        // A pin resolving from a private index gets verdicted by
        // name@version against public PyPI data — the mismatch risk must
        // surface as a warning, so the registry URL is collected.
        let lock = r#"
version = 1

[[package]]
name = "innerpkg"
version = "2.0.0"
source = { registry = "https://private.example/simple" }
"#;
        let set = parse_uv_lock(lock).expect("parse uv.lock");
        assert_eq!(set.packages.len(), 1);
        assert_eq!(
            set.non_default_registries.iter().collect::<Vec<_>>(),
            vec!["https://private.example/simple"]
        );
    }

    #[test]
    fn parse_uv_lock_registry_package_missing_version_fails_closed() {
        let lock = r#"
version = 1

[[package]]
name = "mystery"
source = { registry = "https://pypi.org/simple" }
"#;
        let err = parse_uv_lock(lock).expect_err("missing version must fail");
        assert!(err.contains("has no version"), "got: {err}");
    }

    #[test]
    fn parse_uv_lock_rejects_invalid_toml() {
        let err = parse_uv_lock("not = [valid").expect_err("invalid toml");
        assert!(err.contains("parse uv.lock"), "got: {err}");
    }
}
