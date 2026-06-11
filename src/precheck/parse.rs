//! Parse install-command argument lists into structured `InstallTarget`s.
//!
//! The goal is to be liberal with valid inputs (real install commands
//! mix flags, package specs, and pass-through args freely) and clear
//! about anything we can't verify (URLs / git / filesystem refs).

use std::path::PathBuf;

use crate::verify_deps::registry::{NpmSpec, PypiSpec};

use super::{InstallTarget, PackageManager, TargetKind};

#[derive(Debug, Default)]
pub struct ParsedInstall {
    pub targets: Vec<InstallTarget>,
    /// `pip install -r foo.txt` — requirements files are only noted
    /// (not verified) by the baseline gate.
    pub requirements_files: Vec<PathBuf>,
}

/// `uv pip install` argument list (everything after `pip install`).
pub fn parse_pip_install_args(args: &[String]) -> Result<ParsedInstall, String> {
    Ok(build_parsed_install(
        extract_pip_positionals(args)?,
        parse_pypi_spec,
    ))
}

/// `uv add` argument list (everything after `add`).
pub fn parse_pypi_positionals_args(args: &[String]) -> ParsedInstall {
    build_parsed_install(
        extract_node_positionals(PackageManager::Uv, args),
        parse_pypi_spec,
    )
}

fn build_parsed_install(
    positionals: PositionalSplit,
    parse_spec: fn(&str) -> InstallTarget,
) -> ParsedInstall {
    ParsedInstall {
        targets: positionals
            .specs
            .iter()
            .map(|raw| parse_spec(raw))
            .collect(),
        requirements_files: positionals.requirements_files,
    }
}

pub fn parse_install_args(
    manager: PackageManager,
    args: &[String],
) -> Result<ParsedInstall, String> {
    match manager {
        PackageManager::Pip => parse_pip_install_args(args),
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => Ok(
            build_parsed_install(extract_node_positionals(manager, args), parse_npm_spec),
        ),
        PackageManager::Uv => unreachable!("uv uses classify_uv_command"),
    }
}

/// Install-shaped `uv` invocations we know how to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvCommand<'a> {
    Passthrough,
    PipInstall {
        install_args: &'a [String],
    },
    Add {
        add_args: &'a [String],
    },
    /// `uv sync` — installs the locked project environment; gated from
    /// `uv.lock`. (`uv lock` stays passthrough: it installs nothing.)
    Sync,
}

pub fn classify_uv_command(cmd: &[String]) -> UvCommand<'_> {
    match cmd.first().map(String::as_str) {
        Some("pip") if matches!(cmd.get(1).map(String::as_str), Some("install" | "i")) => {
            UvCommand::PipInstall {
                install_args: &cmd[2..],
            }
        }
        Some("add") => UvCommand::Add {
            add_args: &cmd[1..],
        },
        Some("sync") => UvCommand::Sync,
        _ => UvCommand::Passthrough,
    }
}

#[derive(Debug, Default)]
struct PositionalSplit {
    specs: Vec<String>,
    requirements_files: Vec<PathBuf>,
}

/// Known install flags that take a separate value argument, per manager.
/// The fallback heuristic in [`skip_unknown_flag`] only skips URL/path-like
/// values, so a bare-word value (`-w my-workspace`) would otherwise parse —
/// and get verified or blocked — as a package spec. Not exhaustive; the
/// heuristic still backstops anything unlisted. The same letter can differ
/// by manager: npm's `-w <name>` takes a value, while pnpm's `-w`
/// (workspace-root) and yarn's `-W` are boolean.
fn takes_value(manager: PackageManager, flag: &str) -> bool {
    match manager {
        PackageManager::Npm => matches!(
            flag,
            "-w" | "--workspace"
                | "--prefix"
                | "--registry"
                | "--tag"
                | "--omit"
                | "--include"
                | "--loglevel"
        ),
        PackageManager::Pnpm => matches!(
            flag,
            "-C" | "--dir" | "--filter" | "--registry" | "--reporter" | "--loglevel"
        ),
        PackageManager::Yarn => matches!(
            flag,
            "--registry" | "--modules-folder" | "--cache-folder" | "--mutex" | "--network-timeout"
        ),
        PackageManager::Uv => matches!(
            flag,
            "--group" | "--extra" | "--index" | "--tag" | "--branch" | "--rev" | "--package"
        ),
        PackageManager::Pip => false,
    }
}

/// Strip flags from a npm/yarn/pnpm (or `uv add`) install argument list,
/// returning only the positional package specs.
///
/// We treat anything starting with `-` as a flag. Boolean flags (`-D`,
/// `--save-dev`, `--no-save`, ...) are dropped on their own. Flags
/// that take a value can be written as either `--flag=value` or
/// `--flag value`; known value-taking flags ([`takes_value`]) skip the
/// next token outright, anything else skips it only if it looks like a
/// value (a URL / path), never like a package spec.
fn extract_node_positionals(manager: PackageManager, args: &[String]) -> PositionalSplit {
    let mut out = PositionalSplit::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            // After `--`, everything is positional.
            for rest in &args[i + 1..] {
                out.specs.push(rest.clone());
            }
            break;
        }
        if a.starts_with('-') {
            if !a.contains('=') && takes_value(manager, a) {
                i += 2;
                continue;
            }
            i = skip_unknown_flag(args, i);
            continue;
        }
        out.specs.push(a.clone());
        i += 1;
    }
    out
}

/// Advance past an unknown flag at `i`. `--flag=value` is self-contained;
/// otherwise peek at the next arg and skip it too if it doesn't look like
/// a package spec (contains `://` or is path-like) — see the heuristic
/// rationale on [`extract_node_positionals`].
fn skip_unknown_flag(args: &[String], i: usize) -> usize {
    if args[i].contains('=') {
        return i + 1;
    }
    let next_is_value = args
        .get(i + 1)
        .map(|n| {
            !n.starts_with('-')
                && (n.contains("://")
                    || n.starts_with('/')
                    || n.starts_with("./")
                    || n.starts_with('~'))
        })
        .unwrap_or(false);
    i + if next_is_value { 2 } else { 1 }
}

/// pip's argument grammar is more structured than npm's: there are
/// known flags that take a value (`-r FILE`, `-c FILE`, `-e PATH`,
/// `--index-url URL`, `--target DIR`, ...). We special-case `-r/-c/-e`
/// because they affect behaviour, and treat the rest with the same
/// liberal heuristic as npm.
fn extract_pip_positionals(args: &[String]) -> Result<PositionalSplit, String> {
    let mut out = PositionalSplit::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            for rest in &args[i + 1..] {
                out.specs.push(rest.clone());
            }
            break;
        }
        match a.as_str() {
            "-r" | "--requirement" => {
                let path = args
                    .get(i + 1)
                    .ok_or_else(|| "`-r` / `--requirement` requires a file path".to_string())?;
                out.requirements_files.push(PathBuf::from(path));
                i += 2;
                continue;
            }
            "-c" | "--constraint" => {
                // Constraints don't add packages, but skip the path.
                i += 2;
                continue;
            }
            "-e" | "--editable" => {
                // Editable installs are explicit unverifiable targets.
                let path = args.get(i + 1).cloned().unwrap_or_default();
                out.specs.push(format!("-e {}", path));
                i += if args.get(i + 1).is_some() { 2 } else { 1 };
                continue;
            }
            _ => {}
        }
        // Long-form `--requirement=foo.txt`.
        if let Some(rest) = a.strip_prefix("--requirement=") {
            out.requirements_files.push(PathBuf::from(rest));
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--editable=") {
            out.specs.push(format!("-e {}", rest));
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            i = skip_unknown_flag(args, i);
            continue;
        }
        out.specs.push(a.clone());
        i += 1;
    }
    Ok(out)
}

/// Parse a single npm-style positional, e.g. `axios`, `axios@1.0.0`,
/// `axios@^1.0.0`, `axios@latest`, `@types/node@20.10.5`,
/// `git+https://...`, `file:./local`, `./local`, `npm:other@1.0.0`.
fn parse_npm_spec(raw: &str) -> InstallTarget {
    let display = raw.to_string();
    let trimmed = raw.trim();

    let unverifiable_prefixes = [
        "git+",
        "git:",
        "git@",
        "ssh://",
        "http://",
        "https://",
        "file:",
        "./",
        "../",
        "/",
        "~/",
        "npm:",
        "workspace:",
    ];
    if let Some(p) = unverifiable_prefixes
        .iter()
        .find(|p| trimmed.starts_with(*p))
    {
        let reason = match *p {
            "npm:" => "npm: aliased dependency — registry verification skipped",
            "workspace:" => "workspace: dependency — registry verification skipped",
            _ => "spec is a URL/git/filesystem reference — registry verification skipped",
        };
        return InstallTarget {
            name: trimmed.to_string(),
            display,
            kind: TargetKind::Unverifiable {
                reason: reason.to_string(),
            },
        };
    }

    // Find the version separator. Scoped names start with `@` and the
    // version separator is the *next* `@` (if any). Unscoped names
    // use the first `@`.
    let (name_part, spec_part): (&str, &str) = if let Some(rest) = trimmed.strip_prefix('@') {
        match rest.find('@') {
            Some(at_in_rest) => {
                let split = 1 + at_in_rest;
                (&trimmed[..split], &trimmed[split + 1..])
            }
            None => (trimmed, ""),
        }
    } else {
        match trimmed.find('@') {
            Some(at) => (&trimmed[..at], &trimmed[at + 1..]),
            None => (trimmed, ""),
        }
    };

    let name = name_part.trim().to_string();
    let spec_str = spec_part.trim();

    let kind = if spec_str.is_empty() || spec_str.eq_ignore_ascii_case("latest") {
        TargetKind::Npm(NpmSpec::Latest)
    } else if semver::Version::parse(spec_str).is_ok() {
        TargetKind::Npm(NpmSpec::Exact(spec_str.to_string()))
    } else if looks_like_npm_range(spec_str) {
        TargetKind::Npm(NpmSpec::Range(spec_str.to_string()))
    } else if is_npm_dist_tag(spec_str) {
        TargetKind::Npm(NpmSpec::Tag(spec_str.to_string()))
    } else {
        TargetKind::Unverifiable {
            reason: format!(
                "could not classify version spec '{}' (not a valid semver, range, or dist-tag)",
                spec_str
            ),
        }
    };

    InstallTarget {
        name,
        display,
        kind,
    }
}

/// Loose check: does this spec look like an npm version range?
/// We accept anything that *starts* with a range metacharacter
/// (`^`, `~`, `>`, `<`, `=`, `*`) or with a digit (so `1.x`, `1.2.x`,
/// and bare ranges still resolve). Validation against the registry's
/// version list happens later inside the resolver.
fn looks_like_npm_range(s: &str) -> bool {
    matches!(
        s.chars().next(),
        Some('^') | Some('~') | Some('>') | Some('<') | Some('=') | Some('*')
    ) || s
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
}

/// A dist-tag is a non-empty alphanumeric string (e.g. `latest`,
/// `next`, `beta`, `alpha-1`). We reject anything that contains
/// version-spec metacharacters.
fn is_npm_dist_tag(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && s.chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
}

/// Parse a single pip-style positional, e.g. `requests`, `requests==2.31.0`,
/// `requests>=2.0`, `requests[security]`, `git+https://...`, `./local`.
fn parse_pypi_spec(raw: &str) -> InstallTarget {
    let display = raw.to_string();
    let trimmed = raw.trim();

    let unverifiable_prefixes = [
        "git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:", "./", "../", "/", "~/",
        "-e ", "-e=",
    ];
    if unverifiable_prefixes.iter().any(|p| trimmed.starts_with(p)) {
        return InstallTarget {
            name: trimmed.to_string(),
            display,
            kind: TargetKind::Unverifiable {
                reason: "spec is a VCS / URL / editable / filesystem reference — registry verification skipped".to_string(),
            },
        };
    }

    // Split at the leftmost specifier operator (`==`, `>=`, `<=`, `!=`,
    // `~=`, `>`, `<`; PEP 440 also allows `===`). Only the index matters —
    // the operator itself stays with the spec part.
    let separators = ["===", "==", ">=", "<=", "!=", "~=", ">", "<"];
    let split_at = separators.iter().filter_map(|sep| trimmed.find(sep)).min();

    let (name_part, spec_part): (&str, &str) = match split_at {
        Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
        None => (trimmed, ""),
    };

    // Strip extras: `requests[security]` -> `requests`.
    let name_no_extras = name_part.split('[').next().unwrap_or(name_part).trim();

    // Strip env markers: `package; python_version >= "3.7"`.
    let spec_no_marker = spec_part.split(';').next().unwrap_or(spec_part).trim();

    let kind = if spec_no_marker.is_empty() {
        TargetKind::Pypi(PypiSpec::Latest)
    } else if let Some(rest) = spec_no_marker.strip_prefix("===") {
        TargetKind::Pypi(PypiSpec::Exact(rest.trim().to_string()))
    } else if let Some(rest) = spec_no_marker.strip_prefix("==") {
        let v = rest.trim();
        if v.is_empty() {
            TargetKind::Unverifiable {
                reason: "empty `==` specifier".to_string(),
            }
        } else {
            TargetKind::Pypi(PypiSpec::Exact(v.to_string()))
        }
    } else {
        TargetKind::Pypi(PypiSpec::Specifier(spec_no_marker.to_string()))
    };

    InstallTarget {
        name: name_no_extras.to_string(),
        display,
        kind,
    }
}

/// Bare PyPI name from a requirement line: stop at extras, operators,
/// markers, or whitespace. Callers normalize when they need a comparison key.
pub(super) fn pypi_name_part(spec: &str) -> &str {
    let stop = |c: char| matches!(c, '[' | '<' | '>' | '=' | '!' | '~' | ';' | ' ');
    let cut = spec.find(stop).unwrap_or(spec.len());
    spec[..cut].trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_npm_positionals_skipping_flags() {
        let args = vec![
            "axios".to_string(),
            "--save-dev".to_string(),
            "@types/node@latest".to_string(),
            "-D".to_string(),
            "--registry".to_string(),
            "https://example.com/registry".to_string(),
            "lodash@^4.0.0".to_string(),
        ];
        let p = extract_node_positionals(PackageManager::Npm, &args);
        assert_eq!(
            p.specs,
            vec![
                "axios".to_string(),
                "@types/node@latest".to_string(),
                "lodash@^4.0.0".to_string(),
            ]
        );
    }

    #[test]
    fn npm_workspace_flag_value_is_not_a_spec() {
        // npm's `-w <name>` / `--workspace <name>` take a bare-word value;
        // it must never be verified (or blocked) as a package spec.
        for flag in ["-w", "--workspace"] {
            let args = vec![
                flag.to_string(),
                "my-workspace".to_string(),
                "lodash".to_string(),
            ];
            let p = extract_node_positionals(PackageManager::Npm, &args);
            assert_eq!(p.specs, vec!["lodash".to_string()], "flag {flag}");
        }
        // `--workspace=name` is self-contained.
        let args = vec!["--workspace=my-workspace".to_string(), "lodash".to_string()];
        let p = extract_node_positionals(PackageManager::Npm, &args);
        assert_eq!(p.specs, vec!["lodash".to_string()]);
    }

    #[test]
    fn pnpm_and_yarn_boolean_workspace_flags_keep_the_spec() {
        // pnpm's `-w` (--workspace-root) and yarn's `-W` are boolean —
        // the next token is the package being installed.
        let args = vec!["-w".to_string(), "lodash".to_string()];
        let p = extract_node_positionals(PackageManager::Pnpm, &args);
        assert_eq!(p.specs, vec!["lodash".to_string()]);

        let args = vec!["-W".to_string(), "lodash".to_string()];
        let p = extract_node_positionals(PackageManager::Yarn, &args);
        assert_eq!(p.specs, vec!["lodash".to_string()]);

        // pnpm's `--filter <selector>` does take a value.
        let args = vec![
            "--filter".to_string(),
            "my-app".to_string(),
            "lodash".to_string(),
        ];
        let p = extract_node_positionals(PackageManager::Pnpm, &args);
        assert_eq!(p.specs, vec!["lodash".to_string()]);
    }

    #[test]
    fn uv_add_group_flag_value_is_not_a_spec() {
        let args = vec![
            "--group".to_string(),
            "dev".to_string(),
            "requests".to_string(),
        ];
        let p = extract_node_positionals(PackageManager::Uv, &args);
        assert_eq!(p.specs, vec!["requests".to_string()]);
    }

    #[test]
    fn extracts_npm_positionals_after_double_dash() {
        let args = vec![
            "--save-dev".to_string(),
            "--".to_string(),
            "axios".to_string(),
            "--this-is-positional-now".to_string(),
        ];
        let p = extract_node_positionals(PackageManager::Npm, &args);
        assert_eq!(
            p.specs,
            vec!["axios".to_string(), "--this-is-positional-now".to_string()]
        );
    }

    #[test]
    fn parse_npm_spec_classifies() {
        let cases = vec![
            ("axios", NpmSpec::Latest),
            ("axios@", NpmSpec::Latest),
            ("axios@latest", NpmSpec::Latest),
            ("axios@1.0.0", NpmSpec::Exact("1.0.0".to_string())),
            ("axios@^1.0.0", NpmSpec::Range("^1.0.0".to_string())),
            ("axios@~1.0.0", NpmSpec::Range("~1.0.0".to_string())),
            (
                "axios@>=1.0.0 <2.0.0",
                NpmSpec::Range(">=1.0.0 <2.0.0".to_string()),
            ),
            ("axios@next", NpmSpec::Tag("next".to_string())),
            ("axios@beta", NpmSpec::Tag("beta".to_string())),
            ("@types/node", NpmSpec::Latest),
            ("@types/node@20.10.5", NpmSpec::Exact("20.10.5".to_string())),
            ("@types/node@^20.0.0", NpmSpec::Range("^20.0.0".to_string())),
            ("@types/node@latest", NpmSpec::Latest),
        ];
        for (input, expected) in cases {
            let target = parse_npm_spec(input);
            match (&target.kind, &expected) {
                (TargetKind::Npm(actual), expected) => {
                    assert_eq!(actual, expected, "for input '{}'", input);
                }
                _ => panic!("unexpected kind for '{}'", input),
            }
        }
    }

    #[test]
    fn parse_npm_spec_extracts_scoped_names() {
        assert_eq!(parse_npm_spec("@types/node").name, "@types/node");
        assert_eq!(parse_npm_spec("@types/node@20.10.5").name, "@types/node");
        assert_eq!(parse_npm_spec("axios@1.2.3").name, "axios");
        assert_eq!(parse_npm_spec("axios").name, "axios");
    }

    #[test]
    fn parse_npm_spec_skips_unverifiable() {
        let unverifiable = vec![
            "git+https://github.com/x/y.git",
            "git@github.com:x/y.git",
            "https://example.com/pkg.tgz",
            "file:./local-pkg",
            "./local-pkg",
            "../sibling",
            "/abs/path",
            "npm:alias-of-other@1.0.0",
            "workspace:*",
        ];
        for u in unverifiable {
            let t = parse_npm_spec(u);
            assert!(
                matches!(t.kind, TargetKind::Unverifiable { .. }),
                "for '{}'",
                u
            );
        }
    }

    #[test]
    fn parse_pypi_spec_classifies() {
        let cases = vec![
            ("requests", PypiSpec::Latest),
            ("requests==2.31.0", PypiSpec::Exact("2.31.0".to_string())),
            ("requests>=2.0", PypiSpec::Specifier(">=2.0".to_string())),
            ("requests~=2.0", PypiSpec::Specifier("~=2.0".to_string())),
            ("requests<3,>=2", PypiSpec::Specifier("<3,>=2".to_string())),
            ("requests[security]", PypiSpec::Latest),
            (
                "requests[security]==2.31.0",
                PypiSpec::Exact("2.31.0".to_string()),
            ),
        ];
        for (input, expected) in cases {
            let t = parse_pypi_spec(input);
            match (&t.kind, &expected) {
                (TargetKind::Pypi(actual), expected) => {
                    assert_eq!(actual, expected, "for '{}'", input);
                }
                _ => panic!("unexpected kind for '{}'", input),
            }
        }
    }

    #[test]
    fn parse_pypi_spec_strips_extras_and_markers() {
        assert_eq!(
            parse_pypi_spec("requests[security]==2.31.0").name,
            "requests"
        );
        let t = parse_pypi_spec("requests==2.31.0; python_version >= \"3.7\"");
        assert_eq!(t.name, "requests");
        assert!(
            matches!(t.kind, TargetKind::Pypi(PypiSpec::Exact(ref v)) if v == "2.31.0"),
            "env marker must not leak into the spec: {:?}",
            t.kind
        );

        let marker_only = parse_pypi_spec("pkg; python_version >= \"3.7\"");
        assert_eq!(marker_only.name, "pkg; python_version");
        assert!(
            matches!(marker_only.kind, TargetKind::Pypi(PypiSpec::Specifier(ref s)) if s == ">= \"3.7\""),
            "got {:?}",
            marker_only.kind
        );
    }

    #[test]
    fn pypi_name_part_strips_extras_markers_and_operators() {
        assert_eq!(pypi_name_part("requests"), "requests");
        assert_eq!(pypi_name_part("requests[security]==2.31.0"), "requests");
        assert_eq!(pypi_name_part("Flask_Cors>=4.0"), "Flask_Cors");
        assert_eq!(pypi_name_part("pkg; python_version >= \"3.7\""), "pkg");
        assert_eq!(pypi_name_part("pkg ==1.0"), "pkg");
        assert_eq!(pypi_name_part(""), "");
    }

    #[test]
    fn parse_pypi_spec_skips_unverifiable() {
        let unverifiable = vec![
            "git+https://github.com/x/y.git",
            "https://example.com/pkg.tar.gz",
            "./local-pkg",
            "/abs/path",
            "-e ./local",
        ];
        for u in unverifiable {
            let t = parse_pypi_spec(u);
            assert!(
                matches!(t.kind, TargetKind::Unverifiable { .. }),
                "for '{}'",
                u
            );
        }
    }

    #[test]
    fn classify_uv_command_recognizes_install_shapes() {
        assert!(matches!(
            classify_uv_command(&[
                "pip".to_string(),
                "install".to_string(),
                "requests".to_string(),
            ]),
            UvCommand::PipInstall { .. }
        ));
        assert!(matches!(
            classify_uv_command(&["pip".to_string(), "i".to_string()]),
            UvCommand::PipInstall { .. }
        ));
        assert!(matches!(
            classify_uv_command(&["add".to_string(), "django".to_string()]),
            UvCommand::Add { .. }
        ));
        assert_eq!(
            classify_uv_command(&["sync".to_string(), "--extra".to_string(), "dev".to_string()]),
            UvCommand::Sync
        );
        assert_eq!(
            classify_uv_command(&["run".to_string(), "pytest".to_string()]),
            UvCommand::Passthrough
        );
        assert_eq!(
            classify_uv_command(&["lock".to_string()]),
            UvCommand::Passthrough
        );
    }

    #[test]
    fn uv_add_positionals_parse_as_pypi_specs() {
        let parsed = parse_pypi_positionals_args(&["requests==2.31.0".into()]);
        assert_eq!(parsed.targets.len(), 1);
        assert!(
            matches!(
                &parsed.targets[0].kind,
                TargetKind::Pypi(PypiSpec::Exact(v)) if v == "2.31.0"
            ),
            "uv add targets must parse as PyPI specs, got {:?}",
            parsed.targets[0].kind
        );
    }

    #[test]
    fn pip_args_extract_requirements_files() {
        let args = vec![
            "-r".to_string(),
            "reqs.txt".to_string(),
            "requests==2.31.0".to_string(),
            "--requirement=other.txt".to_string(),
            "-e".to_string(),
            "./local".to_string(),
        ];
        let p = extract_pip_positionals(&args).unwrap();
        assert_eq!(
            p.requirements_files,
            vec![PathBuf::from("reqs.txt"), PathBuf::from("other.txt")]
        );
        assert!(p.specs.contains(&"requests==2.31.0".to_string()));
        assert!(p.specs.iter().any(|s| s.starts_with("-e ")));
    }
}
