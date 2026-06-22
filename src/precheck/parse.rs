//! Parse install-command argument lists into structured `InstallTarget`s.
//!
//! The goal is to be liberal with valid inputs (real install commands
//! mix flags, package specs, and pass-through args freely) and clear
//! about anything we can't verify (URLs / git / filesystem refs).

use std::path::{Path, PathBuf};

use crate::verify_deps::registry::{NpmSpec, PypiSpec};

use super::{InstallTarget, PackageManager, TargetKind};

#[derive(Debug, Default)]
pub struct ParsedInstall {
    pub targets: Vec<InstallTarget>,
    /// `pip install -r foo.txt` — requirements files are only noted
    /// (not verified) by the baseline gate.
    pub requirements_files: Vec<PathBuf>,
    /// `pip install --pre` — allow prerelease versions when resolving the
    /// version that would install, so the gate verdicts what pip installs
    /// rather than the latest stable.
    pub allow_prerelease: bool,
}

fn build_parsed_install(
    positionals: PositionalSplit,
    parse_spec: impl Fn(&str) -> InstallTarget,
) -> ParsedInstall {
    ParsedInstall {
        targets: positionals
            .specs
            .iter()
            .map(|raw| parse_spec(raw))
            .collect(),
        requirements_files: positionals.requirements_files,
        allow_prerelease: false,
    }
}

/// The default npm dist-tag from `--tag <value>` / `--tag=value`, which
/// changes what a *bare* spec (`pkg`, no `@version`) installs. Stops at `--`
/// (everything after is positional). The gate must resolve that tag rather
/// than `latest`, or a fresh/vulnerable `beta`/`canary` release bypasses
/// both blocks whenever `latest` is old/clean.
fn npm_default_tag(args: &[String]) -> Option<String> {
    // npm config is last-wins: `--tag beta --tag canary` installs canary.
    // Returning the first match would gate the wrong dist-tag.
    let mut tag = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            break;
        }
        if a == "--tag" {
            tag = args.get(i + 1).cloned();
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--tag=") {
            tag = Some(v.to_string());
        }
        i += 1;
    }
    tag
}

/// Whether the forwarded pip args request prereleases (`--pre`). Stops at
/// `--` (positional thereafter).
fn pip_allows_prerelease(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--pre")
}

pub fn parse_install_args(
    manager: PackageManager,
    args: &[String],
) -> Result<ParsedInstall, String> {
    match manager {
        PackageManager::Pip => {
            let mut parsed = build_parsed_install(extract_pip_positionals(args)?, parse_pypi_spec);
            parsed.allow_prerelease = pip_allows_prerelease(args);
            Ok(parsed)
        }
        PackageManager::Npm => {
            let default_tag = npm_default_tag(args);
            Ok(build_parsed_install(
                extract_node_positionals(manager, args),
                |raw| parse_npm_spec(raw, default_tag.as_deref()),
            ))
        }
    }
}

/// Best-effort extraction of registry-installable entries from pip
/// requirements files. This is a fallback for when pip's full dry-run cannot
/// resolve the tree. It deliberately skips file-level options and constraints,
/// while preserving URL/VCS/editable entries as unverifiable targets.
pub(super) fn parse_requirement_file_targets(path: &Path) -> Result<Vec<InstallTarget>, String> {
    let mut seen = std::collections::HashSet::new();
    parse_requirement_file_targets_inner(path, &mut seen)
}

fn parse_requirement_file_targets_inner(
    path: &Path,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> Result<Vec<InstallTarget>, String> {
    let path_for_io = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("read {}: {e}", path.display()))?
            .join(path)
    };
    let seen_key = std::fs::canonicalize(&path_for_io).unwrap_or_else(|_| path_for_io.clone());
    if !seen.insert(seen_key) {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&path_for_io)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let base = path_for_io.parent().unwrap_or_else(|| Path::new("."));
    let mut targets = Vec::new();

    for line in requirement_logical_lines(&content) {
        match requirement_line_entry(&line) {
            Some(RequirementLineEntry::Target(spec)) => targets.push(parse_pypi_spec(&spec)),
            Some(RequirementLineEntry::Include(include)) => {
                targets.extend(parse_requirement_file_targets_inner(
                    &base.join(include),
                    seen,
                )?);
            }
            None => {}
        }
    }

    Ok(targets)
}

/// First format-control directive (`--no-binary` / `--only-binary`) found in
/// any of `files`, following nested `-r`/`--requirement` AND `-c`/`--constraint`
/// includes. pip applies file-level format-control AFTER command-line options
/// (the file parser mutates the shared FormatControl object post-CLI-parse), so
/// a `--no-binary :all:` line inside a requirements file overrides the tree
/// pass's trailing `--only-binary :all:` guard and would build sdists —
/// executing package code — during the dry-run. pip reads and applies
/// format-control from nested constraint (`-c`) files too, not just requirement
/// (`-r`) includes, so both kinds of include must be followed. The tree pass
/// must refuse to dry-run such files. Returns `(file, directive)` of the first
/// hit.
pub(super) fn requirements_format_control_directive(
    files: &[PathBuf],
) -> Option<(PathBuf, String)> {
    let mut seen = std::collections::HashSet::new();
    files
        .iter()
        .find_map(|file| format_control_scan(file, &mut seen))
}

fn format_control_scan(
    path: &Path,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> Option<(PathBuf, String)> {
    let path_for_io = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let seen_key = std::fs::canonicalize(&path_for_io).unwrap_or_else(|_| path_for_io.clone());
    if !seen.insert(seen_key) {
        return None;
    }

    // Best-effort: an unreadable/missing file can't carry a directive we'd
    // miss — pip runs as the same uid, so it can't read it either and the
    // dry-run fails loudly on its own.
    let content = std::fs::read_to_string(&path_for_io).ok()?;
    let base = path_for_io.parent().unwrap_or_else(|| Path::new("."));

    for line in requirement_logical_lines(&content) {
        let line = strip_requirement_comment(&line);
        let first = line.split_whitespace().next().unwrap_or_default();
        if first == "--no-binary"
            || first == "--only-binary"
            || first.starts_with("--no-binary=")
            || first.starts_with("--only-binary=")
        {
            return Some((path.to_path_buf(), first.to_string()));
        }
        // pip applies file-level format-control from both `-r` requirement
        // includes and `-c` constraint includes, so follow both.
        for (short, long) in [("-r", "--requirement"), ("-c", "--constraint")] {
            if let Some(include) = requirement_flag_value(line, short, long) {
                if let Some(hit) = format_control_scan(&base.join(include), seen) {
                    return Some(hit);
                }
            }
        }
    }
    None
}

enum RequirementLineEntry {
    Target(String),
    Include(PathBuf),
}

fn requirement_logical_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for raw in content.lines() {
        let trimmed = raw.trim_end();
        let (part, continued) = match trimmed.strip_suffix('\\') {
            Some(part) => (part.trim_end(), true),
            None => (trimmed, false),
        };
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(part.trim());
        if !continued {
            lines.push(std::mem::take(&mut current));
        }
    }

    if !current.trim().is_empty() {
        lines.push(current);
    }
    lines
}

fn requirement_line_entry(line: &str) -> Option<RequirementLineEntry> {
    let line = strip_requirement_comment(line);
    if line.is_empty() {
        return None;
    }

    if let Some(path) = requirement_flag_value(line, "-r", "--requirement") {
        return Some(RequirementLineEntry::Include(PathBuf::from(path)));
    }
    if requirement_flag_value(line, "-c", "--constraint").is_some() {
        return None;
    }
    if let Some(path) = requirement_flag_value(line, "-e", "--editable") {
        return Some(RequirementLineEntry::Target(format!("-e {path}")));
    }

    if line.starts_with('-') {
        return None;
    }

    let spec = strip_inline_requirement_options(line);
    (!spec.is_empty()).then(|| RequirementLineEntry::Target(spec.to_string()))
}

fn strip_requirement_comment(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return "";
    }
    [" #", "\t#"]
        .iter()
        .filter_map(|marker| trimmed.find(marker))
        .min()
        .map_or(trimmed, |idx| trimmed[..idx].trim())
}

fn requirement_flag_value<'a>(line: &'a str, short: &str, long: &str) -> Option<&'a str> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if first == short || first == long {
        return parts.next();
    }
    if let Some(value) = first.strip_prefix(&format!("{long}=")) {
        return Some(value);
    }
    first
        .strip_prefix(short)
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
}

fn strip_inline_requirement_options(line: &str) -> &str {
    [
        " --hash",
        " --config-setting",
        " --global-option",
        " --install-option",
    ]
    .iter()
    .filter_map(|marker| line.find(marker))
    .min()
    .map_or(line.trim(), |idx| line[..idx].trim())
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
/// heuristic still backstops anything unlisted.
pub(super) fn takes_value(manager: PackageManager, flag: &str) -> bool {
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
                | "--install-strategy"
                | "--before"
                | "--cpu"
                | "--os"
                | "--libc"
                | "--otp"
                | "--location"
                | "--cache"
                | "--script-shell"
                | "--userconfig"
                | "--globalconfig"
                | "--depth"
        ),
        PackageManager::Pip => matches!(
            flag,
            "-i" | "--index-url"
                | "--extra-index-url"
                | "-f"
                | "--find-links"
                | "--platform"
                | "--python-version"
                | "--implementation"
                | "--abi"
                | "-t"
                | "--target"
                | "--prefix"
                | "--root"
                | "--src"
                | "--upgrade-strategy"
                | "--no-binary"
                | "--only-binary"
                | "--progress-bar"
                | "--proxy"
                | "--retries"
                | "--timeout"
                | "--exists-action"
                | "--trusted-host"
                | "--cert"
                | "--client-cert"
                | "--cache-dir"
                | "--log"
                | "--python"
                | "--keyring-provider"
                | "--report"
                | "--use-feature"
                | "--use-deprecated"
                | "--config-settings"
                | "-C"
                | "--global-option"
                | "--hash"
        ),
    }
}

/// Strip flags from an npm install argument list, returning only the
/// positional package specs.
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
        // Attached short-option forms (pip's optparse): `-rreqs.txt`,
        // `-cfile`, `-e./path`. Missing these would silently skip the
        // whole gate (`-rreqs.txt` would read as a boolean flag and the
        // install would look bare).
        if let Some(path) = attached_short_value(a, "-r") {
            out.requirements_files.push(PathBuf::from(path));
            i += 1;
            continue;
        }
        if attached_short_value(a, "-c").is_some() {
            i += 1;
            continue;
        }
        if let Some(path) = attached_short_value(a, "-e") {
            out.specs.push(format!("-e {}", path));
            i += 1;
            continue;
        }
        // Long-form `--requirement=foo.txt`.
        if let Some(rest) = a.strip_prefix("--requirement=") {
            out.requirements_files.push(PathBuf::from(rest));
            i += 1;
            continue;
        }
        if a.strip_prefix("--constraint=").is_some() {
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--editable=") {
            out.specs.push(format!("-e {}", rest));
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            if !a.contains('=') && takes_value(PackageManager::Pip, a) {
                i += 2;
                continue;
            }
            i = skip_unknown_flag(args, i);
            continue;
        }
        out.specs.push(a.clone());
        i += 1;
    }
    Ok(out)
}

/// `-rreqs.txt` → `reqs.txt`: the value attached directly to a short
/// option. `None` for the bare flag itself (handled by the exact-match
/// arms) and for long `--` forms.
fn attached_short_value<'a>(arg: &'a str, flag: &str) -> Option<&'a str> {
    arg.strip_prefix(flag).filter(|rest| !rest.is_empty())
}

/// Parse a single npm-style positional, e.g. `axios`, `axios@1.0.0`,
/// `axios@^1.0.0`, `axios@latest`, `@types/node@20.10.5`,
/// `git+https://...`, `file:./local`, `./local`, `npm:other@1.0.0`.
///
/// `default_tag` is the `--tag <value>` from the command, applied only to a
/// *bare* spec (no `@version`): `npm install --tag beta pkg` installs the
/// `beta` dist-tag, so the gate must resolve that, not `latest`. An explicit
/// `pkg@latest` / `pkg@1.0.0` overrides the default tag.
fn parse_npm_spec(raw: &str, default_tag: Option<&str>) -> InstallTarget {
    let display = raw.to_string();
    let trimmed = raw.trim();

    let unverifiable_prefixes = [
        "git+",
        "git:",
        "git@",
        "github:",
        "gist:",
        "bitbucket:",
        "gitlab:",
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

    // Bare `.` / `..` install the current/parent directory; `user/repo`
    // (one `/`, not an `@scope/` name) is npm's GitHub shorthand. Neither
    // is a registry package — resolving them would 404 and block a command
    // plain npm accepts.
    if trimmed == "." || trimmed == ".." {
        return InstallTarget {
            name: trimmed.to_string(),
            display,
            kind: TargetKind::Unverifiable {
                reason: "spec is a filesystem path — registry verification skipped".to_string(),
            },
        };
    }
    if !trimmed.starts_with('@') && trimmed.contains('/') {
        return InstallTarget {
            name: trimmed.to_string(),
            display,
            kind: TargetKind::Unverifiable {
                reason: "spec is a GitHub shorthand or path — registry verification skipped"
                    .to_string(),
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

    let kind = if spec_str.is_empty() {
        // A bare spec picks up the command's `--tag`, if any; otherwise latest.
        match default_tag {
            Some(tag) => TargetKind::Npm(NpmSpec::Tag(tag.to_string())),
            None => TargetKind::Npm(NpmSpec::Latest),
        }
    } else if spec_str.eq_ignore_ascii_case("latest") {
        TargetKind::Npm(NpmSpec::Latest)
    } else if semver::Version::parse(spec_str).is_ok() {
        TargetKind::Npm(NpmSpec::Exact(spec_str.to_string()))
    } else if let Some(rest) = spec_str
        .strip_prefix('v')
        .filter(|rest| semver::Version::parse(rest).is_ok())
    {
        // npm coerces a leading `v` (`pkg@v1.2.3` installs 1.2.3); without
        // this it would read as a dist-tag and error.
        TargetKind::Npm(NpmSpec::Exact(rest.to_string()))
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

    // Strip the PEP 508 environment marker first — its comparison operators
    // (`; python_version >= "3.7"`) must not be mistaken for version
    // operators, which would split the name inside the marker.
    let req_part = trimmed.split(';').next().unwrap_or(trimmed).trim();

    // PEP 508 direct reference: `name @ https://…` — unverifiable like a
    // bare URL (never a registry lookup, never a block).
    if let Some((_, after_at)) = req_part.split_once('@') {
        if after_at.contains("://") {
            return InstallTarget {
                name: trimmed.to_string(),
                display,
                kind: TargetKind::Unverifiable {
                    reason: "spec is a PEP 508 direct reference (name @ url) — registry verification skipped".to_string(),
                },
            };
        }
    }

    // Bare `.` / `..` and anything with a path separator install from the
    // filesystem (`pip install .`), not the registry.
    if req_part == "." || req_part == ".." || req_part.contains('/') || req_part.contains('\\') {
        return InstallTarget {
            name: trimmed.to_string(),
            display,
            kind: TargetKind::Unverifiable {
                reason: "spec is a filesystem path — registry verification skipped".to_string(),
            },
        };
    }

    // Split at the leftmost specifier operator (`==`, `>=`, `<=`, `!=`,
    // `~=`, `>`, `<`; PEP 440 also allows `===`). Only the index matters —
    // the operator itself stays with the spec part.
    let separators = ["===", "==", ">=", "<=", "!=", "~=", ">", "<"];
    let split_at = separators.iter().filter_map(|sep| req_part.find(sep)).min();

    let (name_part, spec_part): (&str, &str) = match split_at {
        Some(idx) => (&req_part[..idx], &req_part[idx..]),
        None => (req_part, ""),
    };

    // Strip extras: `requests[security]` -> `requests`.
    let name_no_extras = name_part
        .split_once('[')
        .map_or(name_part, |(n, _)| n)
        .trim();

    let spec_str = spec_part.trim();

    let kind = if spec_str.is_empty() {
        TargetKind::Pypi(PypiSpec::Latest)
    } else if let Some(rest) = spec_str.strip_prefix("===") {
        TargetKind::Pypi(PypiSpec::Exact(rest.trim().to_string()))
    } else if let Some(rest) = spec_str.strip_prefix("==") {
        let v = rest.trim();
        if v.is_empty() {
            TargetKind::Unverifiable {
                reason: "empty `==` specifier".to_string(),
            }
        } else if v.contains('*') {
            // Wildcard pin (`==1.4.*`) — a range, not a literal version;
            // the resolver desugars it.
            TargetKind::Pypi(PypiSpec::Specifier(spec_str.to_string()))
        } else {
            TargetKind::Pypi(PypiSpec::Exact(v.to_string()))
        }
    } else {
        TargetKind::Pypi(PypiSpec::Specifier(spec_str.to_string()))
    };

    InstallTarget {
        name: name_no_extras.to_string(),
        display,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    fn npm_tag_flag_changes_bare_spec_resolution() {
        // `--tag beta` (before or after the verb's rest) makes a bare spec
        // resolve the beta dist-tag, not latest. An explicit version wins.
        for args in [
            vec!["--tag".to_string(), "beta".to_string(), "pkg".to_string()],
            vec!["pkg".to_string(), "--tag=beta".to_string()],
        ] {
            let p = parse_install_args(PackageManager::Npm, &args).unwrap();
            assert_eq!(p.targets.len(), 1, "args {args:?}");
            assert!(
                matches!(&p.targets[0].kind, TargetKind::Npm(NpmSpec::Tag(t)) if t == "beta"),
                "bare spec must pick up --tag: {:?}",
                p.targets[0].kind
            );
        }

        // Explicit pin ignores --tag.
        let args = vec![
            "--tag".to_string(),
            "beta".to_string(),
            "pkg@1.0.0".to_string(),
        ];
        let p = parse_install_args(PackageManager::Npm, &args).unwrap();
        assert!(
            matches!(&p.targets[0].kind, TargetKind::Npm(NpmSpec::Exact(v)) if v == "1.0.0"),
            "explicit version must override --tag: {:?}",
            p.targets[0].kind
        );

        // No --tag → bare spec stays latest.
        let args = vec!["pkg".to_string()];
        let p = parse_install_args(PackageManager::Npm, &args).unwrap();
        assert!(matches!(
            &p.targets[0].kind,
            TargetKind::Npm(NpmSpec::Latest)
        ));
    }

    #[test]
    fn npm_tag_flag_is_last_wins_like_npm_config() {
        // npm's config parser is last-wins: `--tag beta --tag canary`
        // installs canary. Gating beta would verdict the wrong release.
        let args = vec![
            "--tag".to_string(),
            "beta".to_string(),
            "pkg".to_string(),
            "--tag=canary".to_string(),
        ];
        let p = parse_install_args(PackageManager::Npm, &args).unwrap();
        assert!(
            matches!(&p.targets[0].kind, TargetKind::Npm(NpmSpec::Tag(t)) if t == "canary"),
            "last --tag must win: {:?}",
            p.targets[0].kind
        );
    }

    #[test]
    fn pip_pre_flag_sets_allow_prerelease() {
        let with = parse_install_args(
            PackageManager::Pip,
            &["--pre".to_string(), "flask".to_string()],
        )
        .unwrap();
        assert!(with.allow_prerelease, "--pre must set allow_prerelease");

        let without = parse_install_args(PackageManager::Pip, &["flask".to_string()]).unwrap();
        assert!(!without.allow_prerelease);
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
            let target = parse_npm_spec(input, None);
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
        assert_eq!(parse_npm_spec("@types/node", None).name, "@types/node");
        assert_eq!(
            parse_npm_spec("@types/node@20.10.5", None).name,
            "@types/node"
        );
        assert_eq!(parse_npm_spec("axios@1.2.3", None).name, "axios");
        assert_eq!(parse_npm_spec("axios", None).name, "axios");
    }

    #[test]
    fn parse_npm_spec_skips_unverifiable() {
        let unverifiable = vec![
            "git+https://github.com/x/y.git",
            "git@github.com:x/y.git",
            "github:expressjs/express",
            "https://example.com/pkg.tgz",
            "file:./local-pkg",
            "./local-pkg",
            "../sibling",
            "/abs/path",
            "npm:alias-of-other@1.0.0",
            "workspace:*",
            // GitHub shorthand and bare paths — registry lookups would 404.
            "expressjs/express",
            "user/repo#semver:^1.0.0",
            ".",
            "..",
        ];
        for u in unverifiable {
            let t = parse_npm_spec(u, None);
            assert!(
                matches!(t.kind, TargetKind::Unverifiable { .. }),
                "for '{}'",
                u
            );
        }
        // Scoped names keep their one `/` and stay verifiable.
        assert!(matches!(
            parse_npm_spec("@types/node", None).kind,
            TargetKind::Npm(NpmSpec::Latest)
        ));
    }

    #[test]
    fn parse_npm_spec_coerces_leading_v() {
        // npm installs `pkg@v1.2.3` as 1.2.3; a dist-tag reading would error.
        let t = parse_npm_spec("axios@v1.2.3", None);
        assert!(
            matches!(t.kind, TargetKind::Npm(NpmSpec::Exact(ref v)) if v == "1.2.3"),
            "got {:?}",
            t.kind
        );
        // …but a real tag that merely starts with `v` stays a tag.
        let t = parse_npm_spec("node@v8-canary", None);
        assert!(
            matches!(t.kind, TargetKind::Npm(NpmSpec::Tag(ref s)) if s == "v8-canary"),
            "got {:?}",
            t.kind
        );
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

        // A marker-only spec must not split inside the marker: the name is
        // `pkg` and the (versionless) spec resolves latest.
        let marker_only = parse_pypi_spec("pkg; python_version >= \"3.7\"");
        assert_eq!(marker_only.name, "pkg");
        assert!(
            matches!(marker_only.kind, TargetKind::Pypi(PypiSpec::Latest)),
            "got {:?}",
            marker_only.kind
        );
    }

    #[test]
    fn parse_pypi_spec_wildcard_pin_is_a_specifier() {
        // `==1.4.*` is a range; matching it as a literal release key would
        // always miss and block.
        let t = parse_pypi_spec("django==4.2.*");
        assert_eq!(t.name, "django");
        assert!(
            matches!(t.kind, TargetKind::Pypi(PypiSpec::Specifier(ref s)) if s == "==4.2.*"),
            "got {:?}",
            t.kind
        );
    }

    #[test]
    fn parse_pypi_spec_direct_reference_and_paths_are_unverifiable() {
        // PEP 508 direct reference, bare dot, and separator-bearing paths
        // must never be looked up (and thus never blocked) as registry names.
        for spec in [
            "requests @ https://files.pythonhosted.org/requests-2.31.0.whl",
            "pkg @ https://example.com/x.whl ; python_version >= \"3.7\"",
            ".",
            "..",
            "sub/dir",
        ] {
            let t = parse_pypi_spec(spec);
            assert!(
                matches!(t.kind, TargetKind::Unverifiable { .. }),
                "for '{}': {:?}",
                spec,
                t.kind
            );
        }
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
    fn pip_args_extract_requirements_files() {
        let args = vec![
            "-r".to_string(),
            "reqs.txt".to_string(),
            "requests==2.31.0".to_string(),
            "--requirement=other.txt".to_string(),
            "--constraint".to_string(),
            "constraints.txt".to_string(),
            "--constraint=other-constraints.txt".to_string(),
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
        assert!(!p.specs.contains(&"constraints.txt".to_string()));
        assert!(!p.specs.contains(&"other-constraints.txt".to_string()));
        assert!(!p
            .requirements_files
            .contains(&PathBuf::from("constraints.txt")));
        assert!(!p
            .requirements_files
            .contains(&PathBuf::from("other-constraints.txt")));
    }

    #[test]
    fn pip_attached_short_options_are_recognized() {
        // pip accepts `-rreqs.txt` (value attached); reading it as a boolean
        // flag would make the install look bare and skip the gate entirely.
        let args = vec![
            "-rreqs.txt".to_string(),
            "-cconstraints.txt".to_string(),
            "-e./local".to_string(),
        ];
        let p = extract_pip_positionals(&args).unwrap();
        assert_eq!(p.requirements_files, vec![PathBuf::from("reqs.txt")]);
        assert!(p.specs.contains(&"-e ./local".to_string()));
        assert!(!p.specs.contains(&"-cconstraints.txt".to_string()));
    }

    #[test]
    fn pip_value_flag_values_are_not_specs() {
        // A bare-word value of a known value-taking flag must not be
        // verified (or blocked) as a package.
        let args = vec![
            "--platform".to_string(),
            "win_amd64".to_string(),
            "--no-binary".to_string(),
            ":all:".to_string(),
            "--target".to_string(),
            "build".to_string(),
            "requests".to_string(),
        ];
        let p = extract_pip_positionals(&args).unwrap();
        assert_eq!(p.specs, vec!["requests".to_string()]);
    }

    #[test]
    fn requirements_format_control_scan_follows_includes() {
        // SECURITY: pip applies file-level format-control AFTER CLI flags,
        // so a --no-binary line (even in a nested -r include) defeats the
        // tree pass's trailing --only-binary :all: guard. The scan must
        // find it transitively; option lines that don't touch
        // format-control must not trip it.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("inner.txt"),
            "# comment\n--no-binary :all:\n",
        )
        .expect("write inner");
        std::fs::write(dir.path().join("outer.txt"), "flask==1.0\n-r inner.txt\n")
            .expect("write outer");
        let (file, directive) =
            requirements_format_control_directive(&[dir.path().join("outer.txt")])
                .expect("directive must be found through the include");
        assert!(file.ends_with("outer.txt") || file.ends_with("inner.txt"));
        assert_eq!(directive, "--no-binary");

        // SECURITY: pip reads nested `-c` constraint includes and applies
        // their format-control too, so a --no-binary hidden behind a `-c`
        // include must also be found transitively.
        std::fs::write(
            dir.path().join("constraint_inner.txt"),
            "# comment\n--no-binary :all:\n",
        )
        .expect("write constraint inner");
        std::fs::write(
            dir.path().join("constraint_outer.txt"),
            "flask==1.0\n-c constraint_inner.txt\n",
        )
        .expect("write constraint outer");
        let (c_file, c_directive) =
            requirements_format_control_directive(&[dir.path().join("constraint_outer.txt")])
                .expect("directive must be found through the -c constraint include");
        assert!(
            c_file.ends_with("constraint_outer.txt") || c_file.ends_with("constraint_inner.txt")
        );
        assert_eq!(c_directive, "--no-binary");

        // Attached `=` form counts too.
        std::fs::write(dir.path().join("eq.txt"), "--only-binary=:none:\n").expect("write eq");
        assert!(requirements_format_control_directive(&[dir.path().join("eq.txt")]).is_some());

        // Non-format-control options don't trip the scan.
        std::fs::write(
            dir.path().join("clean.txt"),
            "flask==1.0\n--prefer-binary\n--hash=sha256:abc\n",
        )
        .expect("write clean");
        assert!(requirements_format_control_directive(&[dir.path().join("clean.txt")]).is_none());

        // A missing file is pip's error to report, not the scan's — it
        // can't hide a directive pip could read (same uid).
        assert!(requirements_format_control_directive(&[dir.path().join("absent.txt")]).is_none());
    }
}
