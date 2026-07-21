//! `corgea advisories` — read-only pre-decision queries against the vuln-api.
//!
//! Reports, never refuses: the install-wrap gate (`corgea npm|pip|...`)
//! remains the enforcement backstop. Exit codes: 0 clean / no advisories,
//! 1 advisories found, 2 error (network, auth, parse, guard, bad args).

use clap::Subcommand;

/// Advisories JSON schema version — independent of precheck's
/// render::SCHEMA_VERSION so the two document families evolve separately.
const SCHEMA_VERSION: u32 = 1;

#[derive(Subcommand, Debug, Clone)]
pub enum AdvisoriesSubcommand {
    /// Query known advisories for a package, optionally for one exact version
    Check {
        /// Registry ecosystem: npm or pypi (pip is accepted as an alias)
        ecosystem: String,
        /// Package spec: <package> or <package>@<version> (exact versions only)
        spec: String,
        /// Emit a stable machine-readable JSON document instead of text
        #[arg(long)]
        json: bool,
    },
}

/// Connection options resolved by the binary crate (base URL + optional
/// token) — the same base-URL/token-isolation selection the install wrap
/// uses. `token: None` is public mode; the command must work tokenless.
pub struct AdvisoriesOptions {
    pub base_url: String,
    pub token: Option<String>,
}

pub fn run(cmd: AdvisoriesSubcommand, opts: AdvisoriesOptions) -> i32 {
    let AdvisoriesSubcommand::Check {
        ecosystem,
        spec,
        json,
    } = cmd;
    match run_check(&ecosystem, &spec, json, &opts) {
        Ok(code) => code,
        Err(e) => {
            report_error(&e.to_string(), json);
            2
        }
    }
}

/// Report a failure. In json mode the error document goes to stdout
/// (mirroring precheck's pre-report error documents); otherwise human text
/// goes to stderr. Exit code stays 2 either way. Scope: only post-clap
/// failures reach here — clap-level usage errors abort before `run` sees
/// `--json` and keep clap's own stderr text.
fn report_error(message: &str, json: bool) {
    if json {
        let doc = serde_json::json!({ "schema_version": SCHEMA_VERSION, "error": message });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    } else {
        eprintln!("error: {message}");
    }
}

fn run_check(
    ecosystem: &str,
    spec: &str,
    json: bool,
    opts: &AdvisoriesOptions,
) -> Result<i32, Box<dyn std::error::Error>> {
    let ecosystem = parse_ecosystem(ecosystem)?;
    let (name, version) = parse_package_spec(ecosystem, spec)?;
    let client = crate::vuln_api::http_client()?;
    match version {
        Some(version) => {
            let resp = crate::vuln_api::check_package_version(
                &client,
                &opts.base_url,
                opts.token.as_deref(),
                ecosystem,
                &name,
                &version,
            )?;
            Ok(render_version_verdict(
                ecosystem, &name, &version, &resp, json,
            ))
        }
        None => {
            let profile = crate::vuln_api::fetch_package_profile(
                &client,
                &opts.base_url,
                opts.token.as_deref(),
                ecosystem,
                &name,
            )?;
            Ok(render_profile(ecosystem, &name, profile.as_ref(), json))
        }
    }
}

/// npm|pypi, case-insensitive; `pip` accepted as an alias for pypi.
fn parse_ecosystem(raw: &str) -> Result<crate::vuln_api::Ecosystem, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "npm" => Ok(crate::vuln_api::Ecosystem::Npm),
        "pypi" | "pip" => Ok(crate::vuln_api::Ecosystem::Pypi),
        other => Err(format!("unknown ecosystem '{other}' (expected: npm, pypi)")),
    }
}

/// Split `<package>[@<version>]` on the LAST `@` at index > 0, so scoped
/// npm names survive: `@scope/pkg@1.2.3` → ("@scope/pkg", Some("1.2.3")),
/// `@scope/pkg` → ("@scope/pkg", None). For pypi the pip-native spelling is
/// also accepted: `requests==2.31.0` splits at the leftmost `==` (`===`,
/// PEP 440 arbitrary equality, reads as exact too) and extras are stripped
/// (`requests[security]` → `requests`) — they select install features, not
/// the registry name. Bare `@`, trailing separators, and empty specs are
/// usage errors. Versions must be exact — range syntax, tags, and (npm)
/// partial versions are rejected.
fn parse_package_spec(
    ecosystem: crate::vuln_api::Ecosystem,
    spec: &str,
) -> Result<(String, Option<String>), String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("package spec is empty".to_string());
    }
    let is_pypi = ecosystem == crate::vuln_api::Ecosystem::Pypi;
    let (name, version, sep) = match spec.split_once("==") {
        Some((n, v)) if is_pypi => (n, Some(v.strip_prefix('=').unwrap_or(v)), "=="),
        _ => match spec.rfind('@') {
            Some(0) | None => (spec, None, "@"),
            Some(pos) => (&spec[..pos], Some(&spec[pos + 1..]), "@"),
        },
    };
    let name = if is_pypi {
        name.split_once('[').map_or(name, |(n, _)| n)
    } else {
        name
    };
    // PEP 508 allows spaces around the operator (`requests == 2.31.0`), so
    // trim each half after splitting.
    let name = name.trim();
    if name.is_empty() || name == "@" {
        return Err(format!("invalid package spec '{spec}'"));
    }
    match version.map(str::trim) {
        None => Ok((name.to_string(), None)),
        Some("") => Err(format!(
            "invalid package spec '{spec}': trailing '{sep}' (write <package> or <package>{sep}<version>)"
        )),
        Some(v) => {
            require_exact_version(ecosystem, v)?;
            Ok((name.to_string(), Some(v.to_string())))
        }
    }
}

/// Reject anything that isn't a single exact version literal, per
/// ecosystem's own rules:
///
/// * npm — strict semver parse. This is what "exact" means to npm, and it
///   rejects ranges, dist-tags (`latest`), and partial versions in one
///   check: npm itself treats `1.2` as the x-range `1.2.x`
///   (see `verify_deps::registry::parse_version_or_x_range`), so a partial
///   is NOT an exact version there.
/// * pypi — PEP 440 versions are too varied for a strict parse (epochs
///   `2!1.0`, `1.0rc1`, `.post1`, `.dev2`, and `1.2` IS exact), so gate on
///   range syntax instead: operator prefixes, whitespace joins, specifier
///   sets, and wildcards. Unrecognized literals pass through and the
///   server answers for that exact string.
fn require_exact_version(ecosystem: crate::vuln_api::Ecosystem, v: &str) -> Result<(), String> {
    let exact_err = |detail: &str| {
        Err(format!(
            "version '{v}' is not an exact version ({detail}; pass one exact version)"
        ))
    };
    match ecosystem {
        crate::vuln_api::Ecosystem::Npm => {
            if semver::Version::parse(v).is_ok() {
                Ok(())
            } else {
                exact_err(
                    "npm versions must be full semver like 1.2.3 — no ranges, tags, or partials",
                )
            }
        }
        crate::vuln_api::Ecosystem::Pypi => {
            // Range operators and joins: PEP 440 prefixes (== != >= <= > < ~=),
            // whitespace, "," specifier sets, "||"; wildcard components.
            if v.starts_with(['^', '~', '>', '<', '=', '!'])
                || v.chars().any(char::is_whitespace)
                || v.contains("||")
                || v.contains(',')
                || v == "*"
                || v.split('.')
                    .any(|p| p == "*" || p.eq_ignore_ascii_case("x"))
            {
                exact_err("ranges are not supported")
            } else {
                Ok(())
            }
        }
    }
}

/// Render the versioned-form verdict (text or `--json`) and return the exit
/// code. `ecosystem` is used only by the json document.
fn render_version_verdict(
    ecosystem: crate::vuln_api::Ecosystem,
    name: &str,
    version: &str,
    resp: &crate::vuln_api::VulnCheckResponse,
    json: bool,
) -> i32 {
    if json {
        let doc = version_verdict_json(ecosystem, name, version, resp);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        return if resp.is_vulnerable { 1 } else { 0 };
    }
    if resp.is_vulnerable {
        println!(
            "{name}@{version}: vulnerable ({} advisories)",
            resp.matches.len()
        );
        for m in &resp.matches {
            println!("  {} ({}){}", m.advisory_id, m.severity_level, fix_note(m));
        }
        if let Some(safe) = crate::vuln_api::safe_version(&resp.matches) {
            println!("  → safe version: {name}@{safe}");
        }
        1
    } else {
        println!("{name}@{version}: clean — no known advisories");
        0
    }
}

/// CLI-owned, schema-versioned document for the versioned form. The
/// `verdict` object reuses the gate's `verdict_json` vocabulary
/// (`status`/`matches`/`remediation`) so both document families read alike.
fn version_verdict_json(
    ecosystem: crate::vuln_api::Ecosystem,
    name: &str,
    version: &str,
    resp: &crate::vuln_api::VulnCheckResponse,
) -> serde_json::Value {
    let verdict = if resp.is_vulnerable {
        serde_json::json!({
            "status": "vulnerable",
            "matches": resp.matches,
            "remediation": crate::vuln_api::safe_version(&resp.matches),
        })
    } else {
        serde_json::json!({ "status": "clean" })
    };
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "ecosystem": ecosystem.path_segment(),
        "package": name,
        "version": version,
        "verdict": verdict,
    })
}

/// Same wording as the gate's fix suffix (precheck/render.rs::fix_note),
/// kept local: one format string, not worth a cross-module export.
fn fix_note(m: &crate::vuln_api::VulnMatch) -> String {
    match &m.fixed_version {
        Some(v) => format!(" — fixed in {v}"),
        None => " — no fixed version known".to_string(),
    }
}

/// The route's `LIMIT 100`: exactly 100 rows means "possibly more exist",
/// never provably truncated (the route serves no total).
const PROFILE_LISTING_CAP: usize = 100;

/// Truncate `s` to `max` chars (char-boundary safe, ellipsis when cut).
fn truncate_summary(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

/// Render the unversioned (package profile) form and return the exit code.
/// `None` = the route answered 404 (package unknown to the database).
fn render_profile(
    ecosystem: crate::vuln_api::Ecosystem,
    name: &str,
    profile: Option<&crate::vuln_api::PackageProfile>,
    json: bool,
) -> i32 {
    let advisories: &[crate::vuln_api::AdvisorySummary] =
        profile.map(|p| p.advisories.as_slice()).unwrap_or(&[]);
    let found = profile.is_some();

    if json {
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "ecosystem": ecosystem.path_segment(),
            "package": name,
            "found": found,
            "advisories": advisories,
            "possibly_truncated": advisories.len() == PROFILE_LISTING_CAP,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        return if advisories.is_empty() { 0 } else { 1 };
    }

    if advisories.is_empty() {
        if found {
            println!("{name}: no known advisories");
        } else {
            println!("{name}: not found in the advisory database (no known advisories)");
        }
        return 0;
    }

    let cap_note = if advisories.len() == PROFILE_LISTING_CAP {
        format!(" (listing capped at {PROFILE_LISTING_CAP}; more may exist)")
    } else {
        String::new()
    };
    println!("{name}: {} known advisories{cap_note}", advisories.len());
    for a in advisories {
        println!("  {}{}", a.id, advisory_detail(a));
        if let Some(summary) = &a.summary {
            let summary = summary.trim();
            if !summary.is_empty() {
                println!("    {}", truncate_summary(summary, 100));
            }
        }
    }
    println!(
        "note: package-level listing; run `corgea advisories check {} {name}@<version>` for a version verdict.",
        ecosystem.path_segment()
    );
    1
}

/// The parenthesized detail group plus flag markers for one advisory line:
/// `(high, cvss 7.5, tier 1) [kev] [malware] published 2023-01-12`. Each
/// element is included only when present.
fn advisory_detail(a: &crate::vuln_api::AdvisorySummary) -> String {
    let mut group: Vec<String> = Vec::new();
    if let Some(sev) = &a.severity {
        group.push(sev.clone());
    }
    if let Some(cvss) = a.cvss_score {
        group.push(format!("cvss {cvss}"));
    }
    if let Some(tier) = a.tier {
        group.push(format!("tier {tier}"));
    }
    let mut out = String::new();
    if !group.is_empty() {
        out.push_str(&format!(" ({})", group.join(", ")));
    }
    if a.kev == Some(true) {
        out.push_str(" [kev]");
    }
    if a.malware == Some(true) {
        out.push_str(" [malware]");
    }
    if let Some(published) = &a.published_at {
        out.push_str(&format!(" published {published}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln_api::Ecosystem;

    #[test]
    fn parse_ecosystem_accepts_known_values() {
        assert_eq!(parse_ecosystem("npm"), Ok(Ecosystem::Npm));
        assert_eq!(parse_ecosystem("NPM"), Ok(Ecosystem::Npm));
        assert_eq!(parse_ecosystem("pypi"), Ok(Ecosystem::Pypi));
        assert_eq!(parse_ecosystem("PyPI"), Ok(Ecosystem::Pypi));
        assert_eq!(parse_ecosystem("pip"), Ok(Ecosystem::Pypi));
    }

    #[test]
    fn parse_ecosystem_rejects_unknown() {
        let err = parse_ecosystem("rubygems").expect_err("unknown ecosystem must error");
        assert!(err.contains("npm"), "err lists valid values: {err}");
        assert!(err.contains("pypi"), "err lists valid values: {err}");
    }

    #[test]
    fn parse_spec_unscoped_with_and_without_version() {
        assert_eq!(
            parse_package_spec(Ecosystem::Npm, "leftpad"),
            Ok(("leftpad".to_string(), None))
        );
        assert_eq!(
            parse_package_spec(Ecosystem::Npm, "leftpad@1.0.0"),
            Ok(("leftpad".to_string(), Some("1.0.0".to_string())))
        );
    }

    #[test]
    fn parse_spec_scoped_with_and_without_version() {
        assert_eq!(
            parse_package_spec(Ecosystem::Npm, "@scope/pkg"),
            Ok(("@scope/pkg".to_string(), None))
        );
        assert_eq!(
            parse_package_spec(Ecosystem::Npm, "@scope/pkg@1.2.3"),
            Ok(("@scope/pkg".to_string(), Some("1.2.3".to_string())))
        );
    }

    #[test]
    fn parse_spec_pypi_accepts_pip_style_separators() {
        for spec in [
            "requests==2.31.0",
            "requests===2.31.0",
            "requests == 2.31.0",
        ] {
            assert_eq!(
                parse_package_spec(Ecosystem::Pypi, spec),
                Ok(("requests".to_string(), Some("2.31.0".to_string()))),
                "spec: {spec:?}"
            );
        }
    }

    #[test]
    fn parse_spec_pypi_strips_extras() {
        assert_eq!(
            parse_package_spec(Ecosystem::Pypi, "requests[security]"),
            Ok(("requests".to_string(), None))
        );
        assert_eq!(
            parse_package_spec(Ecosystem::Pypi, "requests[security]==2.31.0"),
            Ok(("requests".to_string(), Some("2.31.0".to_string())))
        );
        assert_eq!(
            parse_package_spec(Ecosystem::Pypi, "requests[security]@2.31.0"),
            Ok(("requests".to_string(), Some("2.31.0".to_string())))
        );
    }

    #[test]
    fn parse_spec_pypi_rejects_bad_pip_forms() {
        let err =
            parse_package_spec(Ecosystem::Pypi, "requests==").expect_err("trailing == is an error");
        assert!(err.contains("trailing"), "err: {err}");
        assert!(parse_package_spec(Ecosystem::Pypi, "[security]==1.0").is_err());
        assert!(parse_package_spec(Ecosystem::Pypi, "requests==2.31.*").is_err());
    }

    #[test]
    fn parse_spec_rejects_trailing_at() {
        let err = parse_package_spec(Ecosystem::Npm, "foo@").expect_err("trailing @ is an error");
        assert!(err.contains("trailing"), "err: {err}");
    }

    #[test]
    fn parse_spec_rejects_bare_and_empty() {
        assert!(parse_package_spec(Ecosystem::Npm, "@").is_err());
        assert!(parse_package_spec(Ecosystem::Npm, "").is_err());
        assert!(parse_package_spec(Ecosystem::Npm, "   ").is_err());
    }

    #[test]
    fn npm_rejects_non_exact_versions() {
        for bad in [
            "^1.0",
            "~1.0",
            ">=1.0",
            "1.0.0 - 2.0.0",
            "1.0 || 2.0",
            "*",
            "1.x",
            "1.2",
            "latest",
        ] {
            assert!(
                require_exact_version(Ecosystem::Npm, bad).is_err(),
                "npm should reject {bad:?}"
            );
        }
    }

    #[test]
    fn npm_accepts_exact_semver() {
        for good in ["1.2.3", "1.2.3-beta.1", "1.2.3+build.5"] {
            assert!(
                require_exact_version(Ecosystem::Npm, good).is_ok(),
                "npm should accept {good:?}"
            );
        }
    }

    #[test]
    fn pypi_rejects_range_syntax() {
        for bad in ["==1.0", ">=1.0,<2.0", "~=1.4", "!=1.0", "1.*", "1.0 || 2.0"] {
            assert!(
                require_exact_version(Ecosystem::Pypi, bad).is_err(),
                "pypi should reject {bad:?}"
            );
        }
    }

    #[test]
    fn pypi_accepts_exact_literals() {
        for good in ["1.2", "2!1.0", "1.0rc1", "1.0.post1"] {
            assert!(
                require_exact_version(Ecosystem::Pypi, good).is_ok(),
                "pypi should accept {good:?}"
            );
        }
    }
}
