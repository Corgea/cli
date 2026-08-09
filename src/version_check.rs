//! Compatibility pre-flight: warn when the Corgea webapp a command is about to
//! talk to is older than this CLI expects.
//!
//! Best effort throughout. A webapp that does not report its version, an
//! unreachable endpoint, or an unparsable version all leave the command to run
//! exactly as before — the check only ever adds a warning.

use crate::log::debug;
use crate::utils::api;
use crate::utils::generic::get_env_var_if_exists;
use regex::Regex;
use semver::Version;
use std::sync::LazyLock;

/// Oldest webapp release this CLI is built against. Raise it whenever the CLI
/// starts depending on a webapp change.
pub const MIN_WEBAPP_VERSION: &str = "v1.71.3";

/// Overrides `MIN_WEBAPP_VERSION`, for testing a different floor without a
/// rebuild.
const MIN_VERSION_ENV_VAR: &str = "CORGEA_MIN_WEBAPP_VERSION";

/// Escape hatch for anyone deliberately pinned to an older self-hosted webapp
/// who does not want the warning on every command.
const SKIP_ENV_VAR: &str = "CORGEA_SKIP_WEBAPP_VERSION_CHECK";

/// Deployment versions are not plain semver: releases ship as `v1.71.3`, while
/// pre-release and per-customer builds add a suffix (`v1.71.3-beta`,
/// `v1.71.3-client-a`). Only the leading numeric part is comparable, so a
/// suffixed build counts as the release it was cut from rather than sorting
/// below it the way semver pre-release ordering would.
static NUMERIC_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?").expect("valid version regex"));

/// The `major.minor.patch` numbers in `raw`, or `None` when it carries none.
/// A missing patch reads as `0`, so `v1.71` and `v1.71.0` compare equal.
pub fn extract_version(raw: &str) -> Option<Version> {
    let captures = NUMERIC_VERSION.captures(raw)?;
    let number = |group: usize| match captures.get(group) {
        Some(digits) => digits.as_str().parse::<u64>().ok(),
        None => Some(0),
    };
    Some(Version::new(number(1)?, number(2)?, number(3)?))
}

/// The warning to show for a webapp running `webapp_version`, or `None` when it
/// is new enough or when either version has no numbers to compare.
pub fn outdated_warning(corgea_url: &str, webapp_version: &str, minimum: &str) -> Option<String> {
    let running = extract_version(webapp_version)?;
    let required = extract_version(minimum)?;

    if running >= required {
        return None;
    }

    Some(format!(
        "Warning: this Corgea CLI (v{cli}) requires Corgea webapp {minimum} or newer, \
         but {corgea_url} is running {webapp_version}. Commands may fail or return \
         incomplete results until the webapp is upgraded. \
         Set {SKIP_ENV_VAR}=1 to silence this warning.",
        cli = env!("CARGO_PKG_VERSION"),
    ))
}

/// The version floor to enforce: `CORGEA_MIN_WEBAPP_VERSION`, else the built-in
/// `MIN_WEBAPP_VERSION`.
fn min_webapp_version() -> String {
    get_env_var_if_exists(MIN_VERSION_ENV_VAR).unwrap_or_else(|| MIN_WEBAPP_VERSION.to_string())
}

fn check_disabled() -> bool {
    matches!(
        get_env_var_if_exists(SKIP_ENV_VAR)
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Warn on stderr when the webapp at `corgea_url` is older than this CLI needs.
/// Call before running the command the user asked for.
pub fn warn_if_webapp_outdated(corgea_url: &str) {
    if check_disabled() {
        debug("Webapp version check disabled");
        return;
    }

    let webapp_version = match api::get_webapp_version(corgea_url) {
        Ok(Some(version)) => version,
        Ok(None) => {
            debug("Webapp did not report a version; skipping compatibility check");
            return;
        }
        Err(e) => {
            debug(&format!("Failed to read the webapp version: {}", e));
            return;
        }
    };

    debug(&format!("Webapp reports version {}", webapp_version));

    if let Some(warning) = outdated_warning(corgea_url, &webapp_version, &min_webapp_version()) {
        log::warn!("{}", warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_numbers_from_release_and_suffixed_versions() {
        assert_eq!(extract_version("v1.71.3"), Some(Version::new(1, 71, 3)));
        assert_eq!(extract_version("1.71.3"), Some(Version::new(1, 71, 3)));
        assert_eq!(
            extract_version("v1.71.3-beta"),
            Some(Version::new(1, 71, 3))
        );
        assert_eq!(
            extract_version("v1.71.3-client-a"),
            Some(Version::new(1, 71, 3))
        );
        assert_eq!(
            extract_version("v1.71.3-main-a1b2c3d"),
            Some(Version::new(1, 71, 3))
        );
    }

    #[test]
    fn a_missing_patch_reads_as_zero() {
        assert_eq!(extract_version("v1.71"), Some(Version::new(1, 71, 0)));
        assert_eq!(extract_version("v2"), None);
    }

    #[test]
    fn versions_without_numbers_are_not_comparable() {
        assert_eq!(extract_version(""), None);
        assert_eq!(extract_version("unknown"), None);
        assert_eq!(extract_version("main"), None);
    }

    #[test]
    fn warns_only_when_the_webapp_is_behind_the_minimum() {
        let warn = |version: &str| outdated_warning("https://corgea.test", version, "v1.71.3");

        assert!(warn("v1.71.2").is_some());
        assert!(warn("v1.70.9").is_some());
        assert!(warn("v0.9.0").is_some());
        assert!(warn("v1.71.3").is_none());
        assert!(warn("v1.71.4").is_none());
        assert!(warn("v2.0.0").is_none());
    }

    #[test]
    fn a_suffixed_build_counts_as_the_release_it_was_cut_from() {
        // Plain semver sorts `1.71.3-beta` below `1.71.3`; comparing only the
        // numeric part deliberately does not.
        let warn = |version: &str| outdated_warning("https://corgea.test", version, "v1.71.3");

        assert!(warn("v1.71.3-beta").is_none());
        assert!(warn("v1.71.3-client-a").is_none());
        assert!(warn("v1.71.2-client-a").is_some());
    }

    #[test]
    fn unreadable_versions_never_warn() {
        assert!(outdated_warning("https://corgea.test", "unknown", "v1.71.3").is_none());
        assert!(outdated_warning("https://corgea.test", "v1.0.0", "not-a-version").is_none());
    }

    #[test]
    fn the_warning_names_the_instance_the_minimum_and_the_escape_hatch() {
        let warning = outdated_warning("https://corgea.test", "v1.70.0", "v1.71.3")
            .expect("an outdated webapp warns");

        assert!(warning.contains("v1.71.3"), "{warning}");
        assert!(warning.contains("v1.70.0"), "{warning}");
        assert!(warning.contains("https://corgea.test"), "{warning}");
        assert!(warning.contains(env!("CARGO_PKG_VERSION")), "{warning}");
        assert!(warning.contains(SKIP_ENV_VAR), "{warning}");
    }

    #[test]
    fn the_default_minimum_is_a_readable_version() {
        assert_eq!(
            extract_version(MIN_WEBAPP_VERSION),
            Some(Version::new(1, 71, 3))
        );
    }
}
