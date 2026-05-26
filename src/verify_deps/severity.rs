//! Severity ladder + floor filter for `corgea deps --check-cve --fail-cve`.
//!
//! The vuln-api emits categorical `severity_level` strings
//! (`critical | high | medium | low | none | unknown`, lowercased on the
//! wire by `cve_worker/src/worker.js`). This module locks an ordered
//! `SeverityLevel` enum on the CLI side and the user-facing
//! `SeverityFloor` used by the `--severity` flag.
//!
//! Unknown server-emitted strings parse to `SeverityLevel::Info` so a
//! future server vocabulary drift (e.g. `"emergency"`, or the existing
//! `"none"` / `"unknown"`) never silently drops findings from the
//! `--fail-cve` gate. A `CORGEA_DEBUG`-gated stderr warning fires the
//! first time a non-canonical string is seen.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Mutex, OnceLock};

/// Ordered severity ladder. `Info` is the bottom rung and is also the
/// fail-open target for unknown server strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    /// Strict parse: returns `Err` for any non-canonical string. Used by
    /// `parse_severity_floor_arg` (which surfaces the error to clap).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(SeverityLevel::Info),
            "low" => Ok(SeverityLevel::Low),
            "medium" => Ok(SeverityLevel::Medium),
            "high" => Ok(SeverityLevel::High),
            "critical" => Ok(SeverityLevel::Critical),
            other => Err(format!(
                "unknown severity: '{}'. Expected one of: critical, high, medium, low, info.",
                other
            )),
        }
    }

    /// Lossy parse used by the gating block on `severity_level` strings
    /// emitted by the vuln-api. Unknown strings (including the server's
    /// own `none` / `unknown` fallback and any future addition) collapse
    /// to `Info` and trigger a `CORGEA_DEBUG`-gated warn-once channel so
    /// they never silently drop out of the gate.
    pub fn parse_lossy(s: &str) -> Self {
        match Self::parse(s) {
            Ok(level) => level,
            Err(_) => {
                warn_unknown_severity_once(s);
                SeverityLevel::Info
            }
        }
    }

    /// Lowercase canonical label for text + JSON rendering.
    pub fn label(self) -> &'static str {
        match self {
            SeverityLevel::Info => "info",
            SeverityLevel::Low => "low",
            SeverityLevel::Medium => "medium",
            SeverityLevel::High => "high",
            SeverityLevel::Critical => "critical",
        }
    }
}

/// Floor used by `--severity`.
///
/// - `Any` — chunk-02 behavior; `includes(level)` is always `true`.
/// - `AtLeast(min)` — single value `--severity high` matches `high | critical`.
/// - `OneOf(set)` — comma list `--severity critical,high` matches exactly those.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SeverityFloor {
    #[default]
    Any,
    AtLeast(SeverityLevel),
    OneOf(BTreeSet<SeverityLevel>),
}

impl SeverityFloor {
    /// True iff `level` meets this floor.
    pub fn includes(&self, level: SeverityLevel) -> bool {
        match self {
            SeverityFloor::Any => true,
            SeverityFloor::AtLeast(min) => level >= *min,
            SeverityFloor::OneOf(set) => set.contains(&level),
        }
    }

    /// Render the floor for text / JSON output. Descending-by-severity
    /// for `OneOf` so the JSON value is stable across runs
    /// (`"critical,high"`, never `"high,critical"`).
    pub fn label(&self) -> String {
        match self {
            SeverityFloor::Any => "any".to_string(),
            SeverityFloor::AtLeast(level) => level.label().to_string(),
            SeverityFloor::OneOf(set) => {
                let mut levels: Vec<SeverityLevel> = set.iter().copied().collect();
                levels.sort_by(|a, b| b.cmp(a)); // descending
                levels
                    .iter()
                    .map(|l| l.label())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        }
    }
}

/// Clap `value_parser` for the `--severity` flag. Empty string and
/// `"any"` (case-insensitive) map to `Any`; a value containing a comma
/// maps to `OneOf` after parsing each token; anything else maps to
/// `AtLeast` after parsing as a single `SeverityLevel`.
pub fn parse_severity_floor_arg(raw: &str) -> Result<SeverityFloor, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("any") {
        return Ok(SeverityFloor::Any);
    }
    if trimmed.contains(',') {
        let set: Result<BTreeSet<_>, _> = trimmed
            .split(',')
            .map(|p| SeverityLevel::parse(p.trim()))
            .collect();
        return set.map(SeverityFloor::OneOf);
    }
    SeverityLevel::parse(trimmed).map(SeverityFloor::AtLeast)
}

/// Process-local channel for warn-once-per-unknown-string behavior.
fn warn_unknown_severity_once(raw: &str) {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match seen.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let key = raw.trim().to_ascii_lowercase();
    // Env-check first so that a future `CORGEA_DEBUG` toggle still surfaces
    // a previously-seen unknown severity (short-circuit avoids inserting
    // into SEEN until we actually intend to print).
    if crate::utils::generic::get_env_var_if_exists("CORGEA_DEBUG").is_some() && guard.insert(key) {
        eprintln!(
            "debug: vuln-api emitted unknown severity_level '{}' — treating as 'info' for --severity filtering.",
            raw
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip_canonical_values() {
        assert_eq!(SeverityLevel::parse("info").unwrap(), SeverityLevel::Info);
        assert_eq!(SeverityLevel::parse("low").unwrap(), SeverityLevel::Low);
        assert_eq!(
            SeverityLevel::parse("medium").unwrap(),
            SeverityLevel::Medium
        );
        assert_eq!(SeverityLevel::parse("high").unwrap(), SeverityLevel::High);
        assert_eq!(
            SeverityLevel::parse("critical").unwrap(),
            SeverityLevel::Critical
        );
    }

    #[test]
    fn parse_is_case_insensitive_and_trims() {
        assert_eq!(
            SeverityLevel::parse("CRITICAL").unwrap(),
            SeverityLevel::Critical
        );
        assert_eq!(
            SeverityLevel::parse("  High  ").unwrap(),
            SeverityLevel::High
        );
    }

    #[test]
    fn parse_rejects_unknown_strings() {
        assert!(SeverityLevel::parse("bogus").is_err());
        assert!(SeverityLevel::parse("").is_err());
        assert!(SeverityLevel::parse("none").is_err());
        assert!(SeverityLevel::parse("unknown").is_err());
    }

    #[test]
    fn parse_lossy_maps_unknown_to_info() {
        assert_eq!(SeverityLevel::parse_lossy("none"), SeverityLevel::Info);
        assert_eq!(SeverityLevel::parse_lossy("unknown"), SeverityLevel::Info);
        assert_eq!(SeverityLevel::parse_lossy("emergency"), SeverityLevel::Info);
        // Canonical values still parse strictly.
        assert_eq!(
            SeverityLevel::parse_lossy("critical"),
            SeverityLevel::Critical
        );
    }

    #[test]
    fn ordering_is_info_lt_low_lt_medium_lt_high_lt_critical() {
        assert!(SeverityLevel::Info < SeverityLevel::Low);
        assert!(SeverityLevel::Low < SeverityLevel::Medium);
        assert!(SeverityLevel::Medium < SeverityLevel::High);
        assert!(SeverityLevel::High < SeverityLevel::Critical);
    }

    #[test]
    fn floor_any_includes_everything() {
        let floor = SeverityFloor::Any;
        for level in [
            SeverityLevel::Info,
            SeverityLevel::Low,
            SeverityLevel::Medium,
            SeverityLevel::High,
            SeverityLevel::Critical,
        ] {
            assert!(floor.includes(level), "Any should include {:?}", level);
        }
    }

    #[test]
    fn floor_at_least_high_matches_high_and_critical_only() {
        let floor = SeverityFloor::AtLeast(SeverityLevel::High);
        assert!(floor.includes(SeverityLevel::Critical));
        assert!(floor.includes(SeverityLevel::High));
        assert!(!floor.includes(SeverityLevel::Medium));
        assert!(!floor.includes(SeverityLevel::Low));
        assert!(!floor.includes(SeverityLevel::Info));
    }

    #[test]
    fn floor_one_of_matches_exact_set() {
        let mut set = BTreeSet::new();
        set.insert(SeverityLevel::Critical);
        set.insert(SeverityLevel::High);
        let floor = SeverityFloor::OneOf(set);
        assert!(floor.includes(SeverityLevel::Critical));
        assert!(floor.includes(SeverityLevel::High));
        assert!(!floor.includes(SeverityLevel::Medium));
        assert!(!floor.includes(SeverityLevel::Low));
        assert!(!floor.includes(SeverityLevel::Info));
    }

    #[test]
    fn parse_arg_empty_and_any_map_to_any() {
        assert_eq!(parse_severity_floor_arg("").unwrap(), SeverityFloor::Any);
        assert_eq!(parse_severity_floor_arg("any").unwrap(), SeverityFloor::Any);
        assert_eq!(parse_severity_floor_arg("ANY").unwrap(), SeverityFloor::Any);
        assert_eq!(
            parse_severity_floor_arg("  any  ").unwrap(),
            SeverityFloor::Any
        );
    }

    #[test]
    fn parse_arg_single_value_maps_to_at_least() {
        assert_eq!(
            parse_severity_floor_arg("critical").unwrap(),
            SeverityFloor::AtLeast(SeverityLevel::Critical)
        );
        assert_eq!(
            parse_severity_floor_arg("HIGH").unwrap(),
            SeverityFloor::AtLeast(SeverityLevel::High)
        );
    }

    #[test]
    fn parse_arg_comma_list_maps_to_one_of() {
        let mut expected = BTreeSet::new();
        expected.insert(SeverityLevel::Critical);
        expected.insert(SeverityLevel::High);
        assert_eq!(
            parse_severity_floor_arg("critical,high").unwrap(),
            SeverityFloor::OneOf(expected.clone())
        );
        // Whitespace + duplicates dedup via BTreeSet.
        assert_eq!(
            parse_severity_floor_arg(" critical , high , critical ").unwrap(),
            SeverityFloor::OneOf(expected)
        );
    }

    #[test]
    fn parse_arg_rejects_bad_token_in_list() {
        assert!(parse_severity_floor_arg("critical,bogus").is_err());
        assert!(parse_severity_floor_arg("bogus").is_err());
    }

    #[test]
    fn label_renders_one_of_in_descending_order() {
        let mut set = BTreeSet::new();
        set.insert(SeverityLevel::High);
        set.insert(SeverityLevel::Critical);
        let floor = SeverityFloor::OneOf(set);
        assert_eq!(floor.label(), "critical,high");
    }

    #[test]
    fn label_any_and_at_least_render_canonical() {
        assert_eq!(SeverityFloor::Any.label(), "any");
        assert_eq!(
            SeverityFloor::AtLeast(SeverityLevel::Critical).label(),
            "critical"
        );
    }
}
