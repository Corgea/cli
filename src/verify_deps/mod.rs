//! Slim slice of #89's verify_deps: registry resolution + threshold helpers.

pub mod registry;

use std::time::Duration;

/// Parse a human-friendly duration like `2d`, `48h`, `30m`, `45s`, or
/// a bare integer (interpreted as days). Returns the parsed duration.
pub fn parse_threshold(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("threshold cannot be empty".to_string());
    }

    let (num_str, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase())
        }
        _ => (s, 'd'),
    };

    let value: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid threshold number: '{}'", num_str))?;

    if value < 0.0 || !value.is_finite() {
        return Err(format!(
            "threshold must be a non-negative finite number: '{}'",
            input
        ));
    }

    let secs = match unit {
        's' => value,
        'm' => value * 60.0,
        'h' => value * 3600.0,
        'd' => value * 86400.0,
        'w' => value * 7.0 * 86400.0,
        other => {
            return Err(format!(
                "unknown threshold unit '{}'. Use s, m, h, d, or w.",
                other
            ))
        }
    };

    let d = Duration::try_from_secs_f64(secs).map_err(|_| "threshold too large".to_string())?;
    // Establish the invariant every consumer relies on: the threshold
    // must also fit in a `chrono::Duration` (see precheck's from_std).
    chrono::Duration::from_std(d).map_err(|_| "threshold too large".to_string())?;
    Ok(d)
}

/// Format a Duration as a short human-readable string (e.g. `1d 4h`).
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs < 60 {
        return format!("{}s", total_secs);
    }
    let mins = total_secs / 60;
    if mins < 60 {
        return format!("{}m", mins);
    }
    let hours = total_secs / 3600;
    let rem_mins = (total_secs % 3600) / 60;
    if hours < 24 {
        if rem_mins == 0 {
            return format!("{}h", hours);
        }
        return format!("{}h {}m", hours, rem_mins);
    }
    let days = total_secs / 86400;
    let rem_hours = (total_secs % 86400) / 3600;
    if rem_hours == 0 {
        format!("{}d", days)
    } else {
        format!("{}d {}h", days, rem_hours)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_threshold_units() {
        assert_eq!(
            parse_threshold("2d").unwrap(),
            Duration::from_secs(2 * 86400)
        );
        assert_eq!(
            parse_threshold("48h").unwrap(),
            Duration::from_secs(48 * 3600)
        );
        assert_eq!(
            parse_threshold("30m").unwrap(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(parse_threshold("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_threshold("1w").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(
            parse_threshold("3").unwrap(),
            Duration::from_secs(3 * 86400)
        );
        assert_eq!(parse_threshold("0.5d").unwrap(), Duration::from_secs(43200));
    }

    #[test]
    fn parse_threshold_rejects_garbage() {
        assert!(parse_threshold("").is_err());
        assert!(parse_threshold("abc").is_err());
        assert!(parse_threshold("-1d").is_err());
        assert!(parse_threshold("1y").is_err());
    }

    #[test]
    fn parse_threshold_rejects_absurdly_large_values() {
        // Too large for chrono::Duration (precheck converts via from_std).
        assert!(parse_threshold("999999999999d").is_err());
        // Too large even for std::time::Duration.
        assert!(parse_threshold("1e308d").is_err());
    }

    #[test]
    fn format_duration_short() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h 1m");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1d 1h");
    }
}
