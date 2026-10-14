//! The project's ignore rules, matched the way the scanner matches them.
//!
//! A scan holds no findings for files its ignore rules matched. When the
//! project lifts one of those rules, an incremental run has to analyze the
//! files it hid, or their findings never appear. Which files those are depends
//! on how a pattern is read, so this mirrors fusion's `ignore_path_matches`
//! exactly: a pattern containing `*`, `?` or `[`, or starting with `**/`, is
//! a Python `fnmatch` glob, where `*` also crosses `/` and a leading `**/` also
//! matches at the root. Anything else is a plain prefix. Doghouse drops
//! findings with the same globs and matches a plain pattern only as the whole
//! path, so whatever it would drop, this matches too.

use regex::Regex;

const GLOB_CHARS: [char; 3] = ['*', '?', '['];

pub struct IgnoreMatcher {
    rules: Vec<Rule>,
}

enum Rule {
    Prefix(String),
    Glob(Regex),
    /// A `**/` pattern: the rest of it, matched against the path and against
    /// every tail of it that follows a `/`.
    AnyTail(Regex),
}

impl IgnoreMatcher {
    /// Fails rather than skipping a pattern it cannot compile. Skipping would
    /// understate what the old rules hid, or overstate what the new ones still
    /// hide, and either way files would go unscanned.
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        let mut rules = Vec::new();
        for pattern in patterns.iter().filter(|pattern| !pattern.is_empty()) {
            let rule = if let Some(suffix) = pattern.strip_prefix("**/") {
                Rule::AnyTail(compile(suffix, pattern)?)
            } else if pattern.contains(GLOB_CHARS) {
                Rule::Glob(compile(pattern, pattern)?)
            } else {
                Rule::Prefix(pattern.clone())
            };
            rules.push(rule);
        }
        Ok(Self { rules })
    }

    pub fn is_match(&self, path: &str) -> bool {
        self.rules.iter().any(|rule| match rule {
            Rule::Prefix(prefix) => path.starts_with(prefix.as_str()),
            Rule::Glob(glob) => glob.is_match(path),
            Rule::AnyTail(glob) => std::iter::once(path)
                .chain(path.match_indices('/').map(|(at, _)| &path[at + 1..]))
                .any(|tail| glob.is_match(tail)),
        })
    }
}

/// Archived paths that a `lifted` rule matches and no `current` rule does: the
/// files the baseline has no findings for that this scan must analyze.
pub fn newly_unignored<'a>(
    paths: impl Iterator<Item = &'a str>,
    lifted: &[String],
    current: &[String],
) -> Result<Vec<String>, String> {
    let hidden_before = IgnoreMatcher::new(lifted)?;
    let hidden_now = IgnoreMatcher::new(current)?;
    Ok(paths
        .filter(|path| hidden_before.is_match(path) && !hidden_now.is_match(path))
        .map(str::to_string)
        .collect())
}

fn compile(glob: &str, pattern: &str) -> Result<Regex, String> {
    Regex::new(&fnmatch_regex(glob))
        .map_err(|e| format!("ignore rule '{pattern}' could not be read ({e})"))
}

/// Python's `fnmatch.translate`, for the regex crate. Case-sensitive, as
/// `fnmatch` is on the Linux hosts the scanner runs on.
fn fnmatch_regex(glob: &str) -> String {
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::from(r"(?s)\A(?:");
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        match c {
            '*' => {
                while chars.get(at) == Some(&'*') {
                    at += 1;
                }
                out.push_str(".*");
            }
            '?' => out.push('.'),
            '[' => match bracket(&chars, at) {
                Some((class, next)) => {
                    out.push_str(&class);
                    at = next;
                }
                // Unterminated, so fnmatch reads the `[` literally.
                None => out.push_str(r"\["),
            },
            _ => out.push_str(&escape(c)),
        }
    }
    out.push_str(r")\z");
    out
}

/// The class opened by the `[` just before `start`, and the index after its
/// `]`. `!` negates, a `]` first is literal, and a reversed range is empty.
fn bracket(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut end = start;
    if chars.get(end) == Some(&'!') {
        end += 1;
    }
    if chars.get(end) == Some(&']') {
        end += 1;
    }
    while end < chars.len() && chars[end] != ']' {
        end += 1;
    }
    if end >= chars.len() {
        return None;
    }
    let mut body = &chars[start..end];
    let negated = body.first() == Some(&'!');
    if negated {
        body = &body[1..];
    }
    let mut items = String::new();
    let mut at = 0;
    while at < body.len() {
        if at + 2 < body.len() && body[at + 1] == '-' {
            let (low, high) = (body[at], body[at + 2]);
            if low <= high {
                items.push_str(&format!("{}-{}", escape(low), escape(high)));
            }
            at += 3;
        } else {
            items.push_str(&escape(body[at]));
            at += 1;
        }
    }
    let class = match (negated, items.is_empty()) {
        (false, true) => r"[^\x00-\x{10FFFF}]".to_string(),
        (true, true) => ".".to_string(),
        (false, false) => format!("[{items}]"),
        (true, false) => format!("[^{items}]"),
    };
    Some((class, end + 1))
}

fn escape(c: char) -> String {
    regex::escape(c.encode_utf8(&mut [0; 4]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, path: &str) -> bool {
        IgnoreMatcher::new(&[pattern.to_string()])
            .expect("compiles")
            .is_match(path)
    }

    #[test]
    fn globs_read_as_fnmatch_where_a_star_crosses_directories() {
        assert!(matches("*/*.js", "src/app.js"));
        assert!(matches("*/*.js", "src/deep/app.js"));
        assert!(!matches("*/*.js", "app.js"));
        assert!(matches("*.js", "src/app.js"));
        assert!(matches("src/?.py", "src/a.py"));
        assert!(!matches("src/?.py", "src/ab.py"));
        assert!(!matches("*.JS", "src/app.js"));
    }

    #[test]
    fn a_leading_double_star_also_matches_at_the_root() {
        assert!(matches("**/vendor/**", "vendor/lib/a.py"));
        assert!(matches("**/vendor/**", "app/vendor/lib/a.py"));
        assert!(matches("**/*.min.js", "bundle.min.js"));
        assert!(!matches("**/vendor/**", "vendored/a.py"));
    }

    #[test]
    fn a_plain_pattern_is_a_prefix_not_a_directory() {
        assert!(matches("vendor", "vendor/a.py"));
        assert!(matches("vendor", "vendorized.py"));
        assert!(!matches("vendor", "src/vendor/a.py"));
    }

    #[test]
    fn brackets_follow_fnmatch() {
        assert!(matches("src/[ab].py", "src/a.py"));
        assert!(!matches("src/[!ab].py", "src/a.py"));
        assert!(matches("src/[!ab].py", "src/c.py"));
        assert!(matches("src/[a-c].py", "src/b.py"));
        assert!(matches("src/[]].py", "src/].py"));
        assert!(matches("src/[-x].py", "src/-.py"));
        // Unterminated: the `[` is literal.
        assert!(matches("src/[a.py", "src/[a.py"));
        // A reversed range is empty and matches nothing.
        assert!(!matches("src/[z-a].py", "src/m.py"));
    }

    #[test]
    fn regex_syntax_in_a_pattern_is_literal() {
        assert!(matches("src/a+b.py", "src/a+b.py"));
        assert!(!matches("src/a+b.py", "src/aab.py"));
        assert!(matches("src/{a,b}.py", "src/{a,b}.py"));
        assert!(!matches("src/{a,b}.py", "src/a.py"));
        assert!(matches("src/[&~].py", "src/~.py"));
    }

    #[test]
    fn newly_unignored_lists_what_the_old_rules_hid_and_the_new_ones_do_not() {
        let paths = ["src/app.js", "src/x-ahmad.js", "src/app.py", "README.md"];

        let narrowed = newly_unignored(
            paths.into_iter(),
            &["*/*.js".to_string()],
            &["*/*-ahmad.js".to_string()],
        )
        .expect("compiles");
        assert_eq!(narrowed, vec!["src/app.js"]);

        let widened = newly_unignored(
            paths.into_iter(),
            &["*/*-ahmad.js".to_string()],
            &["*/*.js".to_string()],
        )
        .expect("compiles");
        assert!(widened.is_empty());
    }
}
