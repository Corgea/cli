//! Force-include rules: files Corgea must scan even though it would skip them.
//!
//! Corgea leaves out vendored, third-party, test and generated code in two
//! places: this CLI's packaging filters (`DEFAULT_EXCLUDE_GLOBS`, `.gitignore`)
//! and the engine's own classification of what it extracted. When either gets
//! that call wrong for proprietary code, an include rule overrides it.
//!
//! Rules come from two places and are unioned: the project's rules on the
//! platform, fetched here before packaging, and `--include` on this command
//! line. Both matter locally — a file the packager leaves out of the zip cannot
//! be scanned whatever the engine later decides — and only the flag values
//! travel with the upload, since the platform already knows its own rules.

use crate::config::Config;
use crate::utils::api;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Ceiling on files one run may force into the archive. A rule like `**/*.js`
/// would otherwise pull an entire `node_modules` tree into the upload.
const MAX_FORCE_INCLUDED_FILES: usize = 5_000;

/// The force-include rules in effect for one scan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IncludeRules {
    /// Every pattern in effect: the project's rules plus `--include`.
    pub patterns: Vec<String>,
    /// Just the `--include` values, the ones the server does not know yet.
    pub cli_patterns: Vec<String>,
}

impl IncludeRules {
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Paths under `root` that the rules match, relative to `root`.
    ///
    /// Walks with the standard ignore filters off, since the point is to reach
    /// files `.gitignore` and the default excludes hide. `.git` is still
    /// skipped: it holds no source and its object store is large.
    pub fn matching_files(&self, root: &Path) -> Vec<PathBuf> {
        let Some(glob_set) = build_glob_set(&self.patterns) else {
            return Vec::new();
        };
        let mut matches = Vec::new();
        let walker = WalkBuilder::new(root)
            .standard_filters(false)
            .filter_entry(|entry| entry.file_name() != ".git")
            .build();
        for entry in walker.flatten() {
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let Ok(relative) = entry.path().strip_prefix(root) else {
                continue;
            };
            if glob_set.is_match(relative) {
                matches.push(relative.to_path_buf());
            }
            if matches.len() >= MAX_FORCE_INCLUDED_FILES {
                log::warn!(
                    "Include rules matched more than {} files; only the first {} are forced into this scan.",
                    MAX_FORCE_INCLUDED_FILES,
                    MAX_FORCE_INCLUDED_FILES
                );
                break;
            }
        }
        matches.sort();
        matches
    }
}

/// Build a matcher, dropping patterns globset cannot compile.
///
/// One unparseable pattern must not discard the rest: the others are still a
/// clear instruction, and silently scanning less than asked is the failure this
/// whole feature exists to fix.
fn build_glob_set(patterns: &[String]) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut usable = 0;
    for pattern in patterns {
        match Glob::new(pattern) {
            Ok(glob) => {
                builder.add(glob);
                usable += 1;
            }
            Err(e) => log::warn!("Ignoring include rule '{pattern}': {e}"),
        }
        // A bare path or directory prefix should match what is under it, which
        // is how the same pattern reads in the platform's ignore rules.
        if !pattern.contains('*') {
            let descendants = format!("{}/**", pattern.trim_end_matches('/'));
            if let Ok(glob) = Glob::new(&descendants) {
                builder.add(glob);
                usable += 1;
            }
        }
    }
    if usable == 0 {
        return None;
    }
    builder.build().ok()
}

/// Collect the rules for this run: the project's, plus `--include`.
///
/// A failed lookup is a warning, not a failure. It leaves the project's rules
/// unapplied for this run, which is the behavior every release before this one
/// had; refusing to scan would be worse.
pub fn resolve(
    config: &Config,
    project_name: &str,
    repo_url: Option<&str>,
    cli_include: &[String],
) -> IncludeRules {
    let cli_patterns = normalize_patterns(cli_include);
    let mut patterns = Vec::new();

    match api::query_scan_settings(&config.get_url(), project_name, repo_url) {
        Ok(Some(settings)) => {
            for pattern in normalize_patterns(&settings.include_paths) {
                push_unique(&mut patterns, pattern);
            }
            if !patterns.is_empty() {
                println!(
                    "Applying {} project include rule(s) from Corgea: {}.",
                    patterns.len(),
                    patterns.join(", ")
                );
            }
        }
        // A backend without the endpoint has no include rules to apply either.
        Ok(None) => {}
        Err(e) => log::warn!(
            "Could not read the project's include rules, so only --include applies to this run: {e}"
        ),
    }

    for pattern in &cli_patterns {
        push_unique(&mut patterns, pattern.clone());
    }
    IncludeRules {
        patterns,
        cli_patterns,
    }
}

fn normalize_patterns(patterns: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for pattern in patterns {
        let trimmed = pattern.trim();
        if !trimmed.is_empty() {
            push_unique(&mut normalized, trimmed.to_string());
        }
    }
    normalized
}

fn push_unique(patterns: &mut Vec<String>, pattern: String) {
    if !patterns.contains(&pattern) {
        patterns.push(pattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn rules(patterns: &[&str]) -> IncludeRules {
        IncludeRules {
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            cli_patterns: Vec::new(),
        }
    }

    fn write(root: &TempDir, relative: &str) {
        let path = root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "class A {}\n").unwrap();
    }

    #[test]
    fn normalize_trims_blanks_and_dedupes() {
        let input = ["a/**".to_string(), " a/** ".to_string(), "  ".to_string()];
        assert_eq!(normalize_patterns(&input), vec!["a/**".to_string()]);
    }

    #[test]
    fn no_patterns_matches_nothing() {
        let root = TempDir::new().unwrap();
        write(&root, "src/App.java");
        assert!(IncludeRules::default()
            .matching_files(root.path())
            .is_empty());
        assert!(build_glob_set(&[]).is_none());
    }

    #[test]
    fn unparseable_pattern_does_not_discard_the_others() {
        assert!(build_glob_set(&["src/**".to_string(), "[".to_string()]).is_some());
    }

    #[test]
    fn matching_files_reaches_gitignored_and_vendored_paths() {
        let root = TempDir::new().unwrap();
        write(&root, "vendor/mylib/Payments.java");
        write(&root, "vendor/other/Other.java");
        write(&root, "node_modules/pkg/index.js");
        write(&root, ".git/objects/blob");
        fs::write(root.path().join(".gitignore"), "vendor/\nnode_modules/\n").unwrap();

        let matched =
            rules(&["vendor/mylib", "node_modules/pkg/index.js"]).matching_files(root.path());

        assert_eq!(
            matched,
            vec![
                PathBuf::from("node_modules/pkg/index.js"),
                PathBuf::from("vendor/mylib/Payments.java"),
            ]
        );
    }
}
