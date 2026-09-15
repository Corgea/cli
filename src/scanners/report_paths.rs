//! Match a third-party report's file paths to the files on this machine.
//!
//! A report's paths are relative to whatever directory the customer's scanner
//! ran from, which is not necessarily where `corgea upload` runs. When the two
//! disagree by a leading prefix -- the scanner ran above the directory the CLI
//! is invoked in, or it recorded build-agent paths such as
//! `C:/jenkins/workspace/<job>/src/App.java` -- every lookup misses and the
//! upload aborts on the first file even though every file is right there.
//!
//! [`find_report_path_prefix`] settles that prefix once per report by dropping
//! one directory at a time from the prefix the report's paths share, and
//! [`local_report_path`] applies it. This is a port of Fusion's
//! `fusion/util/report_paths.py`, which does the same for reports whose source
//! arrives as a zip.
//!
//! Only the file the CLI *reads* is rebased. The path a file is uploaded under
//! stays exactly as the report wrote it, because the engine matches the report
//! against that path and never sees the local working tree.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Report paths sampled when matching a report to the working tree. The offset
/// between the two is a property of the report as a whole, so a sample settles
/// it; a 50k-finding report should not cost a stat call per finding per
/// candidate prefix to reach the same answer.
const MAX_REPORT_PATHS_SAMPLED: usize = 200;

/// Max leading directories dropped from report paths. Report paths can be
/// absolute (a Windows Checkmarx path, a Fortify `SourceBasePath`), so the
/// search needs a ceiling.
const MAX_REPORT_PATH_PREFIX_DEPTH: usize = 12;

/// One report path in both the form the report wrote and the form that can be
/// joined onto the working tree.
struct Sampled {
    /// Exactly as the report wrote it, which is how the CLI resolves paths
    /// when no prefix is dropped.
    raw: String,
    /// Slash-normalized and relative, for joining onto the working tree.
    relative: String,
}

/// Report paths may be Windows-style or rooted at the scanner's base path.
fn normalize(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches('/').to_string()
}

/// Distinct report paths to settle the prefix from, capped.
///
/// Deduplicating before the cap means the cap counts distinct paths: a report
/// that records one finding per line of the same file would otherwise spend the
/// whole sample on a single path.
fn sample_paths(report_paths: &[String]) -> Vec<Sampled> {
    let mut sample = Vec::new();
    let mut seen = HashSet::new();

    for raw in report_paths {
        if sample.len() >= MAX_REPORT_PATHS_SAMPLED {
            break;
        }
        let relative = normalize(raw);
        // A `..` segment cannot be resolved against the working tree without
        // leaving it, and a prefix derived from one would rebase the whole
        // report onto somewhere outside the project.
        if relative.is_empty() || relative.split('/').any(|segment| segment == "..") {
            continue;
        }
        if seen.insert(relative.clone()) {
            sample.push(Sampled {
                raw: raw.clone(),
                relative,
            });
        }
    }

    sample
}

/// The leading directories of `path`, dropping its file name.
fn leading_dirs(path: &str) -> Vec<&str> {
    let mut dirs: Vec<&str> = path.split('/').collect();
    dirs.pop();
    dirs
}

/// Leading directories every path agrees on.
///
/// Candidate prefixes are built from these, so one path's coincidental suffix
/// can never define the offset for the whole report.
fn shared_dirs<'a>(paths: &[&'a str]) -> Vec<&'a str> {
    let mut shared = match paths.first() {
        Some(first) => leading_dirs(first),
        None => return Vec::new(),
    };

    for path in &paths[1..] {
        let dirs = leading_dirs(path);
        let agreed = shared
            .iter()
            .zip(dirs.iter())
            .take_while(|(shared_dir, dir)| shared_dir == dir)
            .count();
        shared.truncate(agreed);
    }

    shared
}

/// Return the leading prefix to drop from a report's paths, or `""`.
///
/// Returns `""` as soon as any sampled path resolves as written, so a report
/// that already matches this working tree is left alone. Otherwise one
/// directory at a time is dropped from the shared prefix, shallowest first, and
/// the first prefix whose remainder resolves under `root` wins.
pub fn find_report_path_prefix(root: &Path, report_paths: &[String]) -> String {
    let sample = sample_paths(report_paths);

    if sample.is_empty() {
        return String::new();
    }

    // The path as the report wrote it is checked alongside the relativized
    // form, not just the latter: a report generated on this machine can carry
    // an absolute path that resolves, and dropping a prefix from it would read
    // a same-named file out of the working tree instead of the file the finding
    // is about.
    if sample
        .iter()
        .any(|path| root.join(&path.relative).is_file() || Path::new(&path.raw).is_file())
    {
        return String::new();
    }

    let relatives: Vec<&str> = sample.iter().map(|path| path.relative.as_str()).collect();
    let shared = shared_dirs(&relatives);

    for depth in 1..=shared.len().min(MAX_REPORT_PATH_PREFIX_DEPTH) {
        let prefix = format!("{}/", shared[..depth].join("/"));
        let hits: Vec<&str> = relatives
            .iter()
            .filter_map(|path| path.strip_prefix(prefix.as_str()))
            .filter(|remainder| root.join(remainder).is_file())
            .collect();

        // A real offset resolves the report broadly. A lone hit that is also a
        // bare basename is more likely a same-named file elsewhere in the tree
        // than evidence of the prefix, and accepting it would upload one file's
        // contents for a finding about another.
        if hits.len() >= 2 || (hits.len() == 1 && hits[0].contains('/')) {
            log::warn!(
                "The report's paths are not relative to this directory. Dropping '{}' from them resolves {} of {} sampled path(s); uploading those files under the paths the report uses.",
                prefix,
                hits.len(),
                relatives.len()
            );
            return prefix;
        }
    }

    String::new()
}

/// Rebase one report path onto this working tree.
pub fn strip_report_prefix(path: &str, prefix: &str) -> String {
    if prefix.is_empty() || path.is_empty() {
        return path.to_string();
    }

    let normalized = normalize(path);

    match normalized.strip_prefix(prefix) {
        Some(remainder) => remainder.to_string(),
        None => path.to_string(),
    }
}

/// Where to read a report's file from on this machine.
///
/// Without a prefix this is the path as the report wrote it, which is how the
/// CLI has always resolved it, so a report that already matches is untouched.
/// With one, the remainder is joined onto `root`; a `..` in it falls back to the
/// report's own path, because the prefix search only samples paths and an
/// unsampled one must not be able to walk out of the project.
pub fn local_report_path(root: &Path, report_path: &str, prefix: &str) -> PathBuf {
    let stripped = strip_report_prefix(report_path, prefix);

    if stripped == report_path || stripped.split('/').any(|segment| segment == "..") {
        return PathBuf::from(report_path);
    }

    root.join(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lay out a working tree and return it as a root.
    fn tree(root: &Path, paths: &[&str]) -> PathBuf {
        for path in paths {
            let full_path = root.join(path);
            std::fs::create_dir_all(full_path.parent().unwrap()).unwrap();
            std::fs::write(&full_path, "export const a = 1;").unwrap();
        }
        root.to_path_buf()
    }

    fn report(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| path.to_string()).collect()
    }

    #[test]
    fn no_prefix_when_paths_already_resolve() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["src/index.ts", "src/app.ts"]);

        assert_eq!(
            find_report_path_prefix(&root, &report(&["src/index.ts", "src/app.ts"])),
            ""
        );
    }

    /// The scan ran above the directory `corgea upload` runs in, so every
    /// report path is prefixed with that directory's own name.
    #[test]
    fn drops_the_directory_the_report_repeats() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(
            root.path(),
            &["proj (3)/src/index.ts", "proj (3)/src/app.ts"],
        );

        assert_eq!(
            find_report_path_prefix(
                &root,
                &report(&[
                    "Downloads/proj (3)/src/index.ts",
                    "Downloads/proj (3)/src/app.ts",
                ])
            ),
            "Downloads/"
        );
    }

    /// A Fortify SourceBasePath or an absolute Checkmarx path: none of the
    /// prefix's directories exist here, so it can only be dropped.
    #[test]
    fn drops_a_multi_segment_prefix_absent_from_the_working_tree() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["src/a.cs", "src/b.cs"]);

        assert_eq!(
            find_report_path_prefix(
                &root,
                &report(&["C:/build/proj/src/a.cs", "C:/build/proj/src/b.cs"])
            ),
            "C:/build/proj/"
        );
    }

    #[test]
    fn normalizes_windows_separators_before_searching() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["src/a.cs", "src/b.cs"]);

        assert_eq!(
            find_report_path_prefix(
                &root,
                &report(&["C:\\build\\proj\\src\\a.cs", "C:\\build\\proj\\src\\b.cs"])
            ),
            "C:/build/proj/"
        );
    }

    #[test]
    fn stops_at_the_shallowest_prefix_that_resolves() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["proj/src/a.ts", "proj/src/b.ts", "src/a.ts"]);

        assert_eq!(
            find_report_path_prefix(
                &root,
                &report(&["build/proj/src/a.ts", "build/proj/src/b.ts"])
            ),
            "build/"
        );
    }

    #[test]
    fn no_prefix_when_nothing_resolves() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["src/index.ts"]);

        for paths in [
            report(&["src/Gone.ts", "src/Missing.ts"]),
            report(&[]),
            report(&["", "/"]),
        ] {
            assert_eq!(find_report_path_prefix(&root, &paths), "");
        }
    }

    #[test]
    fn traversal_paths_are_never_sampled() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "top-secret").unwrap();
        let root = tree(&root.path().join("repo"), &["src/index.ts"]);

        assert_eq!(
            find_report_path_prefix(
                &root,
                &report(&["../outside/secret.txt", "a/../../outside/secret.txt"])
            ),
            ""
        );
    }

    /// Every sampled path shares its whole directory chain, so the search can
    /// strip down to a basename. One hit on a same-named file elsewhere in the
    /// tree is not evidence of the prefix, and taking it would upload that
    /// file's contents for a finding about another file.
    #[test]
    fn lone_bare_basename_match_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["index.ts"]);

        assert_eq!(
            find_report_path_prefix(&root, &report(&["src/utils/index.ts", "src/utils/x.ts"])),
            ""
        );
    }

    #[test]
    fn bare_basename_accepted_when_corroborated() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["index.ts", "app.ts"]);

        assert_eq!(
            find_report_path_prefix(&root, &report(&["proj/src/index.ts", "proj/src/app.ts"])),
            "proj/src/"
        );
    }

    /// `proj` is shared but `src`/`lib` are not, so `proj/src/` is never tried
    /// even though it would resolve.
    #[test]
    fn prefix_never_exceeds_the_shared_directories() {
        let root = tempfile::tempdir().unwrap();
        let root = tree(root.path(), &["index.ts", "app.ts"]);

        assert_eq!(
            find_report_path_prefix(&root, &report(&["proj/src/index.ts", "proj/lib/app.ts"])),
            ""
        );
    }

    /// A report generated on this machine can name a file by an absolute path
    /// that resolves. Dropping a prefix from it would read a same-named file
    /// out of the working tree instead.
    #[test]
    fn absolute_paths_that_resolve_are_left_alone() {
        let scanned = tempfile::tempdir().unwrap();
        let scanned = tree(scanned.path(), &["src/a.ts", "src/b.ts"]);
        let cwd = tempfile::tempdir().unwrap();
        let cwd = tree(cwd.path(), &["src/a.ts", "src/b.ts"]);

        let paths = report(&[
            scanned.join("src/a.ts").to_str().unwrap(),
            scanned.join("src/b.ts").to_str().unwrap(),
        ]);

        assert_eq!(find_report_path_prefix(&cwd, &paths), "");
    }

    #[test]
    fn strip_report_prefix_rebases_only_matching_paths() {
        for (path, prefix, expected) in [
            ("Downloads/src/a.ts", "Downloads/", "src/a.ts"),
            ("/Downloads/src/a.ts", "Downloads/", "src/a.ts"),
            ("Downloads\\src\\a.ts", "Downloads/", "src/a.ts"),
            ("src/a.ts", "Downloads/", "src/a.ts"),
            ("Downloads/src/a.ts", "", "Downloads/src/a.ts"),
            ("", "Downloads/", ""),
        ] {
            assert_eq!(strip_report_prefix(path, prefix), expected);
        }
    }

    #[test]
    fn local_report_path_joins_the_remainder_onto_the_root() {
        let root = Path::new("/work/repo");

        assert_eq!(
            local_report_path(root, "Downloads/src/a.ts", "Downloads/"),
            PathBuf::from("/work/repo/src/a.ts")
        );
    }

    #[test]
    fn local_report_path_leaves_unprefixed_and_unmatched_paths_as_written() {
        let root = Path::new("/work/repo");

        // No prefix: resolved relative to the process directory, as always.
        assert_eq!(
            local_report_path(root, "src/a.ts", ""),
            PathBuf::from("src/a.ts")
        );
        // A path from another tree entirely keeps its own resolution rather
        // than being forced under the root.
        assert_eq!(
            local_report_path(root, "/opt/tool/lib/fs.d.ts", "Downloads/"),
            PathBuf::from("/opt/tool/lib/fs.d.ts")
        );
    }

    #[test]
    fn local_report_path_refuses_to_walk_out_of_the_root() {
        let root = Path::new("/work/repo");

        assert_eq!(
            local_report_path(root, "Downloads/../../etc/passwd", "Downloads/"),
            PathBuf::from("Downloads/../../etc/passwd")
        );
    }
}
