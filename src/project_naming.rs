use crate::utils::generic;
use clap::ValueEnum;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The SEAL pipeline template cuts derived names at this length, so the CLI
/// does too: a longer name would not match the projects the template created.
const MAX_DERIVED_NAME_CHARS: usize = 100;

/// Ways to derive the Corgea project name, picked with `--project-naming-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProjectNamingMode {
    /// The default project name followed by the folders of a sparse checkout.
    SparsePostfixed,
}

/// The project name a command runs against: `--project-name` as given, else
/// the name `--project-naming-mode` derives. None leaves the command to its
/// regular resolution, as when neither flag is passed.
pub fn resolve(project_name: Option<String>, mode: Option<ProjectNamingMode>) -> Option<String> {
    project_name.or_else(|| mode.and_then(name_from_mode))
}

/// The name `mode` derives, or None when the mode does not apply to this
/// checkout.
fn name_from_mode(mode: ProjectNamingMode) -> Option<String> {
    match mode {
        ProjectNamingMode::SparsePostfixed => resolve_sparse_postfixed_name(),
    }
}

/// `<default project name>-<sparse folders>`, e.g. `monorepo-jsoar-agent`, so
/// every service cloned from a monorepo with a sparse checkout lands in its own
/// project.
fn resolve_sparse_postfixed_name() -> Option<String> {
    let folders = match sparse_checkout_folders(Path::new(".")) {
        Ok(folders) => folders,
        Err(reason) => {
            log::warn!(
                "--project-naming-mode=sparse-postfixed: {reason}, so the default project name is used."
            );
            return None;
        }
    };
    let base = generic::determine_project_name(None);
    let name = postfixed_name(&base, &folders);
    log::info!(
        "Corgea project: {name} (default name '{base}' plus sparse checkout folders: {})",
        folders.join(", ")
    );
    Some(name)
}

/// The top-level folders `dir`'s sparse checkout keeps, or why there are none.
/// Only a worktree root qualifies: the default name and git context are
/// resolved there, and nowhere else.
fn sparse_checkout_folders(dir: &Path) -> Result<Vec<String>, String> {
    if !dir.to_str().is_some_and(generic::is_at_repo_root) {
        return Err("the current directory is not the root of a git repository".into());
    }
    // `git sparse-checkout` writes this to `config.worktree`, so it is asked of
    // git rather than read from `.git/config`.
    let enabled = git_stdout(
        dir,
        &[
            "config",
            "--bool",
            "--default",
            "false",
            "core.sparseCheckout",
        ],
    )
    .ok_or("git could not report whether this is a sparse checkout")?;
    if enabled.trim() != "true" {
        return Err("this checkout is not a sparse checkout".into());
    }
    let mut patterns = git_stdout(dir, &["sparse-checkout", "list"]).unwrap_or_default();
    // `sparse-checkout list` needs git 2.25; older git only has the file.
    if patterns.trim().is_empty() {
        patterns = git_stdout(dir, &["rev-parse", "--git-path", "info/sparse-checkout"])
            .and_then(|path| std::fs::read_to_string(dir.join(path.trim())).ok())
            .unwrap_or_default();
    }
    let folders = top_level_folders(&patterns);
    if folders.is_empty() {
        return Err(
            "sparse checkout is on, but no folder could be derived from its patterns".into(),
        );
    }
    Ok(folders)
}

/// The first path segment of every pattern that names one, de-duplicated in
/// byte order. Follows the SEAL pipeline template step for step so both derive
/// the same name for a checkout: comments, negations and root-only patterns
/// (`/*`, `*.md`) name no folder, and `services/payments` reduces to
/// `services`.
fn top_level_folders(patterns: &str) -> Vec<String> {
    let folders: BTreeSet<String> = patterns
        .lines()
        .filter_map(|line| {
            // Some pipelines write each pattern with a literal `\n` after it.
            let line = line.strip_suffix("\\n").unwrap_or(line);
            let line = line.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                return None;
            }
            let path = line.strip_prefix('/').unwrap_or(line);
            let folder = path.split('/').next().unwrap_or_default();
            (!folder.is_empty() && !folder.starts_with('*')).then(|| folder.to_string())
        })
        .collect();
    folders.into_iter().collect()
}

/// `base`, a dash, then the folders joined with dots. The folders get the
/// template's byte-wise character rule, so a non-ASCII byte becomes `_`.
fn postfixed_name(base: &str, folders: &[String]) -> String {
    let suffix: String = folders
        .join(".")
        .bytes()
        .map(|b| match b {
            b',' => '.',
            b'.' | b'_' | b'-' => b as char,
            b if b.is_ascii_alphanumeric() => b as char,
            _ => '_',
        })
        .collect();
    format!("{base}-{suffix}")
        .chars()
        .take(MAX_DERIVED_NAME_CHARS)
        .collect()
}

/// Stdout of a successful `git` run in `dir`, or None when git is missing or
/// the command failed.
fn git_stdout(dir: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    for var in generic::GIT_LOCAL_ENV_VARS {
        command.env_remove(var);
    }
    let output = command.args(args).current_dir(dir).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn git(root: &Path, args: &[&str]) {
        let mut cmd = Command::new("git");
        for (name, _) in std::env::vars() {
            if name.starts_with("GIT_") {
                cmd.env_remove(name);
            }
        }
        assert!(
            cmd.args(args).current_dir(root).status().unwrap().success(),
            "git {args:?} failed"
        );
    }

    /// A committed repo holding one file in each of `dirs`, plus a root file.
    fn monorepo(dirs: &[&str]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        git(root, &["init", "-q"]);
        for dir in dirs {
            fs::create_dir_all(root.join(dir)).unwrap();
            fs::write(root.join(dir).join("f.txt"), "x").unwrap();
        }
        fs::write(root.join("root.txt"), "x").unwrap();
        git(root, &["add", "-A"]);
        git(
            root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "init",
            ],
        );
        tmp
    }

    fn folders(patterns: &str) -> Vec<String> {
        top_level_folders(patterns)
    }

    #[test]
    fn cone_entries_reduce_to_their_top_level_folder() {
        assert_eq!(folders("jsoar-agent"), ["jsoar-agent"]);
        assert_eq!(folders("services/payments"), ["services"]);
        assert_eq!(folders("services/payments\nservices/ledger"), ["services"]);
        assert_eq!(folders("jsoar-agent\ncommon"), ["common", "jsoar-agent"]);
    }

    #[test]
    fn non_cone_patterns_keep_only_folder_names() {
        assert_eq!(
            folders("/services/payments/\n*.md\n!/services/payments/tests/\n# note\n\n"),
            ["services"]
        );
        assert_eq!(folders("/api/**\n/web/*\n/docs/"), ["api", "docs", "web"]);
    }

    #[test]
    fn the_cone_mode_root_patterns_name_no_folder() {
        assert!(folders("/*\n!/*/").is_empty());
    }

    #[test]
    fn a_trailing_literal_newline_escape_is_dropped_but_inner_ones_are_kept() {
        assert_eq!(folders("jsoar-agent\\n"), ["jsoar-agent"]);
        assert_eq!(folders("jsoar-agent\\ncommon\\n"), ["jsoar-agent\\ncommon"]);
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            folders("  jsoar-agent \r\n\tcommon\t"),
            ["common", "jsoar-agent"]
        );
    }

    #[test]
    fn postfixed_name_joins_folders_with_dots() {
        let name = |f: &[&str]| {
            postfixed_name(
                "monorepo",
                &f.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(name(&["jsoar-agent"]), "monorepo-jsoar-agent");
        assert_eq!(
            name(&["common", "jsoar-agent"]),
            "monorepo-common.jsoar-agent"
        );
    }

    #[test]
    fn postfixed_name_applies_the_template_character_rule_to_folders() {
        let name = |f: &str| postfixed_name("monorepo", &[f.to_string()]);
        assert_eq!(name("my svc"), "monorepo-my_svc");
        assert_eq!(name("a,b"), "monorepo-a.b");
        assert_eq!(name("\"caf\\303\\251\""), "monorepo-_caf_303_251_");
        assert_eq!(name("café"), "monorepo-caf__");
    }

    #[test]
    fn postfixed_name_is_cut_at_the_template_length() {
        let name = postfixed_name("monorepo", &["x".repeat(200)]);
        assert_eq!(name.chars().count(), MAX_DERIVED_NAME_CHARS);
        assert!(name.starts_with("monorepo-xxx"));
    }

    #[test]
    fn sparse_cone_checkout_yields_its_top_level_folders() {
        let repo = monorepo(&["jsoar-agent", "common", "services/payments", "other"]);
        git(
            repo.path(),
            &[
                "sparse-checkout",
                "set",
                "--cone",
                "jsoar-agent",
                "services/payments",
            ],
        );
        assert_eq!(
            sparse_checkout_folders(repo.path()).unwrap(),
            ["jsoar-agent", "services"]
        );
    }

    #[test]
    fn a_full_checkout_is_not_sparse() {
        let repo = monorepo(&["jsoar-agent"]);
        let err = sparse_checkout_folders(repo.path()).unwrap_err();
        assert!(err.contains("not a sparse checkout"), "{err}");
    }

    #[test]
    fn a_sparse_checkout_of_only_root_files_names_no_folder() {
        let repo = monorepo(&["jsoar-agent"]);
        git(repo.path(), &["sparse-checkout", "set", "--cone"]);
        let err = sparse_checkout_folders(repo.path()).unwrap_err();
        assert!(err.contains("no folder could be derived"), "{err}");
    }

    #[test]
    fn a_subdirectory_of_a_sparse_checkout_does_not_qualify() {
        let repo = monorepo(&["jsoar-agent"]);
        git(
            repo.path(),
            &["sparse-checkout", "set", "--cone", "jsoar-agent"],
        );
        let err = sparse_checkout_folders(&repo.path().join("jsoar-agent")).unwrap_err();
        assert!(err.contains("not the root"), "{err}");
    }

    #[test]
    fn an_explicit_project_name_is_kept_without_consulting_the_mode() {
        assert_eq!(
            resolve(
                Some("mine".into()),
                Some(ProjectNamingMode::SparsePostfixed)
            ),
            Some("mine".into())
        );
        assert_eq!(resolve(None, None), None);
    }
}
