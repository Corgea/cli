use crate::utils::terminal::{set_text_color, TerminalColor};
use git2::{IndexEntryExtendedFlag, IndexEntryFlag, Repository, StatusOptions};
use globset::{Glob, GlobSetBuilder};
use ignore::WalkBuilder;
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use zip::{write::FileOptions, ZipWriter};

// Global exclude globs used across multiple functions
const DEFAULT_EXCLUDE_GLOBS: &[&str] = &[
    "**/tests/**",
    "**/.corgea/**",
    "**/test/**",
    "**/spec/**",
    "**/specs/**",
    "**/node_modules/**",
    "**/tmp/**",
    "**/migrations/**",
    "**/python*/site-packages/**",
    "**/*.mmdb",
    "**/*.css",
    "**/*.less",
    "**/*.scss",
    "**/*.map",
    "**/*.env",
    "**/*.sh",
    "**/.vs/**",
    "**/.vscode/**",
    "**/.idea/**",
    // A copy of an exported image archive that lives in the repository would put
    // the backend into image-scanning mode on every scan, whether or not
    // `--include-image` was passed. Only the archives this run staged (passed as
    // `extra_files`) are meant to do that.
    "**/corgea-image-scanning-*.tar",
];

/// Create a zip file from a target specification or full repository scan.
///
/// - If `target` is `None`, performs a full repository scan (equivalent to scanning all files).
/// - If `target` is `Some(target_str)`, resolves the target using the targets module and creates zip from those files.
///   The target string can be a comma-separated list of files, directories, globs, or git selectors.
/// - `user_exclude` is an optional comma-separated list of glob patterns from `--exclude`.
/// - `extra_files` are staged files added to the root of the zip as
///   `(source path, zip entry name)`. They come from explicit flags such as
///   `--include-image`, so exclude rules don't apply to them.
pub fn create_zip_from_target<P: AsRef<Path>>(
    target: Option<&str>,
    output_zip: P,
    exclude_globs: Option<&[&str]>,
    user_exclude: Option<&str>,
    extra_files: &[(PathBuf, String)],
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let exclude_globs = exclude_globs.unwrap_or(DEFAULT_EXCLUDE_GLOBS);

    let mut glob_builder = GlobSetBuilder::new();
    for &pattern in exclude_globs {
        glob_builder.add(Glob::new(pattern)?);
    }
    let glob_set = glob_builder.build()?;

    let user_exclude_glob_set = crate::targets::build_user_exclude_glob_set(user_exclude)
        .map_err(|e| format!("Failed to build exclude patterns: {}", e))?;

    let files_to_zip: Vec<(PathBuf, PathBuf)> = if let Some(target_str) = target {
        let current_dir = env::current_dir()?;
        let result = crate::targets::resolve_targets_with_exclude(target_str, user_exclude)
            .map_err(|e| format!("Failed to resolve targets: {}", e))?;

        result
            .files
            .iter()
            .filter_map(|file| {
                if !file.exists() || !file.is_file() {
                    return None;
                }
                match file.strip_prefix(&current_dir) {
                    Ok(relative) => Some((file.clone(), relative.to_path_buf())),
                    Err(_) => Some((file.clone(), file.clone())),
                }
            })
            .collect()
    } else {
        let directory = Path::new(".");
        let walker = WalkBuilder::new(directory).standard_filters(true).build();

        let mut files = Vec::new();
        for result in walker {
            let entry = result?;
            let path = entry.path();

            if path.is_file() || path.is_dir() {
                let relative_path = path.strip_prefix(directory)?;
                if path.is_file()
                    && crate::targets::is_file_excluded(
                        relative_path,
                        Path::new(""),
                        &user_exclude_glob_set,
                    )
                {
                    continue;
                }
                files.push((path.to_path_buf(), relative_path.to_path_buf()));
            }
        }
        files
    };

    let zip_file = File::create(output_zip.as_ref())?;
    let mut zip = ZipWriter::new(zip_file);

    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut added_files = Vec::new();
    let mut excluded_files = Vec::new();

    for (path, relative_path) in files_to_zip {
        // Match repo-relative paths so abs `/tmp/...` targets don't hit `**/tmp/**`.
        let is_excluded = glob_set.is_match(&relative_path);

        if (path.is_file() || path.is_dir()) && !is_excluded {
            if path.is_file() {
                zip.start_file(relative_path.to_string_lossy(), options)?;
                let mut file = File::open(&path)?;
                io::copy(&mut file, &mut zip)?;
                added_files.push(path);
            } else if path.is_dir() {
                zip.add_directory(relative_path.to_string_lossy(), options)?;
            }
        } else if is_excluded && path.is_file() && target.is_some() {
            excluded_files.push(relative_path);
        }
    }

    // Exported container images routinely pass 4 GiB, which a zip entry can only
    // hold with ZIP64 headers; without `large_file` the writer aborts the entry.
    let large_file_options: FileOptions<()> = options.large_file(true);

    for (path, entry_name) in extra_files {
        zip.start_file(entry_name.as_str(), large_file_options)?;
        let mut file = File::open(path)?;
        io::copy(&mut file, &mut zip)?;
        added_files.push(path.clone());
    }

    // Print warnings for excluded files
    if !excluded_files.is_empty() {
        log::warn!(
            "\n{}",
            set_text_color(
                "⚠️  Not everything in your target is scannable.",
                TerminalColor::Yellow
            )
        );
        log::warn!(
            "   {}",
            set_text_color(
                "We skipped files that typically aren't useful for analysis (like vendor/dependency code, test fixtures, style assets, and other non-source files).",
                TerminalColor::Yellow
            )
        );
        for excluded_file in &excluded_files {
            log::warn!(
                "   {} {}",
                set_text_color("•", TerminalColor::Yellow),
                excluded_file.display()
            );
        }
        log::warn!("");
    }

    zip.finish()?;
    Ok(added_files)
}

/// Create a staging directory under the system temp directory, readable only by
/// its owner.
///
/// Staging holds the project zip and any exported container images, so other users
/// on a shared host must not be able to read it. `tempfile` creates directories
/// with default permissions — world-readable under a 0022 umask — so owner-only is
/// requested explicitly. The random name matters too: a fixed parent such as
/// `/tmp/corgea` can be pre-created, or pointed elsewhere by a symlink, by another
/// user first.
pub fn create_private_temp_dir(prefix: &str) -> io::Result<PathBuf> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }

    // Keep the path rather than the guard: callers end the process through
    // `std::process::exit`, which skips destructors, so cleanup stays explicit.
    Ok(builder.tempdir()?.keep())
}

pub fn create_path_if_not_exists<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return fs::create_dir_all(path);
    }
    Ok(())
}

pub fn is_git_repo(dir: &str) -> Result<bool, git2::Error> {
    let git_path = Path::new(dir).join(".git");
    if git_path.exists() {
        return Ok(true);
    }

    // Fall back to the more expensive discover method for cases like:
    // - We're in a subdirectory of a git repo
    // - .git is a file (worktrees, submodules)
    match Repository::discover(dir) {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.code() == git2::ErrorCode::NotFound {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

pub fn delete_directory<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    if path.exists() {
        return fs::remove_dir_all(path);
    }
    Ok(())
}

pub fn get_current_working_directory() -> Option<String> {
    env::current_dir().ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
    })
}

/// Determine the project name with fallback logic:
/// 1. Use provided project_name if given
/// 2. Try to get git repository name from remote URL
/// 3. Fall back to current directory name
pub fn determine_project_name(provided_name: Option<&str>) -> String {
    if let Some(name) = provided_name {
        return sanitize_filename(name);
    }

    if let Ok(Some(repo_info)) = get_repo_info("./") {
        if let Some(repo_url) = repo_info.repo_url {
            if let Some(name) = extract_repo_name_from_url(&repo_url) {
                return sanitize_filename(&name);
            }
        }
    }

    let dir_name = get_current_working_directory().unwrap_or_else(|| "unknown".to_string());
    sanitize_filename(&dir_name)
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn extract_repo_name_from_url(url: &str) -> Option<String> {
    // Handle various git URL formats:
    // - https://github.com/user/repo.git
    // - git@github.com:user/repo.git
    // - https://github.com/user/repo
    // - git@github.com:user/repo

    let url = url.trim();

    let url = url.strip_suffix(".git").unwrap_or(url);

    if let Some(name) = url.split('/').next_back() {
        let name = name.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    if let Some(name) = url.split(':').next_back() {
        let name = name.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

pub fn get_env_var_if_exists(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Repo identity at the worktree root. Does not sample dirty state — use
/// [`get_repo_info_for_scan`] for BLAST uploads.
pub fn get_repo_info(dir: &str) -> Result<Option<RepoInfo>, git2::Error> {
    get_repo_info_inner(dir, false)
}

/// [`get_repo_info`] plus dirty sampling for scan uploads.
pub fn get_repo_info_for_scan(dir: &str) -> Result<Option<RepoInfo>, git2::Error> {
    get_repo_info_inner(dir, true)
}

fn get_repo_info_inner(dir: &str, sample_dirty: bool) -> Result<Option<RepoInfo>, git2::Error> {
    // discover (not open) so worktrees / .git-as-file roots still resolve.
    let repo = match Repository::discover(Path::new(dir)) {
        Ok(repo) => repo,
        Err(e) if e.code() == git2::ErrorCode::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    // Default BLAST packaging walks `dir` (usually "."). Only attach
    // sha/branch/repo_url when that path is the worktree root — otherwise a
    // nested CWD would upload a partial zip labeled with the parent HEAD, and
    // determine_project_name would switch from CWD basename to the remote name.
    if !is_at_repo_root(dir) {
        return Ok(None);
    }

    let branch = repo.head().ok().and_then(|head| {
        if head.is_branch() {
            head.shorthand().ok().map(|s| s.to_string())
        } else {
            None
        }
    });

    let sha = repo.head().ok().and_then(|head| {
        head.peel_to_commit()
            .ok()
            .map(|commit| commit.id().to_string())
    });

    let (dirty, status_dirty) = if sample_dirty {
        worktree_dirty_flags(&repo)
    } else {
        (false, false)
    };

    Ok(Some(RepoInfo {
        branch,
        repo_url: origin_url(&repo),
        sha,
        dirty,
        status_dirty,
    }))
}

/// `(upload_dirty, status_dirty)`.
/// `upload_dirty`: status changes, dirty submodules, or assume-unchanged /
/// skip-worktree (status hides those). Errors fail closed to dirty.
/// `status_dirty`: non-empty `statuses()` only (user notice).
fn worktree_dirty_flags(repo: &Repository) -> (bool, bool) {
    let status_dirty = status_has_changes(repo);
    let upload_dirty = index_hides_worktree(repo) || status_dirty;
    (upload_dirty, status_dirty)
}

fn status_has_changes(repo: &Repository) -> bool {
    let mut opts = StatusOptions::new();
    // Submodules: packaging walks into them, so dirty checkouts must count.
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false);
    repo.statuses(Some(&mut opts))
        .map(|s| !s.is_empty())
        .unwrap_or(true)
}

/// assume-unchanged / skip-worktree are omitted from `statuses()`.
fn index_hides_worktree(repo: &Repository) -> bool {
    repo.index()
        .map(|index| {
            index.iter().any(|entry| {
                IndexEntryFlag::from_bits_truncate(entry.flags).is_valid()
                    || IndexEntryExtendedFlag::from_bits_truncate(entry.flags_extended)
                        .is_skip_worktree()
            })
        })
        .unwrap_or(true)
}

/// Merge before/after packaging samples. Clean only if both exist, both clean,
/// same SHA; otherwise dirty. Prefer post-packaging branch/url/sha.
pub fn reconcile_repo_info_for_upload(
    before: Option<RepoInfo>,
    after: Option<RepoInfo>,
) -> Option<RepoInfo> {
    match (before, after) {
        (None, None) => None,
        (Some(sample), None) | (None, Some(sample)) => Some(RepoInfo {
            dirty: true,
            ..sample
        }),
        (Some(before), Some(after)) => {
            let stable_clean =
                !before.dirty && !after.dirty && before.sha.is_some() && before.sha == after.sha;
            Some(RepoInfo {
                branch: after.branch.or(before.branch),
                repo_url: after.repo_url.or(before.repo_url),
                sha: after.sha.or(before.sha),
                dirty: !stable_clean,
                status_dirty: before.status_dirty || after.status_dirty,
            })
        }
    }
}

/// `origin`'s URL, or None when the remote is missing or carries no URL.
fn origin_url(repo: &Repository) -> Option<String> {
    repo.find_remote("origin")
        .ok()
        .and_then(|remote| remote.url().ok().map(|url| url.to_string()))
}

/// The enclosing repository's `origin` remote URL, searched upward from the
/// current directory so `corgea list`/`wait` also resolve from a subdirectory.
/// `get_repo_info` deliberately returns None outside the worktree root; this
/// does not. None outside a git repo or when `origin` carries no URL.
pub fn discover_repo_url() -> Option<String> {
    origin_url(&Repository::discover(Path::new(".")).ok()?)
}

/// The whole repository path after the host, lowercased (`org/repo`,
/// `group/subgroup/repo`, Azure `org/project/_git/repo`). The host is excluded
/// so SSH/HTTPS/port variants of one remote compare equal; None when the value
/// carries no host at all. The full path — not a trailing `org/repo` slug — is
/// what doghouse `normalize_repo_url` stores (`heeler/models.py:201-246`), so
/// it is what an equality compare needs. Azure SSH remotes
/// (`ssh.dev.azure.com/v3/org/…`, no `_git` segment) remain a known limitation.
pub fn extract_repo_path(url: &str) -> Option<String> {
    Some(split_remote(url)?[1..].join("/").to_lowercase())
}

/// The host of a git remote (`github.com`), lowercased and without userinfo or
/// port. None for a hostless value such as a bare `org/repo` — the same inputs
/// `extract_repo_path` rejects.
pub fn extract_repo_host(url: &str) -> Option<String> {
    Some(split_remote(url)?[0].to_lowercase())
}

/// Split a git remote into `[host, path segments…]`, dropping scheme, userinfo
/// and port. None when fewer than two path segments follow the host, or when
/// nothing marks the value as a network remote.
fn split_remote(url: &str) -> Option<Vec<&str>> {
    let url = url.trim().trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    let (had_scheme, url) = match url.split_once("://") {
        Some((_, rest)) => (true, rest),
        None => (false, url),
    };
    // Drop userinfo (`git@`, `oauth2:token@`) so it is never read as the host.
    let host_end = url.find('/').unwrap_or(url.len());
    let (had_userinfo, url) = match url[..host_end].rfind('@') {
        Some(at) => (true, &url[at + 1..]),
        None => (false, url),
    };
    // A colon before the first '/' is the scp-style `host:org/repo` separator.
    let first_slash = url.find('/').unwrap_or(url.len());
    let had_scp_colon = url[..first_slash].contains(':');
    // URL forms split host from path on '/', scp-like `git@host:org/repo` on ':'.
    let mut segments: Vec<&str> = url.split(['/', ':']).filter(|s| !s.is_empty()).collect();
    // segments[0] is the host; an all-digit segment right after it is a port.
    if segments.len() >= 4 && segments[1].chars().all(|c| c.is_ascii_digit()) {
        segments.remove(1);
    }
    // Need host + at least org + repo.
    if segments.len() < 3 {
        return None;
    }
    // A scheme, userinfo or scp colon is what marks a network remote. Without
    // one this is a bare path — a GitLab `group/subgroup/repo`, whose namespace
    // may itself contain dots — so every segment belongs to the path.
    if !had_scheme && !had_userinfo && !had_scp_colon {
        return None;
    }
    Some(segments)
}

/// True when `dir` is the repository worktree root (not a subdirectory).
fn is_at_repo_root(dir: &str) -> bool {
    let Ok(repo) = Repository::discover(Path::new(dir)) else {
        return false;
    };
    let Some(workdir) = repo.workdir() else {
        return false;
    };
    let Ok(workdir) = workdir.canonicalize() else {
        return false;
    };
    let Ok(cwd) = Path::new(dir).canonicalize() else {
        return false;
    };
    workdir == cwd
}

pub fn get_status(status: &str) -> &str {
    match status.to_lowercase().as_str() {
        "fix available" | "fix_available" => "Fix Available",
        "processing" => "Processing",
        "false positive" | "false_positive" => "False Positive",
        "on hold" | "on_hold" => "On Hold",
        "unsupported" => "Unsupported",
        "plan" => "Plan",
        "complete" => "Complete",
        "scanning" => "Scanning",
        "failed" => "Failed",
        _ => status,
    }
}

#[derive(Debug, Clone)]
pub struct RepoInfo {
    pub branch: Option<String>,
    pub repo_url: Option<String>,
    pub sha: Option<String>,
    /// Not an exact clean HEAD snapshot. Always false from [`get_repo_info`].
    pub dirty: bool,
    /// Non-empty git status (excludes index hide-bits). Drives user notice.
    pub status_dirty: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    // Git exports GIT_DIR/GIT_INDEX_FILE/etc. to hooks; scrub them so the
    // test's git subprocesses operate on the temp repo even when the test
    // suite itself runs inside a pre-commit hook.
    fn git(root: &std::path::Path, args: &[&str]) {
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

    #[test]
    fn get_repo_info_at_root_only_not_nested_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);

        let root_s = root.to_str().unwrap();
        let nested = root.join("pkg").join("inner");
        fs::create_dir_all(&nested).unwrap();
        let nested_s = nested.to_str().unwrap();

        let info = get_repo_info(root_s)
            .unwrap()
            .expect("repo root should yield SHA metadata");
        assert!(info.sha.is_some());
        assert!(is_at_repo_root(root_s));

        assert!(
            get_repo_info(nested_s).unwrap().is_none(),
            "nested CWD must not attach parent HEAD SHA / remote project name"
        );
        assert!(!is_at_repo_root(nested_s));
    }

    fn init_committed_repo(root: &std::path::Path) {
        git(root, &["init"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        fs::write(root.join("README"), "hi").unwrap();
        git(root, &["add", "README"]);
        git(root, &["commit", "-m", "init"]);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_true_when_tracked_file_modified() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        fs::write(root.join("README"), "changed").unwrap();
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(info.dirty);
        assert!(info.status_dirty);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_true_when_change_staged() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        fs::write(root.join("README"), "staged").unwrap();
        git(root, &["add", "README"]);
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(info.dirty);
        assert!(info.status_dirty);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_true_when_untracked_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        fs::write(root.join("new.py"), "print(1)").unwrap();
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(info.dirty);
        assert!(info.status_dirty);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_false_when_only_gitignored_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
        git(root, &["add", ".gitignore"]);
        git(root, &["commit", "-m", "ignore"]);
        fs::write(root.join("ignored.txt"), "secret").unwrap();
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(!info.dirty);
        assert!(!info.status_dirty);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_when_assume_unchanged_hides_edit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        fs::write(root.join("README"), "changed").unwrap();
        git(root, &["update-index", "--assume-unchanged", "README"]);
        // status clean; zip would still include the edit
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(info.dirty);
        assert!(!info.status_dirty);
    }

    #[test]
    fn get_repo_info_for_scan_dirty_when_skip_worktree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);
        git(root, &["update-index", "--skip-worktree", "README"]);
        let info = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(info.dirty);
        assert!(!info.status_dirty);
    }

    #[test]
    fn get_repo_info_skips_dirty_sampling() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_committed_repo(root);

        let clean = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(!clean.dirty);
        assert!(!clean.status_dirty);

        fs::write(root.join("README"), "changed").unwrap();
        let identity = get_repo_info(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(!identity.dirty);
        assert!(!identity.status_dirty);
        let scan = get_repo_info_for_scan(root.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(scan.dirty);
        assert!(scan.status_dirty);
    }

    fn sample_info(sha: &str, dirty: bool) -> RepoInfo {
        RepoInfo {
            branch: Some("main".into()),
            repo_url: Some("https://github.com/org/repo.git".into()),
            sha: Some(sha.into()),
            dirty,
            status_dirty: false,
        }
    }

    #[test]
    fn reconcile_clean_same_sha_stays_clean() {
        let before = sample_info("aaa", false);
        let after = sample_info("aaa", false);
        let out = reconcile_repo_info_for_upload(Some(before), Some(after)).unwrap();
        assert!(!out.dirty);
        assert_eq!(out.sha.as_deref(), Some("aaa"));
    }

    #[test]
    fn reconcile_sha_drift_marks_dirty() {
        let before = sample_info("aaa", false);
        let after = sample_info("bbb", false);
        let out = reconcile_repo_info_for_upload(Some(before), Some(after)).unwrap();
        assert!(out.dirty);
        assert_eq!(out.sha.as_deref(), Some("bbb"));
    }

    #[test]
    fn reconcile_either_dirty_marks_dirty() {
        let before = sample_info("aaa", true);
        let after = sample_info("aaa", false);
        let out = reconcile_repo_info_for_upload(Some(before), Some(after)).unwrap();
        assert!(out.dirty);

        let before = sample_info("aaa", false);
        let after = sample_info("aaa", true);
        let out = reconcile_repo_info_for_upload(Some(before), Some(after)).unwrap();
        assert!(out.dirty);
    }

    #[test]
    fn reconcile_missing_sample_marks_dirty() {
        let only = sample_info("aaa", false);
        assert!(
            reconcile_repo_info_for_upload(Some(only.clone()), None)
                .unwrap()
                .dirty
        );
        assert!(
            reconcile_repo_info_for_upload(None, Some(only))
                .unwrap()
                .dirty
        );
        assert!(reconcile_repo_info_for_upload(None, None).is_none());
    }

    #[test]
    fn get_repo_info_dirty_when_submodule_content_modified() {
        let parent_dir = tempfile::tempdir().unwrap();
        let parent = parent_dir.path();
        init_committed_repo(parent);

        // Submodule source outside parent so it isn't an untracked sibling.
        let sub_dir = tempfile::tempdir().unwrap();
        let sub_src = sub_dir.path();
        git(sub_src, &["init"]);
        git(sub_src, &["config", "user.email", "test@example.com"]);
        git(sub_src, &["config", "user.name", "Test"]);
        fs::write(sub_src.join("lib.py"), "v1\n").unwrap();
        git(sub_src, &["add", "lib.py"]);
        git(sub_src, &["commit", "-m", "sub init"]);

        git(
            parent,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                sub_src.to_str().unwrap(),
                "vendor",
            ],
        );
        git(parent, &["commit", "-m", "add submodule"]);

        let clean = get_repo_info_for_scan(parent.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(!clean.dirty, "committed submodule should be clean");

        fs::write(parent.join("vendor").join("lib.py"), "v2\n").unwrap();
        let dirty = get_repo_info_for_scan(parent.to_str().unwrap())
            .unwrap()
            .expect("repo info");
        assert!(
            dirty.dirty,
            "modified submodule checkout must mark parent dirty"
        );
    }

    #[test]
    fn create_zip_from_target_excludes_default_globs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // A file matched by DEFAULT_EXCLUDE_GLOBS (`**/node_modules/**`)...
        let node_modules = root.join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();
        let excluded = node_modules.join("x.js");
        fs::write(&excluded, "console.log(1)").unwrap();

        // ...alongside an ordinary source file that should be kept.
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let included = src_dir.join("main.py");
        fs::write(&included, "print(1)").unwrap();

        // Explicit, comma-separated file targets resolve to these exact paths,
        // so the test is independent of cwd and .gitignore.
        let output_zip = root.join("out.zip");
        let target = format!("{},{}", excluded.display(), included.display());

        // Scope the exclude globs explicitly to one real default
        // (`**/node_modules/**`): the system tempdir can itself live under a
        // path the full DEFAULT_EXCLUDE_GLOBS would match (e.g. `/tmp/**`),
        // which would exclude *everything*. The filter + warn path under test
        // is identical either way.
        let excludes: &[&str] = &["**/node_modules/**"];
        let added = create_zip_from_target(Some(&target), &output_zip, Some(excludes), None, &[])
            .expect("zip creation should succeed");

        assert!(
            added.iter().any(|p| p.ends_with("src/main.py")),
            "source file should be included: {:?}",
            added
        );
        assert!(
            !added.iter().any(|p| p.ends_with("node_modules/x.js")),
            "node_modules file should be excluded: {:?}",
            added
        );
    }

    /// The staging directory holds the project zip and exported images, so other
    /// local users must not be able to read it.
    #[cfg(unix)]
    #[test]
    fn create_private_temp_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = create_private_temp_dir("corgea-test-").expect("create staging dir");
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o700, "staging dir must be owner-only, got {mode:o}");
        let _ = delete_directory(&dir);
    }

    #[test]
    fn create_zip_from_target_adds_extra_files_at_the_zip_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let source = root.join("main.py");
        fs::write(&source, "print(1)").unwrap();

        let staged = root.join("staged").join("image.tar");
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::write(&staged, "image archive").unwrap();

        let output_zip = root.join("out.zip");
        let entry_name = "corgea-image-scanning-myapp-1.0.tar".to_string();
        let extra_files = vec![(staged.clone(), entry_name.clone())];
        let added = create_zip_from_target(
            Some(&source.display().to_string()),
            &output_zip,
            Some(&[]),
            None,
            &extra_files,
        )
        .expect("zip creation should succeed");

        assert!(added.contains(&staged), "staged archive should be added");

        let mut archive = zip::ZipArchive::new(File::open(&output_zip).unwrap()).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&entry_name), "zip entries: {:?}", names);
    }

    /// Exported images pass 4 GiB routinely, which a zip entry can only hold with
    /// ZIP64 headers. Reads a sparse 4 GiB file, so it is too slow for every run:
    /// `cargo test -- --ignored zip64`.
    #[test]
    #[ignore = "slow: writes and reads a sparse 4 GiB file"]
    fn create_zip_from_target_writes_extras_larger_than_four_gib() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let source = root.join("main.py");
        fs::write(&source, "print(1)").unwrap();

        // Sparse: set_len reserves the length without writing 4 GiB of blocks.
        let staged = root.join("huge.tar");
        File::create(&staged)
            .unwrap()
            .set_len(4 * 1024 * 1024 * 1024 + 1)
            .unwrap();

        let output_zip = root.join("out.zip");
        let extra_files = vec![(
            staged.clone(),
            "corgea-image-scanning-huge-1.0.tar".to_string(),
        )];
        let added = create_zip_from_target(
            Some(&source.display().to_string()),
            &output_zip,
            Some(&[]),
            None,
            &extra_files,
        )
        .expect("a >4 GiB entry needs ZIP64, not an error");

        assert!(added.contains(&staged));
    }

    #[test]
    fn default_exclude_globs_match_abs_tmp_but_not_repo_relative_paths() {
        // Abs `/tmp/...` hits `**/tmp/**`; repo-relative paths must not.
        let mut builder = GlobSetBuilder::new();
        for &pattern in DEFAULT_EXCLUDE_GLOBS {
            builder.add(Glob::new(pattern).unwrap());
        }
        let set = builder.build().unwrap();
        assert!(set.is_match(Path::new("/tmp/proj/app.py")));
        assert!(!set.is_match(Path::new("app.py")));
        assert!(!set.is_match(Path::new("src/app.py")));
    }

    #[test]
    fn extract_repo_path_handles_common_remote_forms() {
        for url in [
            "https://github.com/org/repo.git",
            "https://github.com/org/repo",
            "git@github.com:org/repo.git",
            "git@github.com:org/repo",
            "ssh://git@github.com/org/repo",
            "https://github.com/org/repo/",
            "https://github.com/Org/Repo",
            // host:port must not leak the port into the path
            "https://git.example.com:8443/org/repo",
            // token userinfo must not be read as the host
            "https://oauth2:tok@gitlab.com/org/repo",
        ] {
            assert_eq!(extract_repo_path(url).as_deref(), Some("org/repo"), "{url}");
        }
        // Bank of Hope case: the stored name is the whole org/repo path.
        assert_eq!(
            extract_repo_path("git@github.com:bohappdev/dotnet-azure-web-tsb.git").as_deref(),
            Some("bohappdev/dotnet-azure-web-tsb")
        );
        // Whole path is kept: Azure `_git` and GitLab subgroups.
        assert_eq!(
            extract_repo_path("https://dev.azure.com/org/project/_git/repo").as_deref(),
            Some("org/project/_git/repo")
        );
        assert_eq!(
            extract_repo_path("git@gitlab.com:group/subgroup/repo.git").as_deref(),
            Some("group/subgroup/repo")
        );
        // An SSH-config host alias carries no userinfo and no dot, but the
        // colon before the first slash still marks it scp-style.
        assert_eq!(
            extract_repo_path("corp-github:bohappdev/repo.git").as_deref(),
            Some("bohappdev/repo")
        );
    }

    #[test]
    fn extract_repo_path_returns_none_without_a_host() {
        assert_eq!(extract_repo_path("not a url"), None);
        assert_eq!(extract_repo_path(""), None);
        assert_eq!(extract_repo_path("github.com"), None); // host only
                                                           // Nothing marks these as a network remote, so they are bare paths the
                                                           // caller keeps verbatim; a GitLab namespace may contain dots, so a
                                                           // dotted leading segment is no evidence of a host.
        assert_eq!(extract_repo_path("org/repo"), None);
        assert_eq!(extract_repo_path("group/subgroup/repo"), None);
        assert_eq!(extract_repo_path("my.group/sub/repo"), None);
    }
}
