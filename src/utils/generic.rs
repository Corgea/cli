use crate::utils::terminal::{set_text_color, TerminalColor};
use git2::Repository;
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
];

/// Create a zip file from a target specification or full repository scan.
///
/// - If `target` is `None`, performs a full repository scan (equivalent to scanning all files).
/// - If `target` is `Some(target_str)`, resolves the target using the targets module and creates zip from those files.
///   The target string can be a comma-separated list of files, directories, globs, or git selectors.
/// - `user_exclude` is an optional comma-separated list of glob patterns from `--exclude`.
pub fn create_zip_from_target<P: AsRef<Path>>(
    target: Option<&str>,
    output_zip: P,
    exclude_globs: Option<&[&str]>,
    user_exclude: Option<&str>,
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
        let is_excluded = glob_set.is_match(&path);

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

/// Extract the `org/repo` slug from a git remote URL. Returns the last two
/// meaningful path segments so it is a substring of essentially every stored
/// (normalized) `repo_url` form. Distinct from `extract_repo_name_from_url`,
/// which returns only the final segment (`repo`).
///
/// Handles:
///   https://github.com/org/repo(.git)            -> org/repo
///   git@github.com:org/repo(.git)                -> org/repo
///   ssh://git@github.com/org/repo                -> org/repo
///   https://dev.azure.com/org/project/_git/repo  -> project/_git/repo
///
/// Azure `_git` is kept (and the preceding project segment included) because
/// doghouse `normalize_repo_url` stores Azure as `.../project/_git/repo`
/// (`heeler/models.py:208-212`) — `project/_git/repo` is a substring of that,
/// `project/repo` is NOT. Azure SSH remotes (`ssh.dev.azure.com/v3/...`, which
/// carry no `_git` segment) are a known limitation; users pass --project-name.
///
/// Returns None when fewer than two path segments follow the host (a bare host
/// or garbage input).
pub fn extract_repo_slug(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    // Drop scheme (`https://`, `ssh://`, …) if present.
    let url = url.rsplit("://").next().unwrap_or(url);
    // Split host from path: URL forms use '/', scp-like `git@host:org/repo`
    // uses ':'. After filtering empties, segments[0] is the host.
    let segments: Vec<&str> = url.split(['/', ':']).filter(|s| !s.is_empty()).collect();
    if segments.len() < 3 {
        return None; // need host + at least org + repo
    }
    let last = segments[segments.len() - 1];
    let prev = segments[segments.len() - 2];
    if prev == "_git" && segments.len() >= 4 {
        // Azure DevOps: keep the project so the slug stays a substring of the
        // normalized stored URL (.../project/_git/repo).
        let project = segments[segments.len() - 3];
        Some(format!("{}/_git/{}", project, last))
    } else {
        Some(format!("{}/{}", prev, last))
    }
}

pub fn get_env_var_if_exists(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

pub fn get_repo_info(dir: &str) -> Result<Option<RepoInfo>, git2::Error> {
    let repo = match Repository::open(Path::new(dir)) {
        Ok(repo) => repo,
        Err(_) => return Ok(None),
    };

    let branch = repo.head().ok().and_then(|head| {
        if head.is_branch() {
            head.shorthand().map(|s| s.to_string())
        } else {
            None
        }
    });

    // Get the latest commit SHA
    let sha = repo.head().ok().and_then(|head| {
        head.peel_to_commit()
            .ok()
            .map(|commit| commit.id().to_string())
    });

    // Get the remote URL (assuming "origin")
    let repo_url = repo
        .find_remote("origin")
        .ok()
        .and_then(|remote| remote.url().map(|url| url.to_string()));

    Ok(Some(RepoInfo {
        branch,
        repo_url,
        sha,
    }))
}

/// Find the enclosing repository's `origin` remote URL, searching upward from
/// the current directory so `corgea list`/`wait` resolve correctly when run
/// from a subdirectory, not only the repo root. `get_repo_info` uses
/// `Repository::open`, which succeeds only at the root; this uses
/// `Repository::discover`. Returns None outside a git repo or when `origin`
/// carries no URL.
pub fn discover_repo_url() -> Option<String> {
    let repo = Repository::discover(Path::new(".")).ok()?;
    repo.find_remote("origin")
        .ok()
        .and_then(|remote| remote.url().map(|url| url.to_string()))
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

#[derive(Debug)]
pub struct RepoInfo {
    pub branch: Option<String>,
    pub repo_url: Option<String>,
    pub sha: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let added = create_zip_from_target(Some(&target), &output_zip, Some(excludes), None)
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

    #[test]
    fn extract_repo_slug_handles_common_remote_forms() {
        assert_eq!(
            extract_repo_slug("https://github.com/org/repo.git").as_deref(),
            Some("org/repo")
        );
        assert_eq!(
            extract_repo_slug("https://github.com/org/repo").as_deref(),
            Some("org/repo")
        );
        assert_eq!(
            extract_repo_slug("git@github.com:org/repo.git").as_deref(),
            Some("org/repo")
        );
        assert_eq!(
            extract_repo_slug("git@github.com:org/repo").as_deref(),
            Some("org/repo")
        );
        assert_eq!(
            extract_repo_slug("ssh://git@github.com/org/repo").as_deref(),
            Some("org/repo")
        );
        assert_eq!(
            extract_repo_slug("https://github.com/org/repo/").as_deref(),
            Some("org/repo")
        );
        // host:port should not leak the port into the slug
        assert_eq!(
            extract_repo_slug("https://git.example.com:8443/org/repo").as_deref(),
            Some("org/repo")
        );
        // Bank of Hope case
        assert_eq!(
            extract_repo_slug("git@github.com:bohappdev/dotnet-azure-web-tsb.git").as_deref(),
            Some("bohappdev/dotnet-azure-web-tsb")
        );
        // Azure DevOps `_git` HTTPS -> keeps project + _git so it stays a substring
        // of the normalized stored URL.
        assert_eq!(
            extract_repo_slug("https://dev.azure.com/org/project/_git/repo").as_deref(),
            Some("project/_git/repo")
        );
    }

    #[test]
    fn extract_repo_slug_returns_none_for_unsplittable_input() {
        assert_eq!(extract_repo_slug("not a url"), None);
        assert_eq!(extract_repo_slug(""), None);
        assert_eq!(extract_repo_slug("github.com"), None); // host only
    }
}
