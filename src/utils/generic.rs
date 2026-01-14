use std::io;
use std::path::{Path, PathBuf};
use zip::{write::FileOptions, ZipWriter};
use ignore::{WalkBuilder, overrides::OverrideBuilder};
use globset::{GlobSetBuilder, Glob};
use std::fs::{self, File};
use std::env;
use git2::Repository;
use crate::utils::terminal::{set_text_color, TerminalColor};

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

// Patterns to include even if ignored by .gitignore
pub const OVERRIDE_INCLUDE_PATTERNS: &[&str] = &[
    "**/project.assets.json",
];

/// Create a zip file from a target specification or full repository scan.
/// 
/// - If `target` is `None`, performs a full repository scan (equivalent to scanning all files).
/// - If `target` is `Some(target_str)`, resolves the target using the targets module and creates zip from those files.
///   The target string can be a comma-separated list of files, directories, globs, or git selectors.
pub fn create_zip_from_target<P: AsRef<Path>>(
    target: Option<&str>,
    output_zip: P,
    exclude_globs: Option<&[&str]>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let exclude_globs = exclude_globs.unwrap_or(DEFAULT_EXCLUDE_GLOBS);

    let mut glob_builder = GlobSetBuilder::new();
    for &pattern in exclude_globs {
        glob_builder.add(Glob::new(pattern)?);
    }
    let glob_set = glob_builder.build()?;

    let files_to_zip: Vec<(PathBuf, PathBuf)> = if let Some(target_str) = target {
        let current_dir = env::current_dir()?;
        let result = crate::targets::resolve_targets(target_str)
            .map_err(|e| format!("Failed to resolve targets: {}", e))?;
        
        result.files
            .iter()
            .filter_map(|file| {
                if !file.exists() || !file.is_file() {
                    return None;
                }
                match file.strip_prefix(&current_dir) {
                    Ok(relative) => Some((file.clone(), relative.to_path_buf())),
                    Err(_) => {
                        Some((file.clone(), file.clone()))
                    }
                }
            })
            .collect()
    } else {
        let directory = Path::new(".");
        
        let mut override_builder = OverrideBuilder::new(directory);
        for pattern in OVERRIDE_INCLUDE_PATTERNS {
            override_builder.add(&format!("!{}", pattern))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to add override pattern: {}", e)))?;
        }
        let overrides = override_builder.build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to build overrides: {}", e)))?;
        
        let walker = WalkBuilder::new(directory)
            .standard_filters(true)
            .overrides(overrides)
            .build();

        let mut files = Vec::new();
        for result in walker {
            let entry = result?;
            let path = entry.path();

            if path.is_file() || path.is_dir() {
                let relative_path = path.strip_prefix(directory)?;
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
        eprintln!(
            "\n{}",
            set_text_color(
                "⚠️  Not everything in your target is scannable.",
                TerminalColor::Yellow
            )
        );
        eprintln!(
            "   {}",
            set_text_color(
                "We skipped files that typically aren't useful for analysis (like vendor/dependency code, test fixtures, style assets, and other non-source files).",
                TerminalColor::Yellow
            )
        );
        for excluded_file in &excluded_files {
            eprintln!(
                "   {} {}",
                set_text_color("•", TerminalColor::Yellow),
                excluded_file.display()
            );
        }
        eprintln!();
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
    env::current_dir()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().to_string()))
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
    
    if let Some(name) = url.split('/').last() {
        let name = name.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    
    if let Some(name) = url.split(':').last() {
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
    let sha = repo.head().ok().and_then(|head| head.peel_to_commit().ok().map(|commit| commit.id().to_string()));

    // Get the remote URL (assuming "origin")
    let repo_url = repo.find_remote("origin").ok().and_then(|remote| remote.url().map(|url| url.to_string()));

    Ok(Some(RepoInfo { branch, repo_url, sha }))
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

