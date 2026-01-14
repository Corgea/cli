use std::collections::HashSet;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use globset::{Glob, GlobSetBuilder};
use ignore::{WalkBuilder, overrides::OverrideBuilder};
use git2::{Repository, StatusOptions, Delta};
use crate::utils::generic::OVERRIDE_INCLUDE_PATTERNS;

#[derive(Debug)]
pub struct TargetResolutionResult {
    pub files: Vec<PathBuf>,
    pub segments: Vec<TargetSegmentResult>,
}

#[derive(Debug)]
pub struct TargetSegmentResult {
    pub segment: String,
    pub matches: usize,
    pub error: Option<String>,
}

pub fn resolve_targets(target_value: &str) -> Result<TargetResolutionResult, String> {
    let segments: Vec<String> = target_value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if segments.is_empty() {
        return Err("Target value cannot be empty".to_string());
    }

    if segments.len() > 1 {
        for segment in &segments {
            if segment == "-" || segment == "-0" {
                return Err(format!(
                    "Stdin mode ('{}') cannot be combined with other targets. It must be the only segment.",
                    segment
                ));
            }
        }
    }

    let mut all_files = Vec::new();
    let mut seen_files = HashSet::new();
    let mut segment_results = Vec::new();

    let repo_root = find_repo_root()?;

    for segment in &segments {
        match resolve_segment(segment, &repo_root) {
            Ok(result) => {
                segment_results.push(TargetSegmentResult {
                    segment: segment.clone(),
                    matches: result.len(),
                    error: None,
                });

                for file in result {
                    match normalize_path(&file, &repo_root) {
                        Ok(normalized) => {
                            if seen_files.insert(normalized.clone()) {
                                all_files.push(normalized);
                            }
                        }
                        Err(e) => {
                            segment_results.push(TargetSegmentResult {
                                segment: segment.clone(),
                                matches: 0,
                                error: Some(format!("Failed to normalize path {}: {}", file.display(), e)),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                segment_results.push(TargetSegmentResult {
                    segment: segment.clone(),
                    matches: 0,
                    error: Some(e),
                });
            }
        }
    }

    let errors: Vec<_> = segment_results
        .iter()
        .filter_map(|r| r.error.as_ref().map(|e| format!("{}: {}", r.segment, e)))
        .collect();

    if !errors.is_empty() {
        return Err(format!(
            "Errors resolving targets:\n{}",
            errors.join("\n")
        ));
    }

    Ok(TargetResolutionResult {
        files: all_files,
        segments: segment_results,
    })
}

fn resolve_segment(segment: &str, repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    if segment == "-" {
        return read_stdin_files(false);
    }
    if segment == "-0" {
        return read_stdin_files(true);
    }

    if segment.starts_with("git:") {
        return resolve_git_selector(segment, repo_root);
    }

    let path = Path::new(segment);
    
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    };

    if !full_path.exists() {
        return resolve_glob(segment, repo_root);
    }

    if full_path.is_file() {
        Ok(vec![full_path])
    } else if full_path.is_dir() {
        resolve_directory(&full_path, repo_root)
    } else {
        resolve_glob(segment, repo_root)
    }
}

fn read_stdin_files(nul_delimited: bool) -> Result<Vec<PathBuf>, String> {
    let stdin = io::stdin();
    let mut files = Vec::new();
    let repo_root = find_repo_root()?;

    if nul_delimited {
        let mut buffer = Vec::new();
        stdin.lock().read_to_end(&mut buffer).map_err(|e| {
            format!("Failed to read from stdin: {}", e)
        })?;
        
        for part in buffer.split(|&b| b == 0) {
            if part.is_empty() {
                continue;
            }
            let path_str = String::from_utf8_lossy(part).trim().to_string();
            if !path_str.is_empty() {
                let path = Path::new(&path_str);
                let full_path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    repo_root.join(path)
                };
                if full_path.exists() && full_path.is_file() {
                    files.push(full_path);
                }
            }
        }
    } else {
        for line in stdin.lock().lines() {
            let line = line.map_err(|e| format!("Failed to read from stdin: {}", e))?;
            let path_str = line.trim();
            if path_str.is_empty() {
                continue;
            }
            let path = Path::new(path_str);
            let full_path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo_root.join(path)
            };
            if full_path.exists() && full_path.is_file() {
                files.push(full_path);
            }
        }
    }

    Ok(files)
}

fn resolve_git_selector(selector: &str, repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    if !is_git_repo(repo_root) {
        return Err(format!(
            "Git selector '{}' requires a git repository, but no git repository was found",
            selector
        ));
    }

    let files = if selector == "git:staged" {
        get_git_staged_files(repo_root)?
    } else if selector == "git:untracked" {
        get_git_untracked_files(repo_root)?
    } else if selector == "git:modified" {
        get_git_modified_files(repo_root)?
    } else if selector.starts_with("git:diff=") {
        let range = selector.strip_prefix("git:diff=").unwrap();
        get_git_diff_files(repo_root, range)?
    } else {
        return Err(format!("Invalid git selector: {}. Valid options are: git:staged, git:untracked, git:modified, git:diff=<range>", selector));
    };

    let mut result = Vec::new();
    for file in files {
        let full_path = repo_root.join(&file);
        if full_path.exists() && full_path.is_file() {
            result.push(full_path);
        }
    }

    Ok(result)
}

fn get_git_staged_files(repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let repo = Repository::open(repo_root)
        .map_err(|e| format!("Failed to open git repository: {}", e))?;

    let mut index = repo.index()
        .map_err(|e| format!("Failed to get index: {}", e))?;

    let head_tree = repo.head()
        .ok()
        .and_then(|head| head.peel_to_tree().ok());

    let index_tree_id = index.write_tree()
        .map_err(|e| format!("Failed to write index tree: {}", e))?;
    let index_tree = repo.find_tree(index_tree_id)
        .map_err(|e| format!("Failed to find index tree: {}", e))?;

    let diff = repo.diff_tree_to_tree(
        head_tree.as_ref(),
        Some(&index_tree),
        None
    ).map_err(|e| format!("Failed to create diff: {}", e))?;

    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta.new_file().path() {
                match delta.status() {
                    Delta::Added | Delta::Copied | Delta::Modified | Delta::Renamed => {
                        files.push(PathBuf::from(path));
                    }
                    _ => {}
                }
            }
            true
        },
        None,
        None,
        None,
    ).map_err(|e| format!("Failed to iterate diff: {}", e))?;

    Ok(files)
}

fn get_git_untracked_files(repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let repo = Repository::open(repo_root)
        .map_err(|e| format!("Failed to open git repository: {}", e))?;

    let mut opts = StatusOptions::new();
    opts.include_untracked(true);
    opts.exclude_submodules(true);
    opts.include_ignored(false);

    let statuses = repo.statuses(Some(&mut opts))
        .map_err(|e| format!("Failed to get statuses: {}", e))?;

    let mut files = Vec::new();
    for entry in statuses.iter() {
        let status = entry.status();
        if status.is_wt_new() && !status.is_ignored() {
            if let Some(path) = entry.path() {
                files.push(PathBuf::from(path));
            }
        }
    }

    Ok(files)
}

fn get_git_modified_files(repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let repo = Repository::open(repo_root)
        .map_err(|e| format!("Failed to open git repository: {}", e))?;

    let head_tree = repo.head()
        .ok()
        .and_then(|head| head.peel_to_tree().ok());

    let diff = repo.diff_tree_to_workdir(
        head_tree.as_ref(),
        None
    ).map_err(|e| format!("Failed to create diff: {}", e))?;

    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta.new_file().path() {
                match delta.status() {
                    Delta::Added | Delta::Copied | Delta::Modified | Delta::Renamed => {
                        files.push(PathBuf::from(path));
                    }
                    _ => {}
                }
            }
            true
        },
        None,
        None,
        None,
    ).map_err(|e| format!("Failed to iterate diff: {}", e))?;

    Ok(files)
}

fn get_git_diff_files(repo_root: &Path, range: &str) -> Result<Vec<PathBuf>, String> {
    let repo = Repository::open(repo_root)
        .map_err(|e| format!("Failed to open git repository: {}", e))?;

    let parts: Vec<&str> = range.split("...").collect();
    let (old_ref, new_ref) = if parts.len() == 2 {
        (parts[0].trim(), parts[1].trim())
    } else {
        let parts: Vec<&str> = range.split("..").collect();
        if parts.len() == 2 {
            (parts[0].trim(), parts[1].trim())
        } else {
            return Err(format!("Invalid diff range format: {}. Expected format: 'old..new' or 'old...new'", range));
        }
    };

    let old_commit = if old_ref.is_empty() {
        None
    } else {
        Some(repo.revparse_single(old_ref)
            .map_err(|e| format!("Failed to resolve reference '{}': {}", old_ref, e))?
            .id())
    };

    let new_commit = if new_ref.is_empty() {
        repo.head()
            .map_err(|e| format!("Failed to get HEAD: {}", e))?
            .target()
            .ok_or_else(|| format!("HEAD is not a direct reference"))?
    } else {
        repo.revparse_single(new_ref)
            .map_err(|e| format!("Failed to resolve reference '{}': {}", new_ref, e))?
            .id()
    };

    let old_tree = if let Some(old_id) = old_commit {
        Some(repo.find_commit(old_id)
            .map_err(|e| format!("Failed to find commit: {}", e))?
            .tree()
            .map_err(|e| format!("Failed to get tree: {}", e))?)
    } else {
        None
    };

    let new_tree = repo.find_commit(new_commit)
        .map_err(|e| format!("Failed to find commit: {}", e))?
        .tree()
        .map_err(|e| format!("Failed to get tree: {}", e))?;

    let diff = repo.diff_tree_to_tree(
        old_tree.as_ref(),
        Some(&new_tree),
        None
    ).map_err(|e| format!("Failed to create diff: {}", e))?;

    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta.new_file().path() {
                match delta.status() {
                    Delta::Added | Delta::Copied | Delta::Modified | Delta::Renamed => {
                        files.push(PathBuf::from(path));
                    }
                    _ => {}
                }
            }
            true
        },
        None,
        None,
        None,
    ).map_err(|e| format!("Failed to iterate diff: {}", e))?;

    Ok(files)
}

fn resolve_directory(dir: &Path, _repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    
    let walker = WalkBuilder::new(dir)
        .standard_filters(true)
        .build();

    for result in walker {
        let entry = result.map_err(|e| format!("Error walking directory: {}", e))?;
        let path = entry.path();
        
        if path.is_file() {
            files.push(path.to_path_buf());
        }
    }

    Ok(files)
}

fn resolve_glob(pattern: &str, repo_root: &Path) -> Result<Vec<PathBuf>, String> {
    let glob = Glob::new(pattern)
        .map_err(|e| format!("Invalid glob pattern '{}': {}", pattern, e))?;

    let mut glob_builder = GlobSetBuilder::new();
    glob_builder.add(glob);
    let glob_set = glob_builder.build()
        .map_err(|e| format!("Failed to build glob set: {}", e))?;

    let mut files = Vec::new();
    
    let mut override_builder = OverrideBuilder::new(repo_root);
    for pattern in OVERRIDE_INCLUDE_PATTERNS {
        override_builder.add(&format!("!{}", pattern))
            .map_err(|e| format!("Failed to add override pattern: {}", e))?;
    }
    let overrides = override_builder.build()
        .map_err(|e| format!("Failed to build overrides: {}", e))?;
    
    let walker = WalkBuilder::new(repo_root)
        .standard_filters(true)
        .overrides(overrides)
        .build();

    for result in walker {
        let entry = result.map_err(|e| format!("Error walking directory: {}", e))?;
        let path = entry.path();
        
        if path.is_file() {
            // Get relative path from repo root
            if let Ok(relative) = path.strip_prefix(repo_root) {
                if glob_set.is_match(relative) {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    Ok(files)
}

fn normalize_path(path: &Path, _repo_root: &Path) -> Result<PathBuf, String> {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?
            .join(path)
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize path: {}", e))?
    };

    Ok(abs_path)
}

fn find_repo_root() -> Result<PathBuf, String> {
    let current_dir = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?;

    match Repository::discover(&current_dir) {
        Ok(repo) => {
            repo.workdir()
                .map(|p| p.to_path_buf())
                .or_else(|| repo.path().parent().map(|p| p.to_path_buf()))
                .ok_or_else(|| "Failed to determine repository root".to_string())
        }
        Err(_) => {
            Ok(current_dir)
        }
    }
}

fn is_git_repo(dir: &Path) -> bool {
    Repository::discover(dir).is_ok()
}

