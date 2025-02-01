use std::io;
use std::path::Path;
use zip::{write::FileOptions, ZipWriter};
use ignore::WalkBuilder;
use globset::{GlobSetBuilder, Glob};
use std::fs::{self, File};
use std::env;
use git2::Repository;

pub fn create_zip_from_filtered_files<P: AsRef<Path>>(
    directory: P,
    exclude_globs: Option<&[&str]>,
    output_zip: P,
) -> Result<(), Box<dyn std::error::Error>> {
let exclude_globs = exclude_globs.unwrap_or(&[
        "**/tests/**",
        "**/.corgea/**",
        "**/test/**",
        "**/spec/**",
        "**/specs/**",
        "**/node_modules/**",
        "**/tmp/**",
        "**/migrations/**",
        "**/python*/site-packages/**",
        "**/*.csv",
        "**/*.mmdb",
        "**/*.css",
        "**/*.less",
        "**/*.scss",
        "**/*.map",
        "**/*.env",
        "**/*.sh",
    ]);
    let directory = directory.as_ref();

    let mut glob_builder = GlobSetBuilder::new();
    for &pattern in exclude_globs {
        glob_builder.add(Glob::new(pattern)?);
    }
    let glob_set = glob_builder.build()?;

    let zip_file = File::create(output_zip.as_ref())?;
    let mut zip = ZipWriter::new(zip_file);

    let options:FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let walker = WalkBuilder::new(directory)
        .standard_filters(true)
        .build();

    for result in walker {
        let entry = result?;
        let path = entry.path();

        if path.is_file() && !glob_set.is_match(path) {
            let relative_path = path.strip_prefix(directory)?;
            zip.start_file(relative_path.to_string_lossy(), options)?;
            let mut file = File::open(path)?;
            io::copy(&mut file, &mut zip)?;
        } else if path.is_dir() && !glob_set.is_match(path) {
            let relative_path = path.strip_prefix(directory)?;
            zip.add_directory(relative_path.to_string_lossy(), options)?;
        }
    }

    zip.finish()?;
    Ok(())
}


pub fn create_path_if_not_exists<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return fs::create_dir_all(path);
    }
    Ok(())
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

