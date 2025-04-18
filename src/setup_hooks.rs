use crate::utils::terminal;

pub fn setup_pre_commit_hook() {
    println!("Setting up pre-commit hook...");

    // Check if we're in a git repo
    let git_dir = match std::fs::metadata(".git") {
        Ok(metadata) => {
            if metadata.is_dir() {
                ".git"
            } else {
                eprintln!("Error: .git exists but is not a directory");
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("Error: Not a git repository (or any of the parent directories)");
            std::process::exit(1);
        }
    };

    let hooks_dir = format!("{}/hooks", git_dir);
    let pre_commit_path = format!("{}/pre-commit", hooks_dir);

    // Create hooks directory if it doesn't exist
    std::fs::create_dir_all(&hooks_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create hooks directory: {}", e);
        std::process::exit(1);
    });

    // Check if pre-commit hook already exists
    if std::path::Path::new(&pre_commit_path).exists() {
        if !terminal::ask_yes_no("Pre-commit hook already exists. Do you want to overwrite it?", false) {
            println!("Skipping pre-commit hook setup.");
            return;
        }
    }

    // Create pre-commit hook content
    let hook_content = r#"#!/bin/sh
# Corgea pre-commit hook
corgea scan --only-uncommitted
"#;

    // Write pre-commit hook
    std::fs::write(&pre_commit_path, hook_content).unwrap_or_else(|e| {
        eprintln!("Failed to write pre-commit hook: {}", e);
        std::process::exit(1);
    });

    // Make hook executable
    #[cfg(unix)]
    std::fs::set_permissions(&pre_commit_path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .unwrap_or_else(|e| {
            eprintln!("Failed to set pre-commit hook permissions: {}", e);
            std::process::exit(1);
        });

    println!("Successfully installed pre-commit hook!");
}
