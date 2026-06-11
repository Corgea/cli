//! Resolve and exec the real package manager, forwarding args and exit codes.

use std::ffi::OsString;
use std::process::Command;

use super::PackageManager;

pub(super) fn exec_install_with_args(
    manager: PackageManager,
    subcommand: &str,
    rest: &[String],
) -> i32 {
    let mut full = Vec::with_capacity(rest.len() + 1);
    full.push(subcommand.to_string());
    full.extend(rest.iter().cloned());
    exec_command(manager.binary_name(), &full)
}

/// Resolve `binary` on PATH. On Windows this finds `.cmd` shims. pip is the
/// one manager with a conventional alias, so a missing `pip` retries `pip3`.
/// The error names the binary and any fallback tried.
pub(super) fn resolve_binary(binary: &str) -> Result<std::path::PathBuf, String> {
    if let Ok(p) = which::which(binary) {
        return Ok(p);
    }
    if binary == "pip" {
        if let Ok(p) = which::which("pip3") {
            return Ok(p);
        }
        return Err("error: 'pip' not found on PATH (also tried 'pip3')".to_string());
    }
    Err(format!("error: '{binary}' not found on PATH"))
}

pub(super) fn exec_command(binary: &str, args: &[String]) -> i32 {
    let resolved = match resolve_binary(binary) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 127;
        }
    };

    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();

    match Command::new(&resolved).args(&os_args).status() {
        Ok(status) => status.code().unwrap_or_else(|| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    return 128 + sig;
                }
            }
            1
        }),
        Err(e) => {
            // Name the resolved path: it may be the pip3 fallback, not `binary`.
            eprintln!("failed to exec {}: {}", resolved.display(), e);
            1
        }
    }
}
