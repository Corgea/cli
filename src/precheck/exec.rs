//! Resolve and exec the real package manager, forwarding args and exit codes.

use std::ffi::OsString;
use std::process::Command;

use super::PackageManager;

pub(super) fn exec_install_with_args(
    manager: PackageManager,
    subcommand: &str,
    rest: &[String],
    stdout_to_stderr: bool,
) -> i32 {
    let mut full = Vec::with_capacity(rest.len() + 1);
    full.push(subcommand.to_string());
    full.extend(rest.iter().cloned());
    exec_command_with_stdio(manager.binary_name(), &full, stdout_to_stderr)
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
    exec_command_with_stdio(binary, args, false)
}

/// `stdout_to_stderr` keeps stdout machine-readable under `--json`: the
/// package manager's own output moves to stderr so stdout carries only the
/// Corgea report. Every caller that passes `true` here prints its report (the
/// full report or an empty one via `proceed_ungated`) *before* this exec, so a
/// missing binary must not print a second JSON document — it stays on stderr
/// and exits 127, leaving the already-printed report as the one document.
pub(super) fn exec_command_with_stdio(
    binary: &str,
    args: &[String],
    stdout_to_stderr: bool,
) -> i32 {
    let resolved = match resolve_binary(binary) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 127;
        }
    };

    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();

    let mut command = Command::new(&resolved);
    command.args(&os_args);
    if stdout_to_stderr {
        command.stdout(std::io::stderr());
    }
    match command.status() {
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
