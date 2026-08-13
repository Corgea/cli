use crate::config::Config;
use crate::scan::build_scan_url;
use crate::targets;
use crate::utils;
use crate::utils::api::SCAIssue;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Overrides how long `wait_for_scan` polls before giving up.
const SCAN_TIMEOUT_ENV: &str = "CORGEA_SCAN_TIMEOUT_SECONDS";
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(10 * 60 * 60);

/// Overrides how long the CI gate waits for blocking rules to be evaluated.
const BLOCKING_RULES_TIMEOUT_ENV: &str = "CORGEA_BLOCKING_RULES_TIMEOUT_SECONDS";

#[allow(clippy::too_many_arguments)]
pub fn run(
    config: &Config,
    fail_on: Option<String>,
    fail: &bool,
    block_on: Option<String>,
    only_uncommitted: &bool,
    metadata: Option<String>,
    scan_type: Option<String>,
    policy: Option<String>,
    out_format: Option<String>,
    out_file: Option<String>,
    target: Option<String>,
    exclude: Option<String>,
    project_name: Option<String>,
    sbom: Option<String>,
) {
    // Validate that only_uncommitted and target are not used together
    if *only_uncommitted && target.is_some() {
        log::error!("--only_uncommitted and --target cannot be used together.");
        std::process::exit(1);
    }

    if *only_uncommitted {
        match utils::generic::is_git_repo("./") {
            Ok(false) => {
                log::error!("This is not a git repository. Without a git repository Corgea CLI can't determine which files have been modified or added thus only a full scan is possible.");
                std::process::exit(1);
            }
            Err(e) => {
                log::error!("Error checking git repository information: {}. Without a git repository Corgea CLI can't determine which files have been modified or added thus only a full scan is possible.", e);
                std::process::exit(1);
            }
            Ok(true) => {
                // Continue with the git repo logic
            }
        }
    }
    println!("\nScanning with BLAST 🚀🚀🚀");

    if let Some(scan_type) = &scan_type {
        println!("Running Scan Type: {}", scan_type);
    }
    if let Some(policy) = &policy {
        println!(
            "Including only specified policies for policy scan: {}",
            policy
        );
    }
    println!("\n\n");
    let temp_dir = env::temp_dir().join(format!("corgea/tmp/{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");
    let project_name = utils::generic::determine_project_name(project_name.as_deref());
    let zip_path = format!("{}/{}.zip", temp_dir.display(), project_name);
    match utils::generic::create_path_if_not_exists(&temp_dir) {
        Ok(_) => (),
        Err(e) => {
            log::error!(
                "\n\nOops! Something went wrong while creating the directory at '{}'.\nPlease check if you have the necessary permissions or if the path is valid.\nError details:\n{}\n\n", 
                temp_dir.display(), e
            );
            std::process::exit(1);
        }
    }

    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let packaging_thread = thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Packaging your project... ([T]s)",
            stop_signal_clone,
        );
    });

    let target_str: Option<&str> = if *only_uncommitted {
        Some("git:staged,git:modified,git:untracked")
    } else {
        target.as_deref()
    };

    // Before packaging: mid-pack HEAD move must not look like a clean new SHA.
    let repo_before = utils::generic::get_repo_info_for_scan("./").unwrap_or_default();

    if target_str.is_none() && exclude.is_some() {
        println!("Excluding files matching: {}", exclude.as_deref().unwrap());
    }

    if let Some(target_value) = target_str {
        match targets::resolve_targets_with_exclude(target_value, exclude.as_deref()) {
            Ok(result) => {
                if result.files.is_empty() {
                    *stop_signal.lock().unwrap() = true;
                    let _ = packaging_thread.join();
                    print!(
                        "\r{}",
                        utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
                    );
                    log::error!("\n\nError: target resolved to zero files.\n");
                    log::error!("Target value: {}\n", target_value);
                    log::error!("Segment results:");
                    for segment_result in &result.segments {
                        if let Some(ref error) = segment_result.error {
                            log::error!("  {}: ERROR - {}", segment_result.segment, error);
                        } else {
                            log::error!(
                                "  {}: {} matches",
                                segment_result.segment,
                                segment_result.matches
                            );
                        }
                    }
                    log::error!("\nPlease check your target specification and try again.\n");
                    std::process::exit(1);
                }

                let file_count = result.files.len();
                if *only_uncommitted {
                    println!("\rFiles to be submitted for partial scan:\n");
                    for (index, file) in result.files.iter().enumerate() {
                        if let Ok(relative) =
                            file.strip_prefix(std::env::current_dir().unwrap_or_default())
                        {
                            println!("{}: {}", index + 1, relative.display());
                        } else {
                            println!("{}: {}", index + 1, file.display());
                        }
                    }
                    println!();
                } else {
                    println!("Scanning {} files (target mode)", file_count);

                    let display_count = std::cmp::min(20, file_count);
                    for file in result.files.iter().take(display_count) {
                        if let Ok(relative) =
                            file.strip_prefix(std::env::current_dir().unwrap_or_default())
                        {
                            println!("  {}", relative.display());
                        } else {
                            println!("  {}", file.display());
                        }
                    }
                    if file_count > display_count {
                        println!("  (+{} more)", file_count - display_count);
                    }
                    println!();
                }
            }
            Err(e) => {
                *stop_signal.lock().unwrap() = true;
                let _ = packaging_thread.join();
                print!(
                    "\r{}",
                    utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
                );
                log::error!("\n\nError resolving targets: {}\n", e);
                std::process::exit(1);
            }
        }
    }

    match utils::generic::create_zip_from_target(target_str, &zip_path, None, exclude.as_deref()) {
        Ok(added_files) => {
            if added_files.is_empty() {
                *stop_signal.lock().unwrap() = true;
                let _ = packaging_thread.join();
                print!(
                    "\r{}",
                    utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
                );
                if *only_uncommitted {
                    log::error!(
                        "\n\nOops! It seems there are no scannable uncommitted changes in your project.\nYou may have uncommitted changes, but none match the types of files we can scan.\n\n"
                    );
                } else {
                    log::error!("\n\nOops! No valid files found to scan after filtering.\n\n");
                }
                std::process::exit(1);
            }
        }
        Err(e) => {
            *stop_signal.lock().unwrap() = true;
            let _ = packaging_thread.join();
            print!(
                "\r{}",
                utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
            );
            log::error!(
                "\n\nUh-oh! We couldn't package your project at '{}'.\nThis might be due to insufficient permissions, invalid file paths, or a file system error.\nPlease check the directory and try again.\nError details:\n{}\n\n", 
                zip_path, e
            );
            std::process::exit(1);
        }
    }
    *stop_signal.lock().unwrap() = true;
    let _ = packaging_thread.join();
    print!(
        "\r{}Project packaged successfully.\n",
        utils::terminal::set_text_color("", utils::terminal::TerminalColor::Green)
    );
    let repo_after = utils::generic::get_repo_info_for_scan("./").unwrap_or_default();
    // Notice = visible status only (not index hide-bits / --target / SHA drift).
    let worktree_dirty = repo_before.as_ref().is_some_and(|i| i.status_dirty)
        || repo_after.as_ref().is_some_and(|i| i.status_dirty);
    if worktree_dirty {
        let notice_sha = repo_after
            .as_ref()
            .and_then(|i| i.sha.as_deref())
            .or_else(|| repo_before.as_ref().and_then(|i| i.sha.as_deref()));
        match notice_sha {
            Some(sha) => {
                let short_sha = &sha[..sha.len().min(7)];
                println!(
                    "Working tree has uncommitted changes - scanning your local files, not commit {short_sha}."
                );
            }
            None => {
                println!("Working tree has uncommitted changes - scanning your local files.")
            }
        }
    }
    let mut repo_info = utils::generic::reconcile_repo_info_for_upload(repo_before, repo_after);
    // --target/--exclude archives are never an exact HEAD snapshot.
    if target_str.is_some() || exclude.is_some() {
        if let Some(ref mut info) = repo_info {
            info.dirty = true;
        }
    }
    println!("\n\nSubmitting scan to Corgea:");
    let upload_result = match utils::api::upload_zip(
        &zip_path,
        &config.get_url(),
        &project_name,
        repo_info,
        scan_type,
        policy,
        metadata,
    ) {
        Ok(result) => result,
        Err(e) => {
            log::error!("\n\nOh no! We encountered an issue while uploading the zip file '{}' to the server.\nPlease ensure that:
    - Blast is enabled on your Corgea account.
    - Your network connection is stable.
    - The server URL '{}' is correct.
    - Your authentication token is valid.\n\n
    
    Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli

    Error details:\n\n {}",
                zip_path,
                config.get_url(),
                e
            );
            std::process::exit(1);
        }
    };

    let scan_id = upload_result.scan_id;
    let scan_url = build_scan_url(
        &config.get_url(),
        upload_result.project_id.as_deref(),
        &project_name,
        &scan_id,
    );

    let _ = utils::generic::delete_directory(&temp_dir);
    print!(
        "\n\nScan has started with ID: {}.\n\nYou can view it populate at the link:\n{}\n\n",
        scan_id,
        utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green)
    );

    print!(
       "{}",
       utils::terminal::set_text_color("Your scan will continue securely in the Corgea cloud.\nYou can safely exit the process now if you prefer not to wait for it to complete.\n\n", utils::terminal::TerminalColor::Blue)
    );

    wait_for_scan(config, &scan_id, WaitBudget::start());
    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let results_thread = thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Collecting scan results... ([T]s)",
            stop_signal_clone,
        );
    });

    let classifications = match report_scan_status(&config.get_url(), &project_name, &scan_id) {
        Ok(issues_classes) => {
            *stop_signal.lock().unwrap() = true;
            let _ = results_thread.join();
            println!(
                "\n\nYou can view the scan results at the following link:\n{}",
                utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green)
            );
            issues_classes
        }
        Err(e) => {
            *stop_signal.lock().unwrap() = true;
            let _ = results_thread.join();
            log::error!(
                "\r{}\n\n{}\n\n\
                However, the scan results may still be accessible at the following link:\n\n\
                {}\n\n\
                \n\nPlease check your network connection, authentication token, and server URL:\n\n\
                - Server URL: {}\n\
                - Error details: {}\n",
                utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset),
                utils::terminal::set_text_color(
                    &format!(
                        "Failed to report the scan status for project: '{}'.",
                        project_name
                    ),
                    utils::terminal::TerminalColor::Red
                ),
                utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Blue),
                config.get_url(),
                e
            );
            std::process::exit(1);
        }
    };
    // The report and the SBOM are produced before the blocking-rule gates: a
    // tripped gate exits 1, and a pipeline that fails on policy still needs the
    // report it asked for to ingest the findings it failed on.
    write_scan_report(
        config,
        &project_name,
        &scan_id,
        &classifications,
        out_format.as_deref(),
        out_file.as_deref(),
    );

    if let Some(sbom_file) = sbom {
        write_sbom(&sbom_file);
    }

    if *fail {
        log::warn!(
            "\n--fail is deprecated: it evaluates every active blocking rule regardless of whether it applies to pull requests or CI. Use --block-on <slug> to name the CI blocking rules this pipeline should enforce."
        );
        let blocking_rules = wait_for_blocking_rules(config, &scan_id, None);
        if blocking_rules.block {
            println!("\nExiting with error code 1 due to some issues violating some blocking rules defined for this project.\nfor more details, please check the scan results at the link: {}\nAlternatively, you can run {} to view the issues list on your local machine.",
            utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green),
            utils::terminal::set_text_color(
                &format!("corgea ls -i -s={}", scan_id),
                utils::terminal::TerminalColor::Green
            )
        );
            std::process::exit(1);
        }
    }

    if let Some(block_on) = &block_on {
        let blocking_rules = wait_for_blocking_rules(config, &scan_id, Some(block_on));
        if blocking_rules.block {
            // The count comes from the server's pre-pagination total; the slug
            // list is drawn from the returned page, which is all the gate needs
            // to name the rules at fault.
            let triggered = triggered_slug_summary(&blocking_rules.blocking_issues);
            println!(
                "\nExiting with error code 1: {} issue(s) violated the blocking rule(s) {}.\nFor more details, check the scan results at: {}\nAlternatively, run {} to view the issues list on your local machine.",
                blocking_rules.blocked_count(),
                utils::terminal::set_text_color(&triggered, utils::terminal::TerminalColor::Red),
                utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green),
                utils::terminal::set_text_color(
                    &format!("corgea ls -i -s={}", scan_id),
                    utils::terminal::TerminalColor::Green
                )
            );
            std::process::exit(1);
        }
        println!(
            "\nNo issues violated the blocking rule(s): {}.",
            utils::terminal::set_text_color(block_on, utils::terminal::TerminalColor::Green)
        );
    }

    print!("\n\nThank you for using Corgea! 🐕\n\n");

    if let Some(fail_on) = fail_on {
        let tokens = match parse_fail_on_tokens(&fail_on) {
            Ok(tokens) => tokens,
            Err(msg) => {
                log::error!("{}", msg);
                std::process::exit(1);
            }
        };

        let severity_already_tripped = tokens
            .iter()
            .filter(|t| t.as_str() != "malicious")
            .any(|t| severity_gate_trips(t, &classifications));
        let needs_sca_fetch = !severity_already_tripped && tokens.iter().any(|t| t == "malicious");

        let sca_issues = if needs_sca_fetch {
            match utils::api::get_all_sca_issues(
                &config.get_url(),
                &project_name,
                Some(scan_id.clone()),
            ) {
                Ok(issues) => issues,
                Err(e) => {
                    log::error!(
                        "\n\nFailed to fetch SCA issues for --fail-on malicious: {}\n\n",
                        e
                    );
                    std::process::exit(1);
                }
            }
        } else {
            Vec::new()
        };

        if fail_on_gate_trips(&tokens, &classifications, &sca_issues) {
            println!(
                "\nExiting with error code 1: scan results matched --fail-on {}.",
                fail_on
            );
            std::process::exit(1);
        }
    }
}

/// Write the `--out-format` report for a completed scan to `--out-file`.
///
/// Does nothing unless both are set; `main` rejects one without the other.
fn write_scan_report(
    config: &Config,
    project_name: &str,
    scan_id: &str,
    classifications: &HashMap<String, usize>,
    out_format: Option<&str>,
    out_file: Option<&str>,
) {
    let (Some(out_format), Some(out_file)) = (out_format, out_file) else {
        return;
    };

    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let results_thread = thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Generating scan report... ([T]s)",
            stop_signal_clone,
        );
    });
    let stop_spinner = move || {
        *stop_signal.lock().unwrap() = true;
        let _ = results_thread.join();
    };

    if out_format == "json" {
        let issues =
            match utils::api::get_all_issues(&config.get_url(), project_name, Some(scan_id.into()))
            {
                Ok(issues) => issues,
                Err(e) => {
                    log::error!("\n\nFailed to fetch issues: {}\n\n", e);
                    std::process::exit(1);
                }
            };
        let sca_issues = match utils::api::get_all_sca_issues(
            &config.get_url(),
            project_name,
            Some(scan_id.into()),
        ) {
            Ok(issues) => issues,
            Err(e) => {
                log::error!("\n\nFailed to fetch SCA issues: {}\n\n", e);
                std::process::exit(1);
            }
        };
        let json = serde_json::to_string_pretty(&issues).unwrap();
        let sca_json = serde_json::to_string_pretty(&sca_issues).unwrap();
        let report_json = serde_json::to_string_pretty(classifications).unwrap();
        let results_json = format!(
            "{{\"issues\": {}, \"sca_issues\": {}, \"report\": {}}}",
            json, sca_json, report_json
        );
        stop_spinner();
        fs::write(out_file, results_json).expect("Failed to write JSON file, check if the file path is valid and you have the necessary permissions to write to it.");
        utils::terminal::clear_previous_line();
        println!("\n\nScan results written to: {}\n\n", out_file);
        return;
    }

    // The server renders these; `None` is its HTML default.
    let (report_format, label) = match out_format {
        "html" => (None, "HTML"),
        "sarif" => (Some("sarif"), "SARIF"),
        "markdown" => (Some("markdown"), "Markdown"),
        _ => {
            stop_spinner();
            log::error!("\n\nUnsupported out_format: {}\n\n", out_format);
            std::process::exit(1);
        }
    };
    let report = match utils::api::get_scan_report(&config.get_url(), scan_id, report_format) {
        Ok(report) => report,
        Err(e) => {
            stop_spinner();
            log::error!("\n\nFailed to fetch {} report: {}\n\n", label, e);
            std::process::exit(1);
        }
    };
    stop_spinner();
    fs::write(out_file, report).unwrap_or_else(|_| panic!("\n\nFailed to write {label} file, check if the file path is valid and you have the necessary permissions to write to it."));
    utils::terminal::clear_previous_line();
    println!("\n\nScan report written to: {}\n\n", out_file);
}

/// Write a CycloneDX SBOM of the working directory to `sbom_file`.
fn write_sbom(sbom_file: &str) {
    match corgea::deps::report::sbom(std::path::Path::new(".")) {
        Ok(doc) => {
            let json = serde_json::to_string_pretty(&doc).expect("serialize SBOM");
            if let Err(e) = fs::write(sbom_file, json) {
                log::error!("\n\nFailed to write SBOM to '{}': {}\n\n", sbom_file, e);
                std::process::exit(1);
            }
            println!("CycloneDX SBOM written to: {}\n", sbom_file);
        }
        Err(e) => {
            log::error!("\n\nFailed to generate SBOM: {}\n\n", e);
            std::process::exit(1);
        }
    }
}

pub const VALID_FAIL_ON_TOKENS: [&str; 5] = ["CR", "HI", "ME", "LO", "malicious"];

/// Parse and validate a comma-separated --fail-on value.
/// "HI,malicious", "malicious", "CR" are all valid.
pub fn parse_fail_on_tokens(fail_on: &str) -> Result<Vec<String>, String> {
    let tokens: Vec<String> = fail_on
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let valid_options = || {
        VALID_FAIL_ON_TOKENS
            .iter()
            .map(|t| format!("'{}'", t))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if tokens.is_empty() {
        return Err(format!(
            "Invalid fail_on option. Expected a comma-separated list of {}.",
            valid_options()
        ));
    }
    for token in &tokens {
        if !VALID_FAIL_ON_TOKENS.contains(&token.as_str()) {
            return Err(format!(
                "Invalid fail_on option '{}'. Expected a comma-separated list of {}.",
                token,
                valid_options()
            ));
        }
    }
    Ok(tokens)
}

fn severity_rank(severity: &str) -> Option<u8> {
    match severity {
        "LO" => Some(0),
        "ME" => Some(1),
        "HI" => Some(2),
        "CR" => Some(3),
        _ => None,
    }
}

/// At-or-above semantics: --fail-on ME trips on ME, HI, and CR.
pub fn severity_gate_trips(threshold: &str, counts: &HashMap<String, usize>) -> bool {
    let Some(threshold_rank) = severity_rank(threshold) else {
        return false;
    };
    counts.iter().any(|(severity, &count)| {
        count > 0 && severity_rank(severity).is_some_and(|rank| rank >= threshold_rank)
    })
}

/// Any scan-scoped SCA issue classified malicious trips the gate.
/// Merely-vulnerable issues (classification None or other) do not.
pub fn malicious_gate_trips(sca_issues: &[SCAIssue]) -> bool {
    sca_issues
        .iter()
        .any(|issue| issue.classification.as_deref() == Some("malicious"))
}

/// Comma-list OR semantics: ANY listed condition tripping fails the scan.
pub fn fail_on_gate_trips(
    tokens: &[String],
    counts: &HashMap<String, usize>,
    sca_issues: &[SCAIssue],
) -> bool {
    tokens.iter().any(|token| match token.as_str() {
        "malicious" => malicious_gate_trips(sca_issues),
        threshold => severity_gate_trips(threshold, counts),
    })
}

/// Trim and de-duplicate the comma-separated `--block-on` slugs.
///
/// Returns the canonical comma-joined value to send to the API, or `None`
/// when the flag was not supplied. Empty entries are rejected here so a stray
/// comma is reported locally rather than as an opaque server error.
pub fn normalize_block_on(block_on: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = block_on else {
        return Ok(None);
    };

    let mut slugs: Vec<&str> = Vec::new();
    for part in raw.split(',') {
        let slug = part.trim();
        if slug.is_empty() {
            return Err(
                "block-on contains an empty rule slug. Expected a comma-separated list of rule slugs, e.g. --block-on criticals,malicious-deps."
                    .to_string(),
            );
        }
        if !slugs.contains(&slug) {
            slugs.push(slug);
        }
    }

    if slugs.is_empty() {
        return Err("block-on cannot be empty.".to_string());
    }
    Ok(Some(slugs.join(",")))
}

/// The distinct rule slugs that blocked the scan, for the failure message.
///
/// Falls back to rule ids against backends that do not send slugs yet.
pub fn triggered_slug_summary(issues: &[utils::api::BlockingIssue]) -> String {
    let mut names: Vec<String> = Vec::new();
    for issue in issues {
        let identifiers = match &issue.triggered_by_slugs {
            Some(slugs) if !slugs.is_empty() => slugs.clone(),
            _ => issue.triggered_by_rules.clone(),
        };
        for identifier in identifiers {
            if !names.contains(&identifier) {
                names.push(identifier);
            }
        }
    }
    names.join(", ")
}

/// Whether a scan status means the scan has stopped, and if so, how it ended.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ScanState {
    Completed,
    Failed,
    Running,
}

/// Classify the scan status reported by the API.
///
/// The contract is a frozen four-value set: `complete`, `incomplete`,
/// `processing`, `scanning`. `incomplete` is terminal, and treating it as
/// running is what made the CLI poll a finished scan forever. The extra
/// aliases are defensive: terminal-sounding statuses must stop the loop.
pub fn classify_scan_status(status: &str) -> ScanState {
    match status.trim().to_lowercase().as_str() {
        "complete" | "completed" => ScanState::Completed,
        "incomplete" | "failed" | "error" | "cancelled" | "canceled" => ScanState::Failed,
        _ => ScanState::Running,
    }
}

/// Compact duration for a message: `10h`, `15m`, or `90s`.
fn format_timeout(timeout: Duration) -> String {
    match timeout.as_secs() {
        secs if secs > 0 && secs % 3600 == 0 => format!("{}h", secs / 3600),
        secs if secs > 0 && secs % 60 == 0 => format!("{}m", secs / 60),
        secs => format!("{}s", secs),
    }
}

/// How long to wait, from `var`, falling back to `default` when it is unset or
/// unusable. Takes the raw value so it is testable without touching the
/// environment.
fn parse_timeout(var: &str, raw: Option<&str>, default: Duration) -> Duration {
    match raw {
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(seconds) if seconds > 0 => Duration::from_secs(seconds),
            _ => {
                log::warn!(
                    "Ignoring {}='{}': expected a positive whole number of seconds. Waiting up to {} instead.",
                    var,
                    raw,
                    format_timeout(default)
                );
                default
            }
        },
        None => default,
    }
}

fn env_timeout(var: &str, default: Duration) -> Duration {
    parse_timeout(var, env::var(var).ok().as_deref(), default)
}

/// The wall-clock budget for one wait, shared by every read it makes so that a
/// stalled read cannot push the total past what the user asked for.
pub struct WaitBudget {
    started_at: Instant,
    timeout: Duration,
}

impl WaitBudget {
    /// Starts the clock, spending up to `SCAN_TIMEOUT_ENV`.
    ///
    /// Backstop for a scan that never reports a terminal status. Scans that run
    /// past the default raise the override.
    pub fn start() -> Self {
        Self::with_timeout(env_timeout(SCAN_TIMEOUT_ENV, DEFAULT_SCAN_TIMEOUT))
    }

    fn with_timeout(timeout: Duration) -> Self {
        Self {
            started_at: Instant::now(),
            timeout,
        }
    }

    /// What is left to spend, or `None` once the budget is gone.
    pub fn remaining(&self) -> Option<Duration> {
        let remaining = self.timeout.saturating_sub(self.started_at.elapsed());
        (!remaining.is_zero()).then_some(remaining)
    }
}

/// Human-readable explanation of why a scan failed, for the terminal.
///
/// Falls back from `failed_reason` to the reported scanner problems, so the
/// output is always more specific than "the scan failed".
pub fn format_scan_failure(scan: &utils::api::ScanResponse) -> String {
    let mut lines = vec![format!("Scan {} did not complete.", scan.id)];
    if let Some(reason) = scan
        .failed_reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
    {
        lines.push(format!("Reason: {}", reason));
    }
    let problems = scan_problem_lines(scan);
    if !problems.is_empty() {
        lines.push(String::from("Scanner problems:"));
        lines.extend(problems);
    }
    lines.join("\n")
}

/// Warnings for a scan that finished but is missing some scanner's results.
///
/// `None` when nothing degraded. A secondary scanner breaking no longer fails
/// the scan, so this is the only place coverage loss surfaces.
pub fn format_scan_warnings(scan: &utils::api::ScanResponse) -> Option<String> {
    let problems = scan_problem_lines(scan);
    if problems.is_empty() {
        return None;
    }
    let mut lines = vec![String::from(
        "Some scanners reported problems, so this scan may be missing results:",
    )];
    lines.extend(problems);
    Some(lines.join("\n"))
}

/// One bullet per scanner problem, capped so dozens of file-level errors
/// cannot bury the rest of the output.
fn scan_problem_lines(scan: &utils::api::ScanResponse) -> Vec<String> {
    const MAX_LINES: usize = 10;
    let problems: Vec<&utils::api::ScanErrorSummary> = scan
        .scan_errors
        .iter()
        .filter(|error| error.is_problem())
        .collect();
    let mut lines: Vec<String> = problems
        .iter()
        .take(MAX_LINES)
        .map(|error| format_scan_error_line(error))
        .collect();
    if problems.len() > MAX_LINES {
        lines.push(format!(
            "  ...and {} more; see the scan page for the full list.",
            problems.len() - MAX_LINES
        ));
    }
    lines
}

fn format_scan_error_line(error: &utils::api::ScanErrorSummary) -> String {
    let message = error
        .message
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("No details provided.");
    let mut prefix = String::new();
    if let Some(scan_type) = error.scan_type.as_deref().filter(|s| !s.is_empty()) {
        prefix.push_str(scan_type);
    }
    if let Some(location) = error.location.as_deref().filter(|l| !l.is_empty()) {
        if prefix.is_empty() {
            prefix.push_str(location);
        } else {
            prefix.push_str(&format!(" @ {}", location));
        }
    }
    if prefix.is_empty() {
        format!("  - {}", message)
    } else {
        format!("  - [{}] {}", prefix, message)
    }
}

/// Why the wait stopped before the scan reached a terminal state.
fn poll_timed_out(scan_id: &str, budget: &WaitBudget, last_status: &str) -> String {
    format!(
        "Stopped waiting for scan {} after {}s; it was last reported as '{}'.\n\
         The scan may still finish in the Corgea cloud — check the scan page, \
         or set {} to wait longer.",
        scan_id,
        budget.timeout.as_secs(),
        last_status,
        SCAN_TIMEOUT_ENV
    )
}

/// Block until the scan reaches a terminal state, then report it.
///
/// Exits non-zero on failure or poll timeout, so CI cannot mistake a broken
/// scan for a clean one.
pub fn wait_for_scan(config: &Config, scan_id: &str, budget: WaitBudget) {
    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let spinner = thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Scanning... The Hunt Is On! ([T]s)",
            stop_signal_clone,
        );
    });

    let mut last_status = String::from("unknown");

    let result = loop {
        thread::sleep(Duration::from_secs(1));
        // Every read is capped to what is left of the budget: on the client's
        // own timeout a stalled read would otherwise keep us going long past
        // the wait the user asked for.
        let Some(remaining) = budget.remaining() else {
            break Err(poll_timed_out(scan_id, &budget, &last_status));
        };
        match utils::api::get_scan(&config.get_url(), scan_id, Some(remaining)) {
            Ok(scan) => match classify_scan_status(&scan.status) {
                ScanState::Completed => break Ok(scan),
                ScanState::Failed => break Err(format_scan_failure(&scan)),
                ScanState::Running => last_status = scan.status,
            },
            // A read cut short by the deadline is a timeout, not a broken link.
            Err(_) if budget.remaining().is_none() => {
                break Err(poll_timed_out(scan_id, &budget, &last_status))
            }
            Err(e) => {
                break Err(format!(
                    "Unable to check the status of scan '{}'.\n\
                     Please verify that:\n\
                     - The server URL '{}' is reachable.\n\
                     - Your authentication token is valid.\n\
                     - The scan ID is correct.\n\n\
                     Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli\n\n\
                     Error details: {}",
                    scan_id,
                    config.get_url(),
                    e
                ))
            }
        }
    };

    *stop_signal.lock().unwrap() = true;
    let _ = spinner.join();
    print!(
        "\r{}",
        utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
    );

    let scan = match result {
        Ok(scan) => scan,
        Err(message) => {
            log::error!("\n\n{}\n", message);
            std::process::exit(1);
        }
    };

    println!(
        "\r╭────────────────────────────────────────────╮\n\
             │ {: <42} │\n\
             │   🎉🎉 Scan Completed Successfully! 🎉🎉   │\n\
             │ {: <42} │\n\
             ╰────────────────────────────────────────────╯\n",
        " ", " "
    );
    if let Some(warnings) = format_scan_warnings(&scan) {
        log::warn!("{}\n", warnings);
    }
}

/// Match doghouse `LICENSE_DEPS_WAIT_TIMEOUT` (15 minutes).
const DEFAULT_BLOCKING_RULES_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const BLOCKING_RULES_POLL_INTERVAL: Duration = Duration::from_secs(2);

fn stop_blocking_rules_spinner(stop_signal: &Arc<Mutex<bool>>, spinner: thread::JoinHandle<()>) {
    *stop_signal.lock().unwrap() = true;
    let _ = spinner.join();
    print!(
        "{}",
        utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
    );
}

#[derive(Debug)]
enum BlockingRulesPollDecision {
    Complete(utils::api::BlockingRuleResponse),
    KeepWaiting,
    FailClosed { message: String },
}

const BLOCKING_RULES_TIMEOUT_MESSAGE: &str =
    "Timed out waiting for blocking rules to finish. Failing closed.";

/// Only explicit `complete` is terminal. Pending/unknown wait; transient errors
/// retry until timeout; permanent errors fail immediately.
fn decide_blocking_rules_poll(
    result: Result<utils::api::BlockingRuleResponse, String>,
    elapsed: Duration,
    timeout: Duration,
) -> BlockingRulesPollDecision {
    match result {
        Ok(rules) if rules.is_complete() => BlockingRulesPollDecision::Complete(rules),
        Ok(rules) => {
            if elapsed >= timeout {
                log::debug!(
                    "Blocking-rules wait timed out; last status was '{}'.",
                    rules.status
                );
                BlockingRulesPollDecision::FailClosed {
                    message: BLOCKING_RULES_TIMEOUT_MESSAGE.to_string(),
                }
            } else {
                if rules.status == utils::api::BLOCKING_RULES_STATUS_PENDING {
                    log::debug!("Blocking rules still pending; waiting.");
                } else {
                    log::debug!(
                        "Unexpected blocking-rules status '{}'; waiting for complete.",
                        rules.status
                    );
                }
                BlockingRulesPollDecision::KeepWaiting
            }
        }
        Err(e) => {
            if !utils::api::is_retryable_blocking_rules_error_message(&e) || elapsed >= timeout {
                BlockingRulesPollDecision::FailClosed { message: e }
            } else {
                log::debug!("Transient blocking-rules error; will retry: {}", e);
                BlockingRulesPollDecision::KeepWaiting
            }
        }
    }
}

/// Poll until blocking-rules status is `complete`, or `BLOCKING_RULES_TIMEOUT_ENV`
/// (15m by default) runs out.
/// Older backends omit status (serde defaults to complete: one-shot).
/// `block_on` is forwarded as the CI rule-slug filter (`--block-on`); `None`
/// keeps legacy `--fail` "all active rules" behavior.
fn wait_for_blocking_rules(
    config: &Config,
    scan_id: &str,
    block_on: Option<&str>,
) -> utils::api::BlockingRuleResponse {
    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let spinner = thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Checking blocking rules... ([T]s)",
            stop_signal_clone,
        );
    });

    let timeout = env_timeout(BLOCKING_RULES_TIMEOUT_ENV, DEFAULT_BLOCKING_RULES_TIMEOUT);
    let started = Instant::now();
    loop {
        // Do not start another request after the deadline.
        if started.elapsed() >= timeout {
            stop_blocking_rules_spinner(&stop_signal, spinner);
            log::error!("\n{} (scan '{}')", BLOCKING_RULES_TIMEOUT_MESSAGE, scan_id);
            std::process::exit(1);
        }

        let result = utils::api::check_blocking_rules(&config.get_url(), scan_id, None, block_on)
            .map_err(|e| e.to_string());
        match decide_blocking_rules_poll(result, started.elapsed(), timeout) {
            BlockingRulesPollDecision::Complete(rules) => {
                stop_blocking_rules_spinner(&stop_signal, spinner);
                return rules;
            }
            BlockingRulesPollDecision::KeepWaiting => {}
            BlockingRulesPollDecision::FailClosed { message } => {
                stop_blocking_rules_spinner(&stop_signal, spinner);
                if message == BLOCKING_RULES_TIMEOUT_MESSAGE {
                    log::error!("\n{} (scan '{}')", message, scan_id);
                } else {
                    log::error!("Failed to check blocking rules: {}", message);
                }
                std::process::exit(1);
            }
        }
        thread::sleep(BLOCKING_RULES_POLL_INTERVAL);
    }
}

pub fn fetch_and_group_scan_issues(
    url: &str,
    project: &str,
    scan_id: &str,
) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let issues = match utils::api::get_all_issues(url, project, Some(scan_id.to_string())) {
        Ok(issues) => issues,
        Err(err) => {
            return Err(format!("Failed to fetch scan issues: {}", err).into());
        }
    };
    let mut classification_counts: HashMap<String, usize> = HashMap::new();
    if !issues.is_empty() {
        for issue in &issues {
            *classification_counts
                .entry(issue.urgency.clone())
                .or_insert(0) += 1;
        }
    }
    Ok(classification_counts)
}

pub fn report_scan_status(
    url: &str,
    project: &str,
    scan_id: &str,
) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let classification_counts = match fetch_and_group_scan_issues(url, project, scan_id) {
        Ok(counts) => counts,
        Err(e) => {
            return Err(e);
        }
    };

    let total_issues = classification_counts.values().sum::<usize>();
    utils::terminal::clear_previous_line();
    println!("\rScan Results:-\n");
    println!("{:<20} | Count", "Classification");
    println!("{:-<20} | ", "");

    let order = vec!["CR", "HI", "ME", "LO"];
    for classification in order {
        if let Some(count) = classification_counts.get(classification) {
            println!("{:<20} | {}", classification, count);
        } else {
            println!("{:<20} | {}", classification, 0);
        }
    }

    println!("{:-<20} | ", "");
    println!("{:<20} | {}", "Total", total_issues);
    Ok(classification_counts)
}

/// Parse `--metadata KEY=VALUE` flags into a JSON object string.
/// Splits on the first `=`; duplicate keys last-wins. Empty input -> `Ok(None)`.
pub fn metadata_json_from_pairs(pairs: &[String]) -> Result<Option<String>, String> {
    let mut map = serde_json::Map::new();
    for entry in pairs {
        match entry.split_once('=') {
            Some((key, value)) if !key.is_empty() => {
                map.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
            _ => {
                return Err(
                    "Invalid --metadata value. Use KEY=VALUE with a non-empty key, e.g. --metadata pipeline_url=https://...".to_string(),
                );
            }
        }
    }
    if map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::Value::Object(map).to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::api::{
        BlockOnError, BlockingIssue, BlockingRuleResponse, BlockingRuleStats, SCAIssue,
        SCALocation, SCAPackage, BLOCKING_RULES_STATUS_COMPLETE, BLOCKING_RULES_STATUS_PENDING,
    };

    fn counts(pairs: &[(&str, usize)]) -> HashMap<String, usize> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn sample_rules(status: &str, block: bool) -> BlockingRuleResponse {
        BlockingRuleResponse {
            block,
            blocking_issues: vec![],
            total_pages: 1,
            stats: None,
            status: status.to_string(),
        }
    }

    #[test]
    fn poll_only_complete_is_terminal_unknown_keeps_waiting() {
        let timeout = Duration::from_secs(60);
        match decide_blocking_rules_poll(
            Ok(sample_rules(BLOCKING_RULES_STATUS_COMPLETE, true)),
            Duration::ZERO,
            timeout,
        ) {
            BlockingRulesPollDecision::Complete(r) => assert!(r.block),
            other => panic!("expected Complete, got {other:?}"),
        }
        assert!(matches!(
            decide_blocking_rules_poll(
                Ok(sample_rules(BLOCKING_RULES_STATUS_PENDING, false)),
                Duration::ZERO,
                timeout
            ),
            BlockingRulesPollDecision::KeepWaiting
        ));
        assert!(matches!(
            decide_blocking_rules_poll(
                Ok(sample_rules("processing", false)),
                Duration::ZERO,
                timeout
            ),
            BlockingRulesPollDecision::KeepWaiting
        ));
        assert!(matches!(
            decide_blocking_rules_poll(Ok(sample_rules("", false)), Duration::ZERO, timeout),
            BlockingRulesPollDecision::KeepWaiting
        ));
        assert!(matches!(
            decide_blocking_rules_poll(Ok(sample_rules("processing", false)), timeout, timeout),
            BlockingRulesPollDecision::FailClosed { .. }
        ));
    }

    #[test]
    fn poll_retries_transient_error_then_accepts_complete() {
        let timeout = Duration::from_secs(60);
        assert!(matches!(
            decide_blocking_rules_poll(
                Err("API request failed with status: 503 Service Unavailable".into()),
                Duration::from_secs(1),
                timeout,
            ),
            BlockingRulesPollDecision::KeepWaiting
        ));
        // Still fail closed once the overall deadline is hit.
        assert!(matches!(
            decide_blocking_rules_poll(
                Err("API request failed with status: 503 Service Unavailable".into()),
                timeout,
                timeout,
            ),
            BlockingRulesPollDecision::FailClosed { .. }
        ));
        match decide_blocking_rules_poll(
            Ok(sample_rules(BLOCKING_RULES_STATUS_COMPLETE, false)),
            Duration::from_secs(2),
            timeout,
        ) {
            BlockingRulesPollDecision::Complete(r) => assert!(!r.block),
            other => panic!("expected Complete after retry, got {other:?}"),
        }
    }

    #[test]
    fn poll_fails_fast_on_permanent_auth_error() {
        assert!(matches!(
            decide_blocking_rules_poll(
                Err("API request failed with status: 401 Unauthorized".into()),
                Duration::ZERO,
                Duration::from_secs(60),
            ),
            BlockingRulesPollDecision::FailClosed { .. }
        ));
    }

    #[test]
    fn poll_accepts_complete_even_after_deadline_overrun() {
        // Request started under budget; late response still honored.
        match decide_blocking_rules_poll(
            Ok(sample_rules(BLOCKING_RULES_STATUS_COMPLETE, true)),
            Duration::from_secs(16 * 60),
            Duration::from_secs(15 * 60),
        ) {
            BlockingRulesPollDecision::Complete(r) => assert!(r.block),
            other => panic!("expected late Complete to be accepted, got {other:?}"),
        }
    }

    fn sca_issue(classification: Option<&str>) -> SCAIssue {
        SCAIssue {
            id: "issue-1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            description: None,
            details: None,
            severity: Some("CRITICAL".to_string()),
            classification: classification.map(|c| c.to_string()),
            cve: None,
            package: SCAPackage {
                name: "pkg".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: "npm".to_string(),
                fix_version: None,
            },
            location: SCALocation {
                path: "package-lock.json".to_string(),
            },
        }
    }

    #[test]
    fn parse_accepts_single_severity_and_malicious_and_mixed_list() {
        assert_eq!(parse_fail_on_tokens("CR").unwrap(), vec!["CR"]);
        assert_eq!(
            parse_fail_on_tokens("malicious").unwrap(),
            vec!["malicious"]
        );
        assert_eq!(
            parse_fail_on_tokens("HI, malicious").unwrap(),
            vec!["HI", "malicious"]
        );
    }

    #[test]
    fn parse_rejects_invalid_and_empty_tokens() {
        assert!(parse_fail_on_tokens("BAD").is_err());
        assert!(parse_fail_on_tokens("HI,BAD").is_err());
        assert!(parse_fail_on_tokens("").is_err());
        assert!(parse_fail_on_tokens(",").is_err());
    }

    #[test]
    fn severity_gate_me_trips_on_cr_only_scan() {
        // Deliberate behavior fix: at-or-above (previously the ME arm omitted CR).
        assert!(severity_gate_trips("ME", &counts(&[("CR", 1)])));
    }

    #[test]
    fn severity_gate_at_or_above_matrix() {
        assert!(severity_gate_trips("LO", &counts(&[("LO", 1)])));
        assert!(severity_gate_trips("LO", &counts(&[("CR", 1)])));
        assert!(severity_gate_trips("ME", &counts(&[("ME", 2)])));
        assert!(severity_gate_trips("HI", &counts(&[("CR", 1)])));
        assert!(severity_gate_trips("CR", &counts(&[("CR", 1)])));
        assert!(!severity_gate_trips("CR", &counts(&[("HI", 5)])));
        assert!(!severity_gate_trips("HI", &counts(&[("ME", 5), ("LO", 5)])));
        assert!(!severity_gate_trips("ME", &counts(&[("LO", 5)])));
        assert!(!severity_gate_trips("LO", &counts(&[])));
        // zero-count buckets never trip
        assert!(!severity_gate_trips("LO", &counts(&[("CR", 0)])));
        // unknown severity strings never trip
        assert!(!severity_gate_trips("LO", &counts(&[("NA", 3)])));
    }

    #[test]
    fn malicious_gate_trips_only_on_malicious_classification() {
        assert!(malicious_gate_trips(&[sca_issue(Some("malicious"))]));
        assert!(malicious_gate_trips(&[
            sca_issue(None),
            sca_issue(Some("malicious"))
        ]));
        // merely-vulnerable (classification None) does NOT trip
        assert!(!malicious_gate_trips(&[sca_issue(None)]));
        assert!(!malicious_gate_trips(&[sca_issue(Some("other"))]));
        assert!(!malicious_gate_trips(&[]));
    }

    #[test]
    fn fail_on_gate_composes_comma_list_with_or_semantics() {
        let tokens = |s: &str| parse_fail_on_tokens(s).unwrap();

        // HI,malicious: severity side alone trips (CR is at-or-above HI)
        assert!(fail_on_gate_trips(
            &tokens("HI,malicious"),
            &counts(&[("CR", 1)]),
            &[]
        ));
        // HI,malicious: malicious side alone trips
        assert!(fail_on_gate_trips(
            &tokens("HI,malicious"),
            &counts(&[("LO", 1)]),
            &[sca_issue(Some("malicious"))]
        ));
        // HI,malicious: neither side trips
        assert!(!fail_on_gate_trips(
            &tokens("HI,malicious"),
            &counts(&[("LO", 1)]),
            &[sca_issue(None)]
        ));
        // malicious alone: severity findings never trip it, merely-vulnerable passes
        assert!(!fail_on_gate_trips(
            &tokens("malicious"),
            &counts(&[("CR", 9)]),
            &[sca_issue(None)]
        ));
        // severity alone: SCA issues never trip it
        assert!(!fail_on_gate_trips(
            &tokens("CR"),
            &counts(&[("LO", 1)]),
            &[sca_issue(Some("malicious"))]
        ));
    }

    #[test]
    fn parse_metadata_valid_pairs() {
        let pairs = vec![
            "pipeline_url=https://ci.example/run/1".to_string(),
            "artifact_version=1.2.3".to_string(),
            "note=a=b=c".to_string(),
        ];
        let json = metadata_json_from_pairs(&pairs).unwrap().unwrap();
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get("pipeline_url").and_then(|v| v.as_str()),
            Some("https://ci.example/run/1")
        );
        assert_eq!(
            map.get("artifact_version").and_then(|v| v.as_str()),
            Some("1.2.3")
        );
        assert_eq!(map.get("note").and_then(|v| v.as_str()), Some("a=b=c"));
    }

    #[test]
    fn parse_metadata_rejects_missing_eq_or_empty_key() {
        assert!(metadata_json_from_pairs(&["novalue".to_string()]).is_err());
        assert!(metadata_json_from_pairs(&["=value".to_string()]).is_err());
        assert!(metadata_json_from_pairs(&["".to_string()]).is_err());
    }

    #[test]
    fn parse_metadata_duplicate_keys_last_wins() {
        let pairs = vec!["k=first".to_string(), "k=second".to_string()];
        let json = metadata_json_from_pairs(&pairs).unwrap().unwrap();
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(map.get("k").and_then(|v| v.as_str()), Some("second"));
    }

    #[test]
    fn parse_metadata_empty_value_and_empty_list_ok() {
        let json = metadata_json_from_pairs(&["k=".to_string()])
            .unwrap()
            .unwrap();
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(map.get("k").and_then(|v| v.as_str()), Some(""));
        assert!(metadata_json_from_pairs(&[]).unwrap().is_none());
    }

    #[test]
    fn normalize_block_on_returns_none_when_flag_absent() {
        assert_eq!(normalize_block_on(None).unwrap(), None);
    }

    #[test]
    fn normalize_block_on_trims_and_dedupes_slugs() {
        assert_eq!(
            normalize_block_on(Some("criticals")).unwrap(),
            Some("criticals".to_string())
        );
        assert_eq!(
            normalize_block_on(Some(" criticals , malicious-deps ")).unwrap(),
            Some("criticals,malicious-deps".to_string())
        );
        assert_eq!(
            normalize_block_on(Some("criticals,criticals")).unwrap(),
            Some("criticals".to_string())
        );
    }

    #[test]
    fn normalize_block_on_rejects_empty_entries() {
        assert!(normalize_block_on(Some("")).is_err());
        assert!(normalize_block_on(Some("   ")).is_err());
        assert!(normalize_block_on(Some(",")).is_err());
        assert!(normalize_block_on(Some("criticals,")).is_err());
        assert!(normalize_block_on(Some("criticals,,other")).is_err());
    }

    fn issue(id: &str, rules: &[&str], slugs: Option<&[&str]>) -> BlockingIssue {
        BlockingIssue {
            id: id.to_string(),
            triggered_by_rules: rules.iter().map(|r| r.to_string()).collect(),
            triggered_by_slugs: slugs.map(|s| s.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn triggered_slug_summary_dedupes_across_issues() {
        let issues = vec![
            issue("issue-1", &["1"], Some(&["criticals"])),
            issue(
                "issue-2",
                &["1", "2"],
                Some(&["criticals", "malicious-deps"]),
            ),
        ];
        assert_eq!(triggered_slug_summary(&issues), "criticals, malicious-deps");
    }

    #[test]
    fn triggered_slug_summary_falls_back_to_rule_ids() {
        let issues = vec![issue("issue-1", &["7"], None)];
        assert_eq!(triggered_slug_summary(&issues), "7");
    }

    #[test]
    fn triggered_slug_summary_is_empty_without_issues() {
        assert_eq!(triggered_slug_summary(&[]), "");
    }

    /// The gate reports the server's pre-pagination total, not the page length,
    /// so a blocked scan with more issues than fit on one page still reports the
    /// real count from a single request.
    #[test]
    fn blocked_count_prefers_the_server_total_over_the_page_length() {
        let response = BlockingRuleResponse {
            block: true,
            blocking_issues: vec![issue("issue-1", &["1"], Some(&["criticals"]))],
            total_pages: 7,
            stats: Some(BlockingRuleStats {
                blocked_issues: 133,
            }),
            status: BLOCKING_RULES_STATUS_COMPLETE.to_string(),
        };
        assert_eq!(response.blocked_count(), 133);
    }

    #[test]
    fn blocked_count_falls_back_to_the_page_length_without_stats() {
        let response = BlockingRuleResponse {
            block: true,
            blocking_issues: vec![
                issue("issue-1", &["1"], Some(&["criticals"])),
                issue("issue-2", &["2"], Some(&["malicious-deps"])),
            ],
            total_pages: 1,
            stats: None,
            status: BLOCKING_RULES_STATUS_COMPLETE.to_string(),
        };
        assert_eq!(response.blocked_count(), 2);
    }

    #[test]
    fn block_on_error_names_each_failure_category() {
        let error = BlockOnError {
            message: Some("Invalid block_on rule(s).".to_string()),
            unknown_slugs: vec!["typo-rule".to_string()],
            inactive_slugs: vec!["old-rule".to_string()],
            non_ci_slugs: vec!["pr-only-rule".to_string()],
        };
        let described = error.describe();
        assert!(described.contains("Unknown blocking rule(s): typo-rule"));
        assert!(described.contains("Rule(s) not scoped to CI: pr-only-rule"));
        assert!(described.contains("Inactive rule(s): old-rule"));
    }

    #[test]
    fn block_on_error_falls_back_to_the_server_message() {
        let error = BlockOnError {
            message: Some("block_on was provided but contained no rule slugs.".to_string()),
            ..Default::default()
        };
        assert_eq!(
            error.describe(),
            "block_on was provided but contained no rule slugs."
        );
    }

    fn scan_with(
        status: &str,
        failed_reason: Option<&str>,
        scan_errors: Vec<utils::api::ScanErrorSummary>,
    ) -> utils::api::ScanResponse {
        utils::api::ScanResponse {
            id: "scan-123".to_string(),
            project: "proj".to_string(),
            repo: None,
            branch: None,
            status: status.to_string(),
            engine: "corgea-blast".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            git_sha: None,
            metadata: None,
            failed_reason: failed_reason.map(|r| r.to_string()),
            scan_errors,
        }
    }

    fn scan_error(
        scan_type: Option<&str>,
        level: Option<&str>,
        location: Option<&str>,
        message: Option<&str>,
    ) -> utils::api::ScanErrorSummary {
        utils::api::ScanErrorSummary {
            scan_type: scan_type.map(|s| s.to_string()),
            level: level.map(|s| s.to_string()),
            location: location.map(|s| s.to_string()),
            message: message.map(|s| s.to_string()),
        }
    }

    #[test]
    fn incomplete_status_is_terminal_not_still_running() {
        // The hang: "incomplete" is terminal, and treating it as running meant
        // polling a finished scan indefinitely.
        assert_eq!(classify_scan_status("incomplete"), ScanState::Failed);
    }

    #[test]
    fn classify_scan_status_covers_the_api_contract() {
        assert_eq!(classify_scan_status("complete"), ScanState::Completed);
        assert_eq!(classify_scan_status("processing"), ScanState::Running);
        assert_eq!(classify_scan_status("scanning"), ScanState::Running);
        assert_eq!(classify_scan_status("incomplete"), ScanState::Failed);
    }

    #[test]
    fn classify_scan_status_ignores_case_and_padding() {
        // `corgea wait` compared against "Complete" while the API sends
        // lowercase, so a finished scan was polled again.
        assert_eq!(classify_scan_status("Complete"), ScanState::Completed);
        assert_eq!(classify_scan_status("  COMPLETE  "), ScanState::Completed);
        assert_eq!(classify_scan_status("Incomplete"), ScanState::Failed);
    }

    #[test]
    fn unknown_status_keeps_waiting_rather_than_failing_the_build() {
        assert_eq!(classify_scan_status("queued"), ScanState::Running);
        assert_eq!(classify_scan_status(""), ScanState::Running);
    }

    #[test]
    fn timeout_rejects_overrides_that_are_not_a_positive_number() {
        // A bad value must not shorten or disable the wait: anything that is
        // not a positive count of seconds falls back to the default.
        let default = DEFAULT_SCAN_TIMEOUT;
        let parse = |raw| parse_timeout(SCAN_TIMEOUT_ENV, raw, default);
        assert_eq!(parse(None), default);
        assert_eq!(parse(Some("")), default);
        assert_eq!(parse(Some("abc")), default);
        assert_eq!(parse(Some("0")), default);
        assert_eq!(parse(Some("-30")), default);
        assert_eq!(parse(Some("1.5")), default);
        assert_eq!(parse(Some(" 90 ")), Duration::from_secs(90));
    }

    #[test]
    fn timeout_defaults_are_the_documented_ones() {
        // The docs promise these two numbers; drifting from them silently is
        // the failure mode worth catching.
        assert_eq!(DEFAULT_SCAN_TIMEOUT, Duration::from_secs(10 * 60 * 60));
        assert_eq!(DEFAULT_BLOCKING_RULES_TIMEOUT, Duration::from_secs(15 * 60));
        assert_eq!(format_timeout(DEFAULT_SCAN_TIMEOUT), "10h");
        assert_eq!(format_timeout(DEFAULT_BLOCKING_RULES_TIMEOUT), "15m");
        assert_eq!(format_timeout(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn budget_reports_what_is_left_and_then_nothing() {
        let spent = WaitBudget::with_timeout(Duration::ZERO);
        assert_eq!(spent.remaining(), None, "a spent budget buys no more reads");

        let budget = WaitBudget::with_timeout(Duration::from_secs(60));
        let remaining = budget.remaining().expect("fresh budget has time left");
        assert!(
            remaining <= Duration::from_secs(60),
            "remaining must count down from the timeout, got {remaining:?}"
        );
    }

    #[test]
    fn scan_failure_reports_reason_and_errors() {
        let scan = scan_with(
            "incomplete",
            Some("Dependency Analysis did not finish."),
            vec![scan_error(
                Some("sca"),
                Some("error"),
                Some("Project-wide"),
                Some("Could not reach the public package registry."),
            )],
        );

        let output = format_scan_failure(&scan);

        assert!(output.contains("scan-123"));
        assert!(output.contains("Dependency Analysis did not finish."));
        assert!(output.contains("[sca @ Project-wide]"));
        assert!(output.contains("Could not reach the public package registry."));
    }

    #[test]
    fn scan_failure_without_reason_still_explains_itself() {
        let output = format_scan_failure(&scan_with("incomplete", None, vec![]));

        assert!(output.contains("did not complete"));
        assert!(!output.contains("Reason:"));
    }

    #[test]
    fn scan_failure_omits_blank_reason() {
        let output = format_scan_failure(&scan_with("incomplete", Some("   "), vec![]));

        assert!(!output.contains("Reason:"));
    }

    #[test]
    fn scan_output_skips_informational_notes() {
        // `info` entries are bookkeeping, not missing results.
        let scan = scan_with(
            "incomplete",
            None,
            vec![
                scan_error(Some("sca"), Some("info"), None, Some("some info")),
                scan_error(Some("sca"), Some("warning"), None, Some("a warning")),
                scan_error(Some("iac"), Some("error"), None, Some("a real error")),
            ],
        );

        let output = format_scan_failure(&scan);

        assert!(output.contains("a real error"));
        assert!(output.contains("a warning"));
        assert!(!output.contains("some info"));
    }

    #[test]
    fn info_only_scan_produces_no_warnings() {
        let scan = scan_with(
            "complete",
            None,
            vec![scan_error(Some("sca"), Some("info"), None, Some("skipped"))],
        );

        assert!(format_scan_warnings(&scan).is_none());
    }

    #[test]
    fn missing_or_unknown_level_is_still_reported() {
        // The server defaults an absent level to "error" and may add levels
        // this client does not know; neither may drop a real failure.
        assert!(scan_error(Some("sca"), None, None, Some("boom")).is_problem());
        assert!(scan_error(Some("sca"), Some("critical"), None, Some("boom")).is_problem());
        assert!(!scan_error(Some("sca"), Some("INFO"), None, Some("fyi")).is_problem());
    }

    #[test]
    fn long_error_lists_are_capped() {
        let errors = (0..25)
            .map(|i| {
                scan_error(
                    Some("sast"),
                    Some("error"),
                    None,
                    Some(&format!("boom {}", i)),
                )
            })
            .collect();

        let output = format_scan_failure(&scan_with("incomplete", None, errors));

        assert!(output.contains("boom 9"));
        assert!(!output.contains("boom 10"));
        assert!(output.contains("...and 15 more"));
    }

    #[test]
    fn completed_scan_with_scanner_errors_produces_warnings() {
        // Warnings on a completed scan are the only signal coverage dropped.
        let scan = scan_with(
            "complete",
            None,
            vec![scan_error(
                Some("sca"),
                Some("error"),
                Some("Project-wide"),
                Some("Dependency Analysis did not finish."),
            )],
        );

        let warnings = format_scan_warnings(&scan).expect("expected warnings");

        assert!(warnings.contains("may be missing results"));
        assert!(warnings.contains("Dependency Analysis did not finish."));
    }

    #[test]
    fn clean_scan_produces_no_warnings() {
        assert!(format_scan_warnings(&scan_with("complete", None, vec![])).is_none());
    }

    #[test]
    fn scan_error_line_survives_missing_fields() {
        assert_eq!(
            format_scan_error_line(&scan_error(None, None, None, None)),
            "  - No details provided."
        );
        assert_eq!(
            format_scan_error_line(&scan_error(None, None, Some("pom.xml"), Some("bad"))),
            "  - [pom.xml] bad"
        );
        assert_eq!(
            format_scan_error_line(&scan_error(Some("sca"), None, None, Some("bad"))),
            "  - [sca] bad"
        );
    }

    #[test]
    fn scan_response_deserializes_without_new_fields() {
        // Older servers do not send failed_reason/scan_errors; the client must
        // still parse their responses.
        let json = r#"{
            "id": "abc",
            "project": "p",
            "repo": null,
            "branch": "main",
            "status": "complete",
            "engine": "corgea-blast",
            "created_at": "2026-01-01T00:00:00Z"
        }"#;

        let scan: utils::api::ScanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(classify_scan_status(&scan.status), ScanState::Completed);
        assert!(scan.failed_reason.is_none());
        assert!(scan.scan_errors.is_empty());
        // `corgea ls --json` serializes from the scan list, which never carries
        // these fields; empty ones there would claim a scan had no problems.
        let round_tripped = serde_json::to_string(&scan).unwrap();
        assert!(!round_tripped.contains("scan_errors"));
        assert!(!round_tripped.contains("failed_reason"));
    }

    #[test]
    fn scan_response_deserializes_null_scan_errors() {
        // The API sends `"scan_errors": null` when there is nothing to report,
        // including on failed scans, where a parse error would hide the reason.
        let json = r#"{
            "id": "abc",
            "project": "p",
            "repo": null,
            "branch": "main",
            "status": "incomplete",
            "engine": "corgea-blast",
            "created_at": "2026-01-01T00:00:00Z",
            "failed_reason": "the scanner ran out of memory",
            "scan_errors": null
        }"#;

        let scan: utils::api::ScanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(classify_scan_status(&scan.status), ScanState::Failed);
        assert!(scan.scan_errors.is_empty());
        assert!(format_scan_failure(&scan).contains("the scanner ran out of memory"));
    }

    #[test]
    fn scan_errors_deserialize_with_fields_missing() {
        // A server that omits any of these must still parse, since an entry we
        // cannot read is an entry whose missing results go unreported.
        let json = r#"{
            "id": "abc",
            "project": "p",
            "repo": null,
            "branch": "main",
            "status": "complete",
            "engine": "corgea-blast",
            "created_at": "2026-01-01T00:00:00Z",
            "scan_errors": [{"message": "pom.xml could not be resolved"}, {}]
        }"#;

        let scan: utils::api::ScanResponse = serde_json::from_str(json).unwrap();

        // No level means the entry counts as a problem, so both are reported.
        let warnings = format_scan_warnings(&scan).unwrap();
        assert!(warnings.contains("  - pom.xml could not be resolved"));
        assert!(warnings.contains("  - No details provided."));
    }
}
