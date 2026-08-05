use crate::config::Config;
use crate::targets;
use crate::utils;
use crate::utils::api::SCAIssue;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;

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
    let repo_info = utils::generic::get_repo_info("./").unwrap_or_default();
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
    let scan_url = match &upload_result.project_id {
        Some(pid) => format!("{}/project/{}/?scan_id={}", config.get_url(), pid, scan_id),
        None => format!(
            "{}/project/{}?scan_id={}",
            config.get_url(),
            project_name,
            scan_id
        ),
    };

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

    wait_for_scan(config, &scan_id);
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
    if *fail {
        log::warn!(
            "\n--fail is deprecated: it evaluates every active blocking rule regardless of whether it applies to pull requests or CI. Use --block-on <slug> to name the CI blocking rules this pipeline should enforce."
        );
        let blocking_rules =
            match utils::api::check_blocking_rules(&config.get_url(), &scan_id, None, None) {
                Ok(rules) => rules,
                Err(e) => {
                    log::error!("Failed to check blocking rules: {}", e);
                    std::process::exit(1);
                }
            };
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
        let blocking_rules = match utils::api::check_blocking_rules(
            &config.get_url(),
            &scan_id,
            None,
            Some(block_on),
        ) {
            Ok(rules) => rules,
            Err(e) => {
                log::error!("{}", e);
                std::process::exit(1);
            }
        };
        if blocking_rules.block {
            let issues = collect_blocking_issues(config, &scan_id, block_on, blocking_rules);
            let triggered = triggered_slug_summary(&issues);
            println!(
                "\nExiting with error code 1: {} issue(s) violated the blocking rule(s) {}.\nFor more details, check the scan results at: {}\nAlternatively, run {} to view the issues list on your local machine.",
                issues.len(),
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

    if let Some(out_file) = out_file {
        if let Some(out_format) = out_format {
            let stop_signal = Arc::new(Mutex::new(false));
            let stop_signal_clone = Arc::clone(&stop_signal);
            let results_thread = thread::spawn(move || {
                utils::terminal::show_loading_message(
                    "Generating scan report... ([T]s)",
                    stop_signal_clone,
                );
            });

            if out_format == "json" {
                let issues = match utils::api::get_all_issues(
                    &config.get_url(),
                    &project_name,
                    Some(scan_id.clone()),
                ) {
                    Ok(issues) => issues,
                    Err(e) => {
                        log::error!("\n\nFailed to fetch issues: {}\n\n", e);
                        std::process::exit(1);
                    }
                };
                let sca_issues = match utils::api::get_all_sca_issues(
                    &config.get_url(),
                    &project_name,
                    Some(scan_id.clone()),
                ) {
                    Ok(issues) => issues,
                    Err(e) => {
                        log::error!("\n\nFailed to fetch SCA issues: {}\n\n", e);
                        std::process::exit(1);
                    }
                };
                let json = serde_json::to_string_pretty(&issues).unwrap();
                let sca_json = serde_json::to_string_pretty(&sca_issues).unwrap();
                let report_json = serde_json::to_string_pretty(&classifications).unwrap();
                let results_json = format!(
                    "{{\"issues\": {}, \"sca_issues\": {}, \"report\": {}}}",
                    json, sca_json, report_json
                );
                *stop_signal.lock().unwrap() = true;
                let _ = results_thread.join();
                fs::write(out_file.clone(), results_json).expect("Failed to write JSON file, check if the file path is valid and you have the necessary permissions to write to it.");
                utils::terminal::clear_previous_line();
                println!("\n\nScan results written to: {}\n\n", out_file.clone());
            } else if out_format == "html" {
                let report = match utils::api::get_scan_report(&config.get_url(), &scan_id, None) {
                    Ok(html) => html,
                    Err(e) => {
                        log::error!("\n\nFailed to fetch scan report: {}\n\n", e);
                        std::process::exit(1);
                    }
                };
                *stop_signal.lock().unwrap() = true;
                let _ = results_thread.join();
                fs::write(out_file.clone(), report).expect("\n\nFailed to write HTML file, check if the file path is valid and you have the necessary permissions to write to it.");
                utils::terminal::clear_previous_line();
                println!("\n\nScan report written to: {}\n\n", out_file.clone());
            } else if out_format == "sarif" {
                let report =
                    match utils::api::get_scan_report(&config.get_url(), &scan_id, Some("sarif")) {
                        Ok(sarif) => sarif,
                        Err(e) => {
                            log::error!("\n\nFailed to fetch SARIF report: {}\n\n", e);
                            std::process::exit(1);
                        }
                    };
                *stop_signal.lock().unwrap() = true;
                let _ = results_thread.join();
                fs::write(out_file.clone(), report).expect("\n\nFailed to write SARIF file, check if the file path is valid and you have the necessary permissions to write to it.");
                utils::terminal::clear_previous_line();
                println!("\n\nScan report written to: {}\n\n", out_file.clone());
            } else if out_format == "markdown" {
                let report = match utils::api::get_scan_report(
                    &config.get_url(),
                    &scan_id,
                    Some("markdown"),
                ) {
                    Ok(markdown) => markdown,
                    Err(e) => {
                        log::error!("\n\nFailed to fetch Markdown report: {}\n\n", e);
                        std::process::exit(1);
                    }
                };
                *stop_signal.lock().unwrap() = true;
                let _ = results_thread.join();
                fs::write(out_file.clone(), report).expect("\n\nFailed to write Markdown file, check if the file path is valid and you have the necessary permissions to write to it.");
                utils::terminal::clear_previous_line();
                println!("\n\nScan report written to: {}\n\n", out_file.clone());
            }
        }
    }

    if let Some(sbom_file) = sbom {
        match corgea::deps::report::sbom(std::path::Path::new(".")) {
            Ok(doc) => {
                let json = serde_json::to_string_pretty(&doc).expect("serialize SBOM");
                if let Err(e) = fs::write(&sbom_file, json) {
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

/// Every distinct blocking issue across all pages of the response.
///
/// The endpoint pages at 20 issues by default, so page 1 alone under-reports
/// the count and can omit a rule that only trips on a later page. `first` is
/// the already-fetched page 1.
///
/// A later page that fails to load is warned about and skipped rather than
/// aborting: the scan is already known to be blocked, so turning a transient
/// pagination failure into a lost exit code would be worse than an incomplete
/// summary.
fn collect_blocking_issues(
    config: &Config,
    scan_id: &str,
    block_on: &str,
    first: utils::api::BlockingRuleResponse,
) -> Vec<utils::api::BlockingIssue> {
    let total_pages = first.total_pages;
    let mut seen: HashSet<String> = HashSet::new();
    let mut issues: Vec<utils::api::BlockingIssue> = Vec::new();
    let mut push_unique = |issues: &mut Vec<utils::api::BlockingIssue>,
                           incoming: Vec<utils::api::BlockingIssue>| {
        for issue in incoming {
            if seen.insert(issue.id.clone()) {
                issues.push(issue);
            }
        }
    };

    push_unique(&mut issues, first.blocking_issues);
    for page in 2..=total_pages {
        match utils::api::check_blocking_rules(
            &config.get_url(),
            scan_id,
            Some(page),
            Some(block_on),
        ) {
            Ok(rules) => push_unique(&mut issues, rules.blocking_issues),
            Err(e) => {
                log::warn!(
                    "Could not load page {} of {} of the blocking issues, so the summary below may be incomplete: {}",
                    page,
                    total_pages,
                    e
                );
                break;
            }
        }
    }
    issues
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

pub fn wait_for_scan(config: &Config, scan_id: &str) {
    // Create loading animation
    let stop_signal = Arc::new(Mutex::new(false));

    // Spawn a new thread for the spinner animation
    let stop_signal_clone = Arc::clone(&stop_signal);
    thread::spawn(move || {
        utils::terminal::show_loading_message(
            "Scanning... The Hunt Is On! ([T]s)",
            stop_signal_clone,
        );
    });

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        match check_scan_status(scan_id, &config.get_url()) {
            Ok(true) => {
                *stop_signal.lock().unwrap() = true;
                break;
            }
            Ok(false) => {}
            Err(e) => {
                log::error!(
                    "\n\nUnable to check the scan status for scan ID '{}'.\nPlease verify that:
            - The server URL '{}' is reachable.
            - Your authentication token is valid.
            - The scan ID '{}' exists and is correct.

            Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli
            
            Error details:\n{}",
                    scan_id,
                    config.get_url(),
                    scan_id,
                    e
                );
                std::process::exit(1);
            }
        }
    }
    print!(
        "{}",
        utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset)
    );
    println!(
        "\r╭────────────────────────────────────────────╮\n\
             │ {: <42} │\n\
             │   🎉🎉 Scan Completed Successfully! 🎉🎉   │\n\
             │ {: <42} │\n\
             ╰────────────────────────────────────────────╯\n",
        " ", " "
    );
}

pub fn check_scan_status(scan_id: &str, url: &str) -> Result<bool, Box<dyn Error>> {
    match utils::api::get_scan(url, scan_id) {
        Ok(scan) => Ok(scan.status == "complete"),
        Err(e) => Err(e),
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
    use crate::utils::api::{BlockOnError, BlockingIssue, SCAIssue, SCALocation, SCAPackage};

    fn counts(pairs: &[(&str, usize)]) -> HashMap<String, usize> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
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

    /// A rule that only trips on a later page must still be named, which is the
    /// whole reason the gate aggregates pages before building its message.
    #[test]
    fn triggered_slug_summary_names_rules_from_every_page() {
        let aggregated = vec![
            issue("issue-1", &["1"], Some(&["criticals"])),
            issue("issue-2", &["2"], Some(&["malicious-deps"])),
        ];
        assert_eq!(
            triggered_slug_summary(&aggregated),
            "criticals, malicious-deps"
        );
        // Page 1 in isolation would have blamed only the first rule.
        assert_eq!(triggered_slug_summary(&aggregated[..1]), "criticals");
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
}
