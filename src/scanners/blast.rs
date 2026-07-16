use crate::config::Config;
use crate::targets;
use crate::utils;
use crate::utils::api::{SCAIssue, ScanResponse};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
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
    only_uncommitted: &bool,
    skip_if_scanned: &bool,
    scan_type: Option<String>,
    policy: Option<String>,
    out_format: Option<String>,
    out_file: Option<String>,
    target: Option<String>,
    exclude: Option<String>,
    project_name: Option<String>,
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

    let project_name = utils::generic::determine_project_name(project_name.as_deref());
    let repo_info = utils::generic::get_repo_info("./").unwrap_or_default();

    if *skip_if_scanned {
        if let Some(ref info) = repo_info {
            // Require both SHA and branch so detached-HEAD / unknown-branch
            // never matches a null-branch scan by accident.
            if let (Some(sha), Some(branch)) = (info.sha.as_deref(), info.branch.as_deref()) {
                if let Ok(resp) = utils::api::query_scan_list(
                    &config.get_url(),
                    Some(&project_name),
                    Some(1),
                    None,
                    Some(branch),
                    Some(sha),
                ) {
                    let scans = resp.scans.unwrap_or_default();
                    let now = Utc::now();
                    if let Some(scan) = find_recent_matching_scan(&scans, sha, Some(branch), now) {
                        let age = parse_created_at(&scan.created_at)
                            .map(|created| format_scan_age(created, now))
                            .unwrap_or_else(|| "recently".to_string());
                        let short_sha: String = sha.chars().take(8).collect();
                        println!(
                            "Skipping scan: commit {} on {} was already scanned {} (scan {}).",
                            short_sha, branch, age, scan.id
                        );
                        return;
                    }
                }
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
        let blocking_rules =
            match utils::api::check_blocking_rules(&config.get_url(), &scan_id, None) {
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

fn find_recent_matching_scan<'a>(
    scans: &'a [ScanResponse],
    local_sha: &str,
    local_branch: Option<&str>,
    now: DateTime<Utc>,
) -> Option<&'a ScanResponse> {
    scans.iter().find(|scan| {
        if !scan.status.eq_ignore_ascii_case("complete") {
            return false;
        }
        if scan.git_sha.as_deref() != Some(local_sha) {
            return false;
        }
        if scan.branch.as_deref() != local_branch {
            return false;
        }
        match parse_created_at(&scan.created_at) {
            // Reject future timestamps (clock skew) and anything >= 24h old.
            Some(created) => created <= now && now - created < Duration::hours(24),
            None => false,
        }
    })
}

fn parse_created_at(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    None
}

fn format_scan_age(created: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let minutes = (now - created).num_minutes().max(0);
    if minutes < 60 {
        format!("{minutes}m ago")
    } else {
        format!("{}h ago", minutes / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::api::{SCAIssue, SCALocation, SCAPackage};

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

    // --skip-if-scanned helpers

    fn scan(
        id: &str,
        sha: Option<&str>,
        branch: Option<&str>,
        status: &str,
        created_at: &str,
    ) -> ScanResponse {
        ScanResponse {
            id: id.to_string(),
            project: "proj".to_string(),
            repo: None,
            branch: branch.map(str::to_string),
            status: status.to_string(),
            engine: "blast".to_string(),
            created_at: created_at.to_string(),
            git_sha: sha.map(str::to_string),
        }
    }

    #[test]
    fn skips_matching_complete_scan_within_24h() {
        let now = Utc::now();
        let created = (now - Duration::hours(3)).to_rfc3339();
        let scans = vec![scan(
            "s1",
            Some("abc123"),
            Some("main"),
            "complete",
            &created,
        )];
        let matched = find_recent_matching_scan(&scans, "abc123", Some("main"), now);
        assert_eq!(matched.map(|s| s.id.as_str()), Some("s1"));
    }

    #[test]
    fn skips_title_case_complete_status() {
        let now = Utc::now();
        let created = (now - Duration::hours(1)).to_rfc3339();
        let scans = vec![scan(
            "s1",
            Some("abc123"),
            Some("main"),
            "Complete",
            &created,
        )];
        assert_eq!(
            find_recent_matching_scan(&scans, "abc123", Some("main"), now).map(|s| s.id.as_str()),
            Some("s1")
        );
    }

    #[test]
    fn does_not_skip_stale_or_exact_24h_scan() {
        let now = Utc::now();
        let stale = (now - Duration::hours(25)).to_rfc3339();
        let exact = (now - Duration::hours(24)).to_rfc3339();
        let scans = vec![
            scan("s1", Some("abc123"), Some("main"), "complete", &stale),
            scan("s2", Some("abc123"), Some("main"), "complete", &exact),
        ];
        assert!(find_recent_matching_scan(&scans, "abc123", Some("main"), now).is_none());
    }

    #[test]
    fn does_not_skip_future_created_at() {
        let now = Utc::now();
        let created = (now + Duration::hours(1)).to_rfc3339();
        let scans = vec![scan(
            "s1",
            Some("abc123"),
            Some("main"),
            "complete",
            &created,
        )];
        assert!(find_recent_matching_scan(&scans, "abc123", Some("main"), now).is_none());
    }

    #[test]
    fn does_not_skip_different_branch_or_sha() {
        let now = Utc::now();
        let created = (now - Duration::hours(1)).to_rfc3339();
        let scans = vec![
            scan("s1", Some("abc123"), Some("other"), "complete", &created),
            scan("s2", Some("ffff"), Some("main"), "complete", &created),
        ];
        assert!(find_recent_matching_scan(&scans, "abc123", Some("main"), now).is_none());
    }

    #[test]
    fn does_not_skip_missing_sha_or_incomplete() {
        let now = Utc::now();
        let created = (now - Duration::hours(1)).to_rfc3339();
        let scans = vec![
            scan("s1", None, Some("main"), "complete", &created),
            scan("s2", Some("abc123"), Some("main"), "scanning", &created),
        ];
        assert!(find_recent_matching_scan(&scans, "abc123", Some("main"), now).is_none());
    }

    #[test]
    fn format_scan_age_uses_minutes_under_one_hour() {
        let now = Utc::now();
        let created = now - Duration::minutes(12);
        assert_eq!(format_scan_age(created, now), "12m ago");
        assert_eq!(format_scan_age(now - Duration::hours(3), now), "3h ago");
    }
}
