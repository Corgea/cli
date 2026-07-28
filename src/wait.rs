use crate::config::Config;
use crate::scanners::blast;
use crate::utils;

pub fn run(
    config: &Config,
    scan_id: Option<String>,
    project_name_override: Option<String>,
    repo_override: Option<String>,
    project_id_override: Option<String>,
) {
    // A scan id plus the project id from the upload response leaves nothing to
    // resolve: everything below keys off the scan, and the id-form URL is
    // already known.
    let resolved: Option<utils::api::ResolvedProject> = if scan_id.is_some()
        && project_id_override.is_some()
    {
        None
    } else {
        match utils::api::resolve_project(
            &config.get_url(),
            project_name_override.as_deref(),
            repo_override.as_deref(),
        ) {
            Ok(resolved) => Some(resolved),
            Err(e) => {
                log::error!(
                        "Unable to resolve the Corgea project. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli\n\n\
                        Error details: {}",
                        e
                    );
                std::process::exit(1);
            }
        }
    };
    let project_name = match &resolved {
        Some(r) => r.query_name.clone(),
        None => project_name_override
            .clone()
            .unwrap_or_else(|| utils::generic::get_current_working_directory().unwrap_or_default()),
    };

    // Only the scan-less path reads the listing.
    let scans: Vec<utils::api::ScanResponse> = if scan_id.is_some() {
        Vec::new()
    } else {
        match utils::api::query_scan_list(&config.get_url(), Some(&project_name), Some(1), None) {
            Ok(result) => result.scans.unwrap_or_default(),
            Err(e) => {
                log::error!(
                    "Unable to query the scan list. Please check your connection and ensure that:
                - The server URL is reachable.
                - Your authentication token is valid.

                Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli

                Error details: {}",
                    e
                );
                std::process::exit(1);
            }
        }
    };
    let (scan_id, processed) = match scan_id {
        Some(scan_id) => {
            let processed = match blast::check_scan_status(&scan_id, &config.get_url()) {
                Ok(processed) => processed,
                Err(_) => {
                    log::error!(
                        "\nOops! Something went wrong. Please try again later or check your setup.\n"
                    );
                    std::process::exit(1);
                }
            };
            (scan_id.to_string(), processed)
        }
        None => match scans.first() {
            Some(scan) => (scan.id.clone(), scan.status == "Complete"),
            None => {
                if resolved.as_ref().map(|r| r.confirmed).unwrap_or(false) {
                    log::error!(
                        "Project '{}' has no scans yet. Run 'corgea scan' to start one.",
                        project_name
                    );
                } else {
                    log::error!(
                        "No scan to wait for: no Corgea project found for {}. Run 'corgea scan', or pass --scan-id / --project-name.",
                        resolved.as_ref().map(|r| r.tried_label.as_str()).unwrap_or_default()
                    );
                }
                std::process::exit(1);
            }
        },
    };

    let project_id =
        project_id_override.or_else(|| resolved.as_ref().and_then(|r| r.project_id.clone()));
    let scan_url = match &project_id {
        Some(pid) => format!("{}/project/{}/?scan_id={}", config.get_url(), pid, scan_id),
        None => {
            // Without an id the name goes into the path; an empty or slash-only
            // name would yield `/project//?scan_id=…`, which resolves nowhere.
            let name = project_name.trim().trim_matches('/');
            if name.is_empty() {
                log::error!(
                    "Cannot build the scan URL: no Corgea project resolved. Pass --project-name <NAME>."
                );
                std::process::exit(1);
            }
            format!("{}/project/{}?scan_id={}", config.get_url(), name, scan_id)
        }
    };

    if !processed {
        print!(
            "\n\nWaiting for scan with ID: {}.\n\nYou can view it populate at the link:\n{}\n\n",
            scan_id,
            utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green)
        );
        print!(
           "{}",
           utils::terminal::set_text_color("Your scan will continue securely in the Corgea cloud.\nYou can safely exit the process now if you prefer not to wait for it to complete.\n\n", utils::terminal::TerminalColor::Blue)
        );
        blast::wait_for_scan(config, &scan_id);
    } else {
        println!("Scan has been processed successfully!");
    }

    match blast::report_scan_status(&config.get_url(), &project_name, &scan_id) {
        Ok(_) => {
            println!(
                "\n\nYou can view the scan results at the following link:\n{}",
                utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Green)
            );
        }
        Err(e) => {
            log::error!(
                "\n\n{}\n\n\
                However, the scan results may still be accessible at the following link:\n\n\
                {}\n\n\
                \n\nPlease check your network connection, authentication token, and server URL:\n\n\
                - Server URL: {}\n\
                - Error details: {}\n",
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
    }
}
