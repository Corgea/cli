use crate::config::Config;
use crate::scan::build_scan_url;
use crate::scanners::blast;
use crate::utils;

/// Most recent scan of the project in the current directory.
fn latest_scan_id(config: &Config) -> String {
    let project_name = utils::generic::determine_project_name(None);
    let scans = match utils::api::query_scan_list(
        &config.get_url(),
        Some(&project_name),
        Some(1),
        None,
    ) {
        Ok(result) => result.scans.unwrap_or_default(),
        Err(e) => {
            log::error!(
                    "Unable to query the scan list. Please check your connection and ensure that:\n\
                     - The server URL is reachable.\n\
                     - Your authentication token is valid.\n\n\
                     Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli\n\n\
                     Error details: {}",
                    e
                );
            std::process::exit(1);
        }
    };
    match scans.first() {
        Some(scan) => scan.id.clone(),
        None => {
            log::error!("No scans found for project '{}'.", project_name);
            std::process::exit(1);
        }
    }
}

pub fn run(config: &Config, scan_id: Option<String>, project_id: Option<String>) {
    let scan_id = scan_id.unwrap_or_else(|| latest_scan_id(config));
    // Read the scan itself: the scan list omits failed_reason and scan_errors.
    let scan = match utils::api::get_scan(&config.get_url(), &scan_id) {
        Ok(scan) => scan,
        Err(e) => {
            log::error!(
                "\nUnable to read scan '{}'. Please check your connection and token, then try again.\n\nError details: {}\n",
                scan_id,
                e
            );
            std::process::exit(1);
        }
    };
    let project_name = scan.project.clone();
    // The API reports lowercase statuses, so comparing against "Complete"
    // never matched and finished scans were polled again.
    let state = blast::classify_scan_status(&scan.status);

    let scan_url = build_scan_url(
        &config.get_url(),
        project_id.as_deref(),
        &project_name,
        &scan_id,
    );

    match state {
        blast::ScanState::Running => {
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
        }
        blast::ScanState::Completed => {
            println!("Scan has been processed successfully!");
            if let Some(warnings) = blast::format_scan_warnings(&scan) {
                log::warn!("\n{}\n", warnings);
            }
        }
        // Report the failure rather than claim success or poll forever.
        blast::ScanState::Failed => {
            log::error!("\n\n{}\n", blast::format_scan_failure(&scan));
            println!(
                "\nYou can view the scan details at the following link:\n{}",
                utils::terminal::set_text_color(&scan_url, utils::terminal::TerminalColor::Blue)
            );
            std::process::exit(1);
        }
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
