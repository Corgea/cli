use crate::config::Config;
use crate::scan::build_scan_url;
use crate::scanners::blast;
use crate::utils;
use crate::utils::api::ProjectSelector;

#[derive(Default)]
pub struct WaitArgs {
    pub scan_id: Option<String>,
    pub selector: ProjectSelector,
    /// Known project id — `--project-id`, or straight from an upload response.
    /// Clap requires it to be paired with a scan id.
    pub project_id: Option<String>,
}

/// Most recent scan of the resolved project, or a hard exit naming what was
/// tried when it has none.
fn latest_scan_id(config: &Config, resolved: &utils::api::ResolvedProject) -> String {
    let scans = match utils::api::query_scan_list(
        &config.get_url(),
        Some(&resolved.query_name),
        Some(1),
        None,
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
            if resolved.confirmed {
                log::error!(
                    "Project '{}' has no scans yet. Run 'corgea scan' to start one.",
                    resolved.query_name
                );
            } else {
                log::error!(
                    "No scans found for {}. Run 'corgea scan', or pass --scan-id.",
                    resolved.tried_label
                );
            }
            std::process::exit(1);
        }
    }
}

pub fn run(config: &Config, args: WaitArgs) {
    let WaitArgs {
        scan_id,
        selector,
        project_id,
    } = args;

    // A scan id alone leaves nothing to resolve: the scan and issue endpoints
    // both fetch by scan id, so neither /projects nor the listing is dialed.
    let (scan_id, resolved_name) = match scan_id {
        Some(scan_id) => (scan_id, None),
        None => {
            let resolved = utils::api::resolve_project_or_exit(&config.get_url(), &selector);
            let scan_id = latest_scan_id(config, &resolved);
            (scan_id, Some(resolved.query_name))
        }
    };

    // One budget covers this read and the polling that may follow it, so a
    // stalled first read cannot spend the wait on top of it.
    let budget = blast::WaitBudget::start();

    // Read the scan itself: the listing omits failed_reason and scan_errors,
    // which are the only record of why a scan ended badly.
    let scan = match utils::api::get_scan(&config.get_url(), &scan_id, budget.remaining()) {
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

    // A resolved name already drove the listing query, so keep it. Otherwise an
    // explicit `--project-name` (or an uploaded name passed in) wins, then the
    // canonical project the backend returned for this scan, in preference to a
    // name recomputed from the checkout.
    let project_name = resolved_name
        .or_else(|| selector.name.clone())
        .unwrap_or_else(|| {
            let canonical = scan.project.trim();
            if canonical.is_empty() {
                utils::generic::determine_project_name(None)
            } else {
                canonical.to_string()
            }
        });

    // Canonical names contain `/` (e.g. `bohappdev/dotnet-azure-web-tsb`), which
    // `build_scan_url` percent-encodes into a single path segment.
    let url_name = project_name.trim().trim_matches('/');
    if project_id.is_none() && url_name.is_empty() {
        log::error!(
            "Cannot build the scan URL: no Corgea project resolved. Pass --project-name <NAME>."
        );
        std::process::exit(1);
    }
    let scan_url = build_scan_url(&config.get_url(), project_id.as_deref(), url_name, &scan_id);

    // The API reports lowercase statuses, so comparing against "Complete"
    // never matched and finished scans were polled again.
    match blast::classify_scan_status(&scan.status) {
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
            blast::wait_for_scan(config, &scan_id, budget);
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
