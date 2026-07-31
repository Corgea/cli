use crate::config::Config;
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

pub fn run(config: &Config, args: WaitArgs) {
    let WaitArgs {
        scan_id,
        selector,
        project_id,
    } = args;
    // A scan id alone leaves nothing to resolve: everything below keys off
    // the scan, and `blast::check_scan_status`/`report_scan_status` fetch by
    // scan id regardless of whether the project id came along too.
    let resolved = if scan_id.is_some() {
        let name = selector
            .name
            .clone()
            .unwrap_or_else(|| utils::generic::determine_project_name(None));
        utils::api::ResolvedProject {
            // `confirmed`/`tried_label` are only read on the no-scan-id path.
            tried_label: format!("project '{}'", name),
            query_name: name,
            confirmed: false,
        }
    } else {
        utils::api::resolve_project_or_exit(&config.get_url(), &selector)
    };
    let project_name = resolved.query_name.clone();

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
                if resolved.confirmed {
                    log::error!(
                        "Project '{}' has no scans yet. Run 'corgea scan' to start one.",
                        project_name
                    );
                } else {
                    log::error!(
                        "No scans found for {}. Run 'corgea scan', or pass --scan-id.",
                        resolved.tried_label
                    );
                }
                std::process::exit(1);
            }
        },
    };

    let scan_url = match &project_id {
        Some(pid) => format!("{}/project/{}/?scan_id={}", config.get_url(), pid, scan_id),
        None => {
            // The project name is a free-form path segment (canonical names
            // contain `/`, e.g. `bohappdev/dotnet-azure-web-tsb`), so it must
            // be percent-encoded — see `build_scan_url_from_base` in scan.rs.
            let name = project_name.trim().trim_matches('/');
            if name.is_empty() {
                log::error!(
                    "Cannot build the scan URL: no Corgea project resolved. Pass --project-name <NAME>."
                );
                std::process::exit(1);
            }
            format!(
                "{}/project/{}?scan_id={}",
                config.get_url(),
                urlencoding::encode(name),
                scan_id
            )
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
