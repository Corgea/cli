use crate::utils;
use crate::config::Config;
use crate::scanners::blast;


pub fn run(config: &Config, scan_id: Option<String>) {
    let project_name = match utils::generic::get_current_working_directory() {
        Some(name) => name,
        None => {
            eprintln!("Unable to retrieve the current working directory. Please check your permissions and try again.");
            std::process::exit(1);
        }
    };

    let scans_result = utils::api::query_scan_list(&config.get_url(), &config.get_token(), Some(&project_name), Some(1), None);
    let scans: Vec<utils::api::ScanResponse> = match scans_result {
        Ok(result) => result.scans.unwrap_or_default(),
        Err(e) => {
            eprintln!(
                "Unable to query the scan list. Please check your connection and ensure that:
                - The server URL is reachable.
                - Your authentication token is valid.

                Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli

                Error details: {}", 
                e
            );
            std::process::exit(1);
        }
    };
    let (scan_id, processed) = match scan_id {
        Some(scan_id) => {
            let processed = match blast::check_scan_status(&scan_id, &config.get_url(), &config.get_token()) {
                Ok(processed) => processed,
                Err(_) => {
                    eprintln!(
                        "\nOops! Something went wrong. Please try again later or check your setup.\n"
                    );
                    std::process::exit(1);
                }
            };
            (scan_id.to_string(), processed)
        },
        None => {
            match scans.get(0) {
                Some(scan) => (scan.id.clone(), scan.status == "Complete"),
                None => {
                    eprintln!("Error querying scan list");
                    std::process::exit(1);
                }
            }
        }
    };

    if !processed {
        print!(
            "\n\nWaiting for scan with ID: {}.\n\nYou can view it populate at the link:\n{}\n\n",
            scan_id,
            utils::terminal::set_text_color(&format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id), utils::terminal::TerminalColor::Green)
        );
        print!(
           "{}",
           utils::terminal::set_text_color("Your scan will continue securely in the Corgea cloud.\nYou can safely exit the process now if you prefer not to wait for it to complete.\n\n", utils::terminal::TerminalColor::Blue)
        );
        blast::wait_for_scan(config, &scan_id);
    } else {
        print!("Scan has been processed successfully!\n");
    }

    match blast::report_scan_status(&config.get_url(), &config.get_token(), &project_name) {
        Ok(_) => {
            println!(
                "\n\nYou can view the scan results at the following link:\n{}",
                utils::terminal::set_text_color(&format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id), utils::terminal::TerminalColor::Green)
            );
        },
        Err(e) => {
            eprintln!(
                "\n\n{}\n\n\
                However, the scan results may still be accessible at the following link:\n\n\
                {}\n\n\
                \n\nPlease check your network connection, authentication token, and server URL:\n\n\
                - Server URL: {}\n\
                - Error details: {}\n",
                utils::terminal::set_text_color(
                    &format!("Failed to report the scan status for project: '{}'.", project_name),
                    utils::terminal::TerminalColor::Red
                ),
                utils::terminal::set_text_color(
                    &format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id),
                    utils::terminal::TerminalColor::Blue
                ),
                config.get_url(),
                e
            );
            std::process::exit(1);
        }
    }
}
