use crate::utils;
use crate::config::Config;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::error::Error;
use std::thread;
use std::env;
use std::fs;
use uuid::Uuid;



pub fn run(
    config: &Config, 
    fail_on: Option<String>, 
    fail: &bool, 
    only_uncommitted: &bool,
    scan_type: Option<String>,
    policy: Option<String>,
) {
    println!(
        "\nScanning with BLAST 🚀🚀🚀"
    );

    if let Some(scan_type) = &scan_type {
        println!("Running Scan Type: {}", scan_type);
    }
    if let Some(policy) = &policy {
        println!("Including only specified policies for policy scan: {}", policy);
    }
    println!("\n\n");
    let temp_dir = env::temp_dir().join(format!("corgea/tmp/{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");
    let project_name = utils::generic::get_current_working_directory().unwrap_or("unknown".to_string());
    let zip_path = format!("{}/{}.zip", temp_dir.display(), project_name);
    let repo_info = match utils::generic::get_repo_info("./") {
        Ok(info) => info,
        Err(_) => {
            None
        }
    };
    match utils::generic::create_path_if_not_exists(&temp_dir) {
        Ok(_) => (),
        Err(e) => {
            eprintln!(
                "\n\nOops! Something went wrong while creating the directory at '{}'.\nPlease check if you have the necessary permissions or if the path is valid.\nError details:\n{}\n\n", 
                temp_dir.display(), e
            );
            std::process::exit(1);
        }
    }

    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let packaging_thread = thread::spawn(move || {
        utils::terminal::show_loading_message("Packaging your project... ([T]s)", stop_signal_clone);
    });

    if *only_uncommitted {
        match utils::generic::get_untracked_and_modified_files("./") {
            Ok(files) => {
                let files_to_zip: Vec<(std::path::PathBuf, std::path::PathBuf)> = files
                    .iter()
                    .map(|file| (std::path::PathBuf::from(file), std::path::PathBuf::from(file)))
                    .collect();
                println!("\rFiles to be submitted for partial scan:\n");
                for (index, (_, original)) in files_to_zip.iter().enumerate() {
                    println!("{}: {}", index + 1, original.display());
                }
                print!("\n\n");
                if files_to_zip.is_empty() {
                    *stop_signal.lock().unwrap() = true;
                    print!("\r{}", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset));
                    eprintln!(
                        "\n\nOops! It seems there are no uncommitted changes to scan in your project.\nPlease ensure you have made changes that need to be scanned.\n\n", 
                    );
                    std::process::exit(1);
                }
                match utils::generic::create_zip_from_list_of_files(files_to_zip, &zip_path, None) {
                    Ok(_) => {},
                    Err(e) => {
                        *stop_signal.lock().unwrap() = true;
                        print!("\r{}", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset));
                        eprintln!(
                            "\n\nUh-oh! We couldn't package your project at '{}'.\nThis might be due to insufficient permissions, invalid file paths, or a file system error.\nPlease check the directory and try again.\nError details:\n{}\n\n", 
                            zip_path, e
                        );
                        std::process::exit(1);
                    }
                }
            },
            Err(e) => {
                *stop_signal.lock().unwrap() = true;
                print!("\r{}", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset));
                eprintln!(
                    "\n\nFailed to retrieve untracked and modified files.\nError details:\n{}\n\n", 
                    e
                );
                std::process::exit(1);
            }
        }
    } else {
        match utils::generic::create_zip_from_filtered_files(".", None, &zip_path) {
            Ok(_) => { },
            Err(e) => {
                *stop_signal.lock().unwrap() = true;
                print!("\r{}", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset));
                eprintln!(
                    "\n\nUh-oh! We couldn't package your project at '{}'.\nThis might be due to insufficient permissions, invalid file paths, or a file system error.\nPlease check the directory and try again.\nError details:\n{}\n\n", 
                    zip_path, e
                );
                std::process::exit(1);
            }
        }
    }
    *stop_signal.lock().unwrap() = true;
    let _ = packaging_thread.join();
    print!("\r{}Project packaged successfully.\n", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Green));
    println!("\n\nSubmitting scan to Corgea:");
    let scan_id = match utils::api::upload_zip(&zip_path, &config.get_token(), &config.get_url(), &project_name, repo_info, scan_type, policy) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("\n\nOh no! We encountered an issue while uploading the zip file '{}' to the server.\nPlease ensure that:
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
        },
    };

    let _ = utils::generic::delete_directory(&temp_dir);
    print!(
        "\n\nScan has started with ID: {}.\n\nYou can view it populate at the link:\n{}\n\n",
        scan_id,
        utils::terminal::set_text_color(&format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id), utils::terminal::TerminalColor::Green)
    );

    print!(
       "{}",
       utils::terminal::set_text_color("Your scan will continue securely in the Corgea cloud.\nYou can safely exit the process now if you prefer not to wait for it to complete.\n\n", utils::terminal::TerminalColor::Blue)
    );

    wait_for_scan(config, &scan_id);

    let classifications = match report_scan_status(&config.get_url(), &config.get_token(), &project_name) {
        Ok(issues_classes) => {
            println!(
                "\n\nYou can view the scan results at the following link:\n{}",
                utils::terminal::set_text_color(&format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id), utils::terminal::TerminalColor::Green)
            );
            issues_classes
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
    };
    if *fail {
        let blocking_rules = match utils::api::check_blocking_rules(&config.get_url(), &config.get_token(), &scan_id, None) {
            Ok(rules) => rules,
            Err(e) => {
                eprintln!("Failed to check blocking rules: {}", e);
                std::process::exit(1);
            }
        };
        if blocking_rules.block {
            println!("\nExiting with error code 1 due to some issues violating some blocking rules defined for this project.\nfor more details, please check the scan results at the link: {}\nAlternatively, you can run {} to view the issues list on your local machine.",
            utils::terminal::set_text_color(
                &format!("{}/project/{}?scan_id={}", config.get_url(), project_name, scan_id),
                utils::terminal::TerminalColor::Green
            ), 
            utils::terminal::set_text_color(
                &format!("corgea ls -i -s={}", scan_id),
                utils::terminal::TerminalColor::Green
            )
        );
            std::process::exit(1);
        }
    }
    print!("\n\nThank you for using Corgea! 🐕\n\n");
    if let Some(fail_on) = fail_on {
        match fail_on.as_str() {
            "LO" => {
                if classifications.values().any(|&count| count > 0) {
                    std::process::exit(1);
                }
            },
            "ME" => {
                if classifications.get("ME").map_or(false, |&count| count > 0) ||
                   classifications.get("HI").map_or(false, |&count| count > 0) {
                    std::process::exit(1);
                }
            },
            "HI" => {
                if classifications.get("CR").map_or(false, |&count| count > 0) ||
                    classifications.get("HI").map_or(false, |&count| count > 0) {
                    std::process::exit(1);
                }
            },
            "CR" => {
                if let Some(cr_count) = classifications.get("CR") {
                    if *cr_count > 0 {
                        std::process::exit(1);
                    }
                }
            },
            _ => (),
        }
    }


}

pub fn wait_for_scan(config: &Config, scan_id: &str) {
        // Create loading animation
        let stop_signal = Arc::new(Mutex::new(false));

        // Spawn a new thread for the spinner animation
        let stop_signal_clone = Arc::clone(&stop_signal);
        thread::spawn(move || {
            utils::terminal::show_loading_message("Scanning... The Hunt Is On! ([T]s)", stop_signal_clone);
        });
    
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            match check_scan_status(&scan_id, &config.get_url(), &config.get_token()) {
                Ok(true) => {
                    *stop_signal.lock().unwrap() = true;
                    break;
                },
                Ok(false) => { },
                Err(e) => {
                    eprintln!(
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
        print!("{}", utils::terminal::set_text_color("", utils::terminal::TerminalColor::Reset));
        println!(
            "\r╭────────────────────────────────────────────╮\n\
             │ {: <42} │\n\
             │   🎉🎉 Scan Completed Successfully! 🎉🎉   │\n\
             │ {: <42} │\n\
             ╰────────────────────────────────────────────╯\n",
            " ", 
            " "
        );
    

    
    
}


pub fn check_scan_status(scan_id: &str, url: &str, token: &str) -> Result<bool, Box<dyn Error>> {
    match utils::api::get_scan(url, token, scan_id) {
        Ok(scan) => Ok(scan.status == "complete"),
        Err(e) => Err(e)
    }
}


pub fn fetch_and_group_scan_issues(url: &str, token: &str, project: &str) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let issues = match utils::api::get_all_issues(url, token, project, None) {
        Ok(issues) => issues,
        Err(err) => {
            return Err(format!("Failed to fetch scan issues: {}", err).into());
        }
    };
    let mut classification_counts: HashMap<String, usize> = HashMap::new();
    if !issues.is_empty() {
        for issue in &issues {
            *classification_counts.entry(issue.urgency.clone()).or_insert(0) += 1;
        }
    }
    Ok(classification_counts)
}

pub fn report_scan_status(url: &str, token: &str, project: &str) ->  Result<HashMap<String, usize>, Box<dyn std::error::Error>>{
    let classification_counts = match fetch_and_group_scan_issues(url, token, project) {
        Ok(counts) => counts,
        Err(e) => {
            return Err(e);
        }
    };
    let total_issues = classification_counts.values().sum::<usize>();
    println!("Scan Results:-\n");
    println!("{:<20} | {}", "Classification", "Count");
    println!("{:-<20} | {}", "", "");

    let order = vec!["CR", "HI", "ME", "LO"];
    for classification in order {
        if let Some(count) = classification_counts.get(classification) {
            println!("{:<20} | {}", classification, count);
        } else {
            println!("{:<20} | {}", classification, 0);
        }
    }

    println!("{:-<20} | {}", "", "");
    println!("{:<20} | {}", "Total", total_issues);
    return Ok(classification_counts);
}

