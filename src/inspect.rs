use crate::utils;
use crate::config::Config;
use std::time::SystemTime;
use crate::scanners;
pub fn run(config: &Config, issues: &bool, json: &bool, id: &String) {
    fn print_section(title: &str, value: impl ToString) {
        println!("{:<15}: {}", title, value.to_string());
        println!("-------------------------");
    }
    println!();
    if *issues {
        let issue_details = match utils::api::get_issue(&config.get_url(), &config.get_token(), id) {
            Ok(issue) => issue,
            Err(e) => {
                eprintln!("Failed to fetch issue details for issue ID {} with error:\n{}", id, e);
                if e.to_string().contains("404") {
                    println!("If you're trying to inspect a scan make sure to remove the --issue argument");
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&issue_details).unwrap());
            return;
        }
        print_section("Issue ID", &issue_details.issue.id);
        print_section("Risk", &issue_details.issue.urgency);
        print_section("Classification", &issue_details.issue.classification);
        print_section("File Path", &issue_details.issue.file_path);
        print_section("Line Num", issue_details.issue.line_num);
        print_section("Status", utils::generic::get_status(&issue_details.issue.status));
        let mut input = String::new();

        if let Some(ref explanation) = issue_details.issue.explanation {
            println!("\nTo continue to viewing the issue explanation please press enter, otherwise Ctrl+C to exit.\n");
            std::io::stdin().read_line(&mut input).unwrap();
            utils::terminal::print_with_pagination(&format!(
                "Explanation:\n\n{}\n-------------------------", utils::terminal::format_code(explanation)
            ));

        } 
        if let Some(fix_details) = issue_details.fix {
            println!("\nTo continue to viewing the fix explanation please press enter, otherwise Ctrl+C to exit.\n");
            std::io::stdin().read_line(&mut input).unwrap();
            utils::terminal::print_with_pagination(&format!(
                "Fix Explanation:\n\n{}\n-------------------------", utils::terminal::format_code(&fix_details.explanation)
            ));
            println!("\nTo continue to viewing the diff of the fix please press enter, otherwise Ctrl+C to exit.\n");
            std::io::stdin().read_line(&mut input).unwrap();
            utils::terminal::print_with_pagination(&utils::terminal::format_diff(&fix_details.diff));
        }
    } else {
        let scan_details = match utils::api::get_scan(&config.get_url(), &config.get_token(), id) {
            Ok(details) => details,
            Err(e) => {
                eprintln!("Failed to fetch scan details for scan ID {}: {}", id, e);
                if e.to_string().contains("404") {
                    println!("If you're trying to inspect an issues make sure to pass --issue argument");
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&scan_details).unwrap());
            return;
        }
        print_section("Scan ID", &scan_details.id);
        print_section("Repository", scan_details.repo.as_deref().unwrap_or("N/A"));
        print_section("Branch", scan_details.branch.as_deref().unwrap_or("N/A"));
        let state = if scan_details.mark_failed.unwrap_or(false) {
            utils::generic::get_status("Incomplete")
        } else if scan_details.processed {
            utils::generic::get_status("Complete")
        } else if scan_details.ready_to_process.unwrap_or(true) {
            utils::generic::get_status("Processing")
        } else {
            utils::generic::get_status("Scanning")
        };
        print_section("State", &state);
        print_section("Project", &scan_details.project);
        print_section("Engine", &scan_details.engine);
        let created_at = chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S").to_string();
        print_section("Created At", &created_at);
        match scanners::blast::fetch_and_group_scan_issues(&config.get_url(), &config.get_token(), &scan_details.project) {
            Ok(counts) => {
                let total_issues = counts.values().sum::<usize>();
                let order = vec!["CR", "HI", "ME", "LO"];
                for urgency in order {
                    if let Some(count) = counts.get(urgency) {
                        print_section(&format!("{} Issues", urgency), &count.to_string());
                    }
                }
                print_section("Total Issues", &total_issues);
            },
            Err(_) => { }
        };

    }
}
