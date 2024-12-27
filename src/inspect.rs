use crate::utils;
use crate::config::Config;



pub fn run(config: &Config, issues: &bool, json: &bool, id: &String) {
    fn print_section(title: &str, value: impl ToString) {
        println!("{:<15}: {}", title, value.to_string());
        println!("-------------------------");
    }
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
        print_section("On Hold", issue_details.issue.on_hold);
        print_section("Hold Reason", issue_details.issue.hold_reason.as_deref().unwrap_or("N/A"));
        print_section("Status", &issue_details.issue.status);

    if let Some(ref explanation) = issue_details.issue.explanation {
        println!("Explanation:\n\n{}\n-------------------------", utils::terminal::format_code(explanation));
    } else {
        println!("Explanation: N/A");
        println!("-------------------------");
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
        print_section("Done", scan_details.processed);
        print_section("Project", &scan_details.project);
    }
}
