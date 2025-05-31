mod config;
mod scan;
mod wait;
mod list;
mod inspect;
mod cicd;
mod log;
mod setup_hooks;
mod scanners {
    pub mod fortify;
    pub mod blast;
}
mod utils {
    pub mod terminal;
    pub mod generic;
    pub mod api;
}

use std::str::FromStr;
use clap::{Parser, Subcommand, CommandFactory};
use config::Config;
use scanners::fortify::parse as fortify_parse;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(required = false)]
    args: Vec<String>, 
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate to Corgea
    Login { 
        token: String,

        #[arg(long, help = "The url of the corgea instance to use. defaults to https://www.corgea.app")]
        url: Option<String>,
    
     },
    /// Upload a scan report to Corgea via STDIN or a file
    Upload {
        /// Option path to JSON report to upload
        report: Option<String>,
    },
    /// Scan the current directory. Supports blast, semgrep and snyk.
    Scan {
        /// What scanner to use. Valid options are blast, semgrep and snyk.
        #[arg(default_value = "blast")]
        scanner: Scanner,

        #[arg(long, help = "Fail on (exits with error code 1) a specific severity level . Valid options are CR, HI, ME, LO.")]
        fail_on: Option<String>,

        #[arg(long, help = "Only scan uncommitted changes.")]
        only_uncommitted: bool,

        #[arg(short, long, help = "Fail on (exits with error code 1) based on blocking rules defined in the web app.")]
        fail: bool,

        #[arg(
            short,
            long,
            help = "Specify the policies to use by their ids. can use comma separated values to specify multiple policies."
        )]
        policy: Option<String>,

        #[arg(
            short,
            long,
            help = "Specify the scan type. By default, a full scan is run, which includes all scan types. You can choose to run a partial scan by specifying one or more of the following types: base AI blast (blast), malicious code detection (malicious), policy checks (policy), secret detection (secrets), and PII scan (pii). Use comma-separated values to run multiple types, e.g., 'policy,secrets,pii'."
        )]
        scan_type: Option<String>,
    },
    /// Wait for the latest in progress scan
    Wait {
        scan_id: Option<String>,
    },
    /// List something, by default it lists the scans
    #[command(alias = "ls")]
    List {
        #[arg(short, long, help = "List issues instead of scans")]
        issues: bool,

        #[arg(short, long, help = "Specify the scan id to list issues for.")]
        scan_id: Option<String>,

        #[arg(short, long, value_parser = clap::value_parser!(u16))]
        page: Option<u16>,

        #[arg(long, help = "Output the result in JSON format.")]
        json: bool,

        #[arg(long, value_parser = clap::value_parser!(u16), help = "Number of items per page")]
        page_size: Option<u16>
    },
    /// Inspect something something, by default it will inspect a scan
    Inspect {
        /// An optional args is the user want to inspect issues
        #[arg(short, long, help = "Specify if you want to inspect issues.")]
        issue: bool,

        #[arg(long, help = "Output the result in JSON format.")]
        json: bool,

        #[arg(long, short, help = "Display a summary only of the issue in the output (only if --issue is true).")]
        summary: bool,

        #[arg(long, short, help = "Display the fix explanations only in the output (only if --issue is true).")]
        fix: bool,

        #[arg(long, short, help = "Display the diff of the fix only in the output (only if --issue is true).")]
        diff: bool,

        id: String,
    },
    /// Setup a git hook, currently only pre-commit is supported
    SetupHooks {
        #[arg(long, short, help = "Include default config (scan types are pii, secrets and fail on levels are CR, HI, ME, LO).")]
        default_config: bool,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
enum Scanner {
    Snyk,
    Semgrep,
    Blast,
}

impl FromStr for Scanner {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "snyk" => Ok(Scanner::Snyk),
            "semgrep" => Ok(Scanner::Semgrep),
            "blast" => Ok(Scanner::Blast),
            _ => Err("Only snyk, semgrep and blast are valid scanners."),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let mut corgea_config = Config::load().expect("Failed to load config");
    fn verify_token_and_exit_when_fail (config: &Config) {
        if config.get_token().is_empty() {
            eprintln!("No token set.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
            std::process::exit(1);
        }
        match utils::api::verify_token(config.get_token().as_str(), config.get_url().as_str()) {
            Ok(true) => {
                return;
            }
            Ok(false) => {
                println!("Invalid token provided.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
                std::process::exit(1);
            },
            Err(e) => {
                eprintln!("Error occurred: {}", e);
                std::process::exit(1);
            }
        }
    }
    match &cli.command {
        Some(Commands::Login { token, url }) => {
            match utils::api::verify_token(token, url.as_deref().unwrap_or(corgea_config.get_url().as_str())) {
                Ok(true) => {
                    corgea_config.set_token(token.clone()).expect("Failed to set token");
                    if let Some(url) = url {
                        corgea_config.set_url(url.clone()).expect("Failed to set url");
                    }
                    println!("Successfully authenticated to Corgea.")
                }
                Ok(false) => println!("Invalid token provided."),
                Err(e) => eprintln!("Error occurred: {}", e),
            }
        }
        Some(Commands::Upload { report }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            match report {
                Some(report) => {
                    if report.ends_with(".fpr") {
                        fortify_parse(&corgea_config, report);
                    } else {
                        scan::read_file_report(&corgea_config, report);
                    }
                }
                None => {
                    scan::read_stdin_report(&corgea_config);
                }
            }
        }
        Some(Commands::Scan { scanner , fail_on, fail, only_uncommitted, scan_type, policy }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            if let Some(level) = fail_on {
                if *scanner != Scanner::Blast {
                    eprintln!("fail_on is only supported with blast scanner.");
                    std::process::exit(1);
                }
                if !["CR", "HI", "LO", "ME"].contains(&level.as_str()) {
                    eprintln!("Invalid fail_on option. Expected one of 'CR', 'HI', 'ME', 'LO'.");
                    std::process::exit(1);
                }
            }

            if *fail && *scanner != Scanner::Blast {
                eprintln!("fail is only supported with blast scanner.");
                std::process::exit(1);
            }

            if *only_uncommitted && *scanner != Scanner::Blast {
                eprintln!("only_uncommitted is only supported with blast scanner.");
                std::process::exit(1);
            }

            if *fail && fail_on.is_some() {
                eprintln!("fail and fail_on cannot be used together.");
                std::process::exit(1);
            }

            if let Some(scan_type) = scan_type {
                if scan_type.is_empty() {
                    eprintln!("scan_type cannot be empty.");
                    std::process::exit(1);
                }
                let supported_scan_types = ["blast", "malicious", "policy", "secrets", "pii"];
                let scan_types: Vec<_> = scan_type.split(',').map(|t| t.trim()).collect();
                for scan in scan_types {
                    if !supported_scan_types.contains(&scan) {
                        eprintln!("Invalid scan_type: {}. Supported types are: blast, malicious, policy, secrets, pii.", scan);
                        std::process::exit(1);
                    }
                }
            }
            if let Some(policy) = policy {
                if policy.is_empty() {
                    eprintln!("policy cannot be empty.");
                    std::process::exit(1);
                }
                let policy_ids: Vec<_> = policy.split(',').map(|t| t.trim()).collect();
                for policy_id in policy_ids {
                    if policy_id.is_empty() {
                        eprintln!("One of the policy ids passed is empty.");
                        std::process::exit(1);
                    }
                }
                if scan_type.is_none() {
                    eprintln!("\nWarning: you didn't specify an only policy scan, so all other types of scans will run as well.");
                }
            }
            match scanner {
                Scanner::Snyk => scan::run_snyk(&corgea_config),
                Scanner::Semgrep => scan::run_semgrep(&corgea_config),
                Scanner::Blast => scanners::blast::run(&corgea_config, fail_on.clone(), fail, only_uncommitted, scan_type.clone(), policy.clone())
            }
        }
        Some(Commands::Wait { scan_id }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            wait::run(&corgea_config, scan_id.clone());
        }
        Some(Commands::List { issues , json, page, page_size, scan_id}) => {
            verify_token_and_exit_when_fail(&corgea_config);
            if scan_id.is_some() && !*issues {
                println!("scan_id option is only supported for issues list command.");
                std::process::exit(1);
            }
            list::run(&corgea_config, issues, json, page, page_size, scan_id);
        }
        Some(Commands::Inspect { issue, json, id, summary, fix, diff}) => {
            verify_token_and_exit_when_fail(&corgea_config);
            inspect::run(&corgea_config, issue, json, summary, fix, diff, id)
        }
        Some(Commands::SetupHooks { default_config }) => {
            setup_hooks::setup_pre_commit_hook(*default_config);
        }
        None => {
            utils::terminal::show_welcome_message();
            let _ = Cli::command().print_help();
            println!();
        }
    }
}
