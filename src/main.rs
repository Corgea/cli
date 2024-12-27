mod login;
mod config;
mod scan;
mod wait;
mod list;
mod inspect;
mod cicd;
mod log;
mod scanners {
    pub mod fortify;
    pub mod blast;
}
mod utils{
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
    Login { token: String },
    /// Upload a scan report to Corgea via STDIN or a file
    Upload {
        /// Option path to JSON report to upload
        report: Option<String>,
    },
    /// Scan the current directory. Supports semgrep and snyk.
    Scan {
        /// What scanner to use. Valid options are sempgrep and snyk.
        scanner: Scanner,

        #[arg(short, long)]
        fail_on: Option<String>,
    },
    /// Wait for the latest in progress scan
    Wait {
        scan_id: Option<String>,
    },
    /// List something, by default it lists the scans
    #[command(alias = "ls")]
    List {
        /// An optional args is the user want to list issues
        #[arg(short, long)]
        issues: bool,

        #[arg(long)]
        json: bool
    },
    /// Inspect something something, by default it will inspect a scan
    Inspect {
        /// An optional args is the user want to inspect issues
        #[arg(short, long)]
        issue: bool,

        #[arg(long)]
        json: bool,

        id: String,
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
    let command_args = format!("{:?}", cli);
    if !command_args.contains("json: true") {
        utils::terminal::show_welcome_message();
    }
    let mut corgea_config = Config::load().expect("Failed to load config");
    fn verify_token_and_exit_when_fail (config: &Config) {
        if config.get_token().is_empty() {
            eprintln!("No token set.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
            std::process::exit(1);
        }
        match login::verify_token(config.get_token().as_str(), config.get_url().as_str()) {
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
        Some(Commands::Login { token }) => {
            match login::verify_token(token, corgea_config.get_url().as_str()) {
                Ok(true) => {
                    corgea_config.set_token(token.clone()).expect("Failed to set token");
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
        Some(Commands::Scan { scanner , fail_on }) => {
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
            match scanner {
                Scanner::Snyk => scan::run_snyk(&corgea_config),
                Scanner::Semgrep => scan::run_semgrep(&corgea_config),
                Scanner::Blast => scanners::blast::run(&corgea_config, fail_on.clone())
            }
        }
        Some(Commands::Wait { scan_id }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            wait::run(&corgea_config, scan_id.clone());
        }
        Some(Commands::List { issues , json}) => {
            verify_token_and_exit_when_fail(&corgea_config);
            list::run(&corgea_config, issues, json);
        }
        Some(Commands::Inspect { issue, json, id}) => {
            verify_token_and_exit_when_fail(&corgea_config);
            inspect::run(&corgea_config, issue, json, id)
        }
        None => {
            let _ = Cli::command().print_help();
            println!();
        }
    }
}
