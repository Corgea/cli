mod login;
mod config;
mod scan;
mod cicd;
mod log;
mod scanners {
    pub mod fortify;
}

use std::str::FromStr;
use clap::{Parser, Subcommand};
use config::Config;
use scanners::fortify::parse as fortify_parse;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
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
        scanner: Scanner
    },
}

#[derive(Subcommand, Debug, Clone)]
enum Scanner {
    Snyk,
    Semgrep,
}

impl FromStr for Scanner {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "snyk" => Ok(Scanner::Snyk),
            "semgrep" => Ok(Scanner::Semgrep),
            _ => Err("Only snyk and semgrep are valid scanners."),
        }
    }
}

fn check_token_set(config: &Config) {
    if config.get_token().is_empty() {
        eprintln!("No token set. Please run 'corgea login' to authenticate.");
        std::process::exit(1);
    }
}

fn main() {
    let cli = Cli::parse();
    let mut corgea_config = Config::load().expect("Failed to load config");

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
            check_token_set(&corgea_config);

            match login::verify_token(corgea_config.get_token().as_str(), corgea_config.get_url().as_str()) {
                Ok(true) => {
                    match report {
                        Some(report) => {
                            if report.ends_with(".fpr") {
                                fortify_parse(&corgea_config, report);
                            } else {
                                scan::read_file_report(&corgea_config, report);
                            }
                        }
                        None => {
                            // Read from stdin
                            scan::read_stdin_report(&corgea_config);
                        }
                    }
                }
                Ok(false) => println!("Invalid token provided. Please run 'corgea login' to authenticate."),
                Err(e) => eprintln!("Error occurred: {}", e)
            }
        }
        Some(Commands::Scan { scanner }) => {
            check_token_set(&corgea_config);

            match scanner {
                Scanner::Snyk => scan::run_snyk(&corgea_config),
                Scanner::Semgrep => scan::run_semgrep(&corgea_config)
            }
        }
        None => {
            // println!("Default subcommand");
        }
    }
}
