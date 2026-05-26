mod authorize;
mod cicd;
mod config;
mod inspect;
mod list;
mod log;
mod precheck;
mod scan;
mod setup_hooks;
mod verify_deps;
mod vuln_api;
mod wait;
mod scanners {
    pub mod blast;
    pub mod fortify;
    pub mod parsers;
}
mod utils {
    pub mod api;
    pub mod generic;
    pub mod terminal;
}
mod targets;

use clap::{Args, CommandFactory, Parser, Subcommand};
use config::Config;
use scanners::fortify::parse as fortify_parse;
use std::str::FromStr;

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
        #[arg(help = "API token (if not provided, will use OAuth flow)")]
        token: Option<String>,

        #[arg(
            long,
            help = "The url of the corgea instance to use. defaults to https://www.corgea.app"
        )]
        url: Option<String>,

        #[arg(
            long,
            help = "Scope to use for custom domain (e.g., 'ikea' for ikea.corgea.app). Only used with OAuth flow"
        )]
        scope: Option<String>,
    },
    /// Upload a scan report to Corgea via STDIN or a file
    Upload {
        /// Option path to JSON report to upload
        report: Option<String>,

        #[arg(
            long,
            help = "The name of the Corgea project. Defaults to git repository name if found, otherwise to the current directory name."
        )]
        project_name: Option<String>,
    },
    /// Scan the current directory. Supports blast, semgrep and snyk.
    Scan {
        /// What scanner to use. Valid options are blast, semgrep and snyk.
        #[arg(default_value = "blast")]
        scanner: Scanner,

        #[arg(
            long,
            help = "Fail on (exits with error code 1) a specific severity level . Valid options are CR, HI, ME, LO."
        )]
        fail_on: Option<String>,

        #[arg(long, help = "Only scan uncommitted changes.")]
        only_uncommitted: bool,

        #[arg(
            short,
            long,
            help = "Fail on (exits with error code 1) based on blocking rules defined in the web app."
        )]
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

        #[arg(
            long,
            help = "Output the result to a file in a specific format. Valid options are json, html, sarif, markdown."
        )]
        out_format: Option<String>,

        #[arg(
            short,
            long,
            help = "Output the result to a file. you can use the out_format option to specify the format of the output file."
        )]
        out_file: Option<String>,

        #[arg(
            long,
            help = "Specify specific files, directories, glob patterns, or git selectors to scan. Accepts comma-separated values. Examples: 'src/,pyproject.toml', 'src/**/*.py', 'git:diff=origin/main...HEAD', 'git:staged', 'git:untracked', or '-' to read from stdin (newline-delimited). Use '-0' for NUL-delimited stdin."
        )]
        target: Option<String>,

        #[arg(
            long,
            help = "The name of the Corgea project. Defaults to git repository name if found, otherwise to the current directory name."
        )]
        project_name: Option<String>,
    },
    /// Wait for the latest in progress scan
    Wait { scan_id: Option<String> },
    /// List something, by default it lists the scans
    #[command(alias = "ls")]
    List {
        #[arg(short, long, help = "List issues instead of scans")]
        issues: bool,

        #[arg(
            long,
            short = 'c',
            help = "List SCA (Software Composition Analysis) issues instead of regular issues"
        )]
        sca_issues: bool,

        #[arg(short, long, help = "Specify the scan id to list issues for.")]
        scan_id: Option<String>,

        #[arg(short, long, value_parser = clap::value_parser!(u16))]
        page: Option<u16>,

        #[arg(long, help = "Output the result in JSON format.")]
        json: bool,

        #[arg(long, value_parser = clap::value_parser!(u16), help = "Number of items per page")]
        page_size: Option<u16>,
    },
    /// Inspect something, by default it will inspect a scan
    Inspect {
        /// An optional args is the user want to inspect issues
        #[arg(short, long, help = "Specify if you want to inspect issues.")]
        issue: bool,

        #[arg(long, help = "Output the result in JSON format.")]
        json: bool,

        #[arg(
            long,
            short,
            help = "Display a summary only of the issue in the output (only if --issue is true)."
        )]
        summary: bool,

        #[arg(
            long,
            short,
            help = "Display the fix explanations only in the output (only if --issue is true)."
        )]
        fix: bool,

        #[arg(
            long,
            short,
            help = "Display the diff of the fix only in the output (only if --issue is true)."
        )]
        diff: bool,

        id: String,
    },
    /// Setup a git hook, currently only pre-commit is supported
    SetupHooks {
        #[arg(
            long,
            short,
            help = "Include default config (scan types are pii, secrets and fail on levels are CR, HI, ME, LO)."
        )]
        default_config: bool,
    },
    /// Verify installed dependencies against the registry to flag recently published versions.
    /// Useful as a supply-chain tripwire: any dep whose installed version was published within
    /// the configured threshold will be reported. Currently supports npm and Python.
    Deps {
        #[arg(
            long,
            short = 'e',
            default_value = "all",
            help = "Which ecosystem(s) to verify. Valid options are 'npm', 'python', or 'all' (default)."
        )]
        ecosystem: String,

        #[arg(
            long,
            short = 't',
            default_value = "2d",
            help = "Recency threshold. Any dependency published within this window is flagged. Examples: '2d' (default), '48h', '30m', '1w'. Bare numbers are interpreted as days."
        )]
        threshold: String,

        #[arg(
            long,
            help = "Include development dependencies (default: production only)."
        )]
        include_dev: bool,

        #[arg(
            long,
            short = 'f',
            help = "Exit with a non-zero status code if any recently published dependency is found."
        )]
        fail: bool,

        #[arg(
            long,
            help = "Exit with a non-zero status code if any dependency is unpinned (e.g. package.json without a lockfile, pyproject.toml/Pipfile without a matching lockfile, or unpinned `requirements.txt` lines). Independent of --fail."
        )]
        fail_unpinned: bool,

        #[arg(
            long,
            help = "Output the result as JSON instead of human-readable text."
        )]
        json: bool,

        #[arg(
            long,
            short = 'p',
            help = "Path to the project to verify. Defaults to the current directory."
        )]
        path: Option<String>,

        #[arg(
            long,
            help = "Check each dependency against the Corgea vulnerability database for known CVEs/advisories."
        )]
        check_cve: bool,

        #[arg(
            long,
            requires = "check_cve",
            help = "Exit with a non-zero status code if any known CVE is found. Requires --check-cve. Independent of --fail and --fail-unpinned."
        )]
        fail_cve: bool,
    },
    /// Wrap `npm` install/add commands: verify registry publish times, then run npm.
    ///
    /// Examples:
    ///   corgea npm install axios@^1.0.0 --save-dev
    ///   corgea npm install
    Npm(InstallWrapArgs),
    /// Wrap `yarn` add/install commands: verify registry publish times, then run yarn.
    ///
    /// Examples:
    ///   corgea yarn add lodash
    ///   corgea yarn install
    Yarn(InstallWrapArgs),
    /// Wrap `pnpm` add/install commands: verify registry publish times, then run pnpm.
    ///
    /// Examples:
    ///   corgea pnpm add @types/node@latest
    ///   corgea pnpm install
    Pnpm(InstallWrapArgs),
    /// Wrap `pip install`: verify registry publish times, then run pip.
    ///
    /// Examples:
    ///   corgea pip install requests==2.31.0
    ///   corgea pip install -r requirements.txt
    Pip(InstallWrapArgs),
    /// Wrap `uv` install commands: verify registry publish times, then run uv.
    ///
    /// Examples:
    ///   corgea uv add requests
    ///   corgea uv pip install django==5.0.1
    ///   corgea uv sync
    Uv(InstallWrapArgs),
}

/// Shared flags for `corgea npm` / `yarn` / `pnpm` / `pip` / `uv`.
#[derive(Args, Debug, Clone)]
struct InstallWrapArgs {
    #[arg(
        long,
        short = 't',
        default_value = "2d",
        help = "Recency threshold. Resolved versions younger than this are flagged. Same syntax as `deps --threshold`."
    )]
    threshold: String,

    #[arg(
        long,
        help = "Demote a recent finding from a hard block to a printed warning. The install still runs."
    )]
    no_fail: bool,

    #[arg(
        long,
        help = "Run the verification but never exec the install command."
    )]
    check_only: bool,

    #[arg(
        long,
        help = "Also fail when an unpinned/unverifiable spec (URL, git, file:, editable) is in the install command."
    )]
    fail_unpinned: bool,

    #[arg(
        long,
        help = "Output the result as JSON instead of human-readable text."
    )]
    json: bool,

    /// Arguments forwarded to the package manager (subcommand and package specs).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
enum Scanner {
    Snyk,
    Semgrep,
    Blast,
}

fn parse_threshold_or_exit(threshold: &str) -> std::time::Duration {
    match verify_deps::parse_threshold(threshold) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Invalid --threshold: {}", e);
            std::process::exit(2);
        }
    }
}

fn install_wrap_options(args: &InstallWrapArgs) -> precheck::PrecheckOptions {
    precheck::PrecheckOptions {
        threshold: parse_threshold_or_exit(&args.threshold),
        no_fail: args.no_fail,
        check_only: args.check_only,
        fail_unpinned: args.fail_unpinned,
        json: args.json,
        npm_registry: utils::generic::get_env_var_if_exists("CORGEA_NPM_REGISTRY"),
        pypi_registry: utils::generic::get_env_var_if_exists("CORGEA_PYPI_REGISTRY"),
    }
}

fn run_install_wrap_command(manager: precheck::PackageManager, args: &InstallWrapArgs) {
    let exit_code = precheck::run_install(manager, &args.cmd, install_wrap_options(args));
    std::process::exit(exit_code);
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
    fn verify_token_and_exit_when_fail(config: &Config) {
        if config.get_token().is_empty() {
            eprintln!("No token set.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
            std::process::exit(1);
        }
        utils::api::set_auth_token(&config.get_token());
        match utils::api::verify_token(config.get_url().as_str()) {
            Ok(true) => {}
            Ok(false) => {
                println!("Invalid token provided.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error occurred: {}", e);
                std::process::exit(1);
            }
        }
    }
    match &cli.command {
        Some(Commands::Login { token, url, scope }) => {
            let effective_token = token
                .clone()
                .or_else(|| utils::generic::get_env_var_if_exists("CORGEA_TOKEN"));

            match effective_token {
                Some(token_value) => {
                    let token_source = if token.is_some() {
                        "parameter"
                    } else {
                        "CORGEA_TOKEN environment variable"
                    };
                    utils::api::set_auth_token(&token_value);
                    match utils::api::verify_token(
                        url.as_deref().unwrap_or(corgea_config.get_url().as_str()),
                    ) {
                        Ok(true) => {
                            corgea_config
                                .set_token(token_value.clone())
                                .expect("Failed to set token");
                            if let Some(url) = url {
                                corgea_config
                                    .set_url(url.clone())
                                    .expect("Failed to set url");
                            }
                            println!(
                                "Successfully authenticated to Corgea using token from {}.",
                                token_source
                            )
                        }
                        Ok(false) => println!("Invalid token provided from {}.", token_source),
                        Err(e) => {
                            if e.to_string().contains("401") {
                                println!("Invalid token provided from {}.", token_source);
                                std::process::exit(1);
                            }
                            eprintln!("Error occurred: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                // No token available - use OAuth flow
                None => {
                    if url.is_some() && scope.is_some() {
                        eprintln!("Warning: --url option is ignored when using OAuth flow with --scope. The scope determines the domain.");
                    }

                    match authorize::run(scope.clone(), url.clone()) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("Authorization failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Some(Commands::Upload {
            report,
            project_name,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            match report {
                Some(report) => {
                    if report.ends_with(".fpr") {
                        fortify_parse(&corgea_config, report, project_name.clone());
                    } else {
                        scan::read_file_report(&corgea_config, report, project_name.clone());
                    }
                }
                None => {
                    scan::read_stdin_report(&corgea_config, project_name.clone());
                }
            }
        }
        Some(Commands::Scan {
            scanner,
            fail_on,
            fail,
            only_uncommitted,
            scan_type,
            policy,
            out_format,
            out_file,
            target,
            project_name,
        }) => {
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

            if out_file.is_some() && *scanner != Scanner::Blast {
                eprintln!("out_file is only supported with blast scanner.");
                std::process::exit(1);
            }

            if out_format.is_some() && *scanner != Scanner::Blast {
                eprintln!("out_format is only supported with blast scanner.");
                std::process::exit(1);
            }

            if out_file.is_some() && !out_format.is_some()
                || !out_file.is_some() && out_format.is_some()
            {
                eprintln!("out_file and out_format must be used together.");
                std::process::exit(1);
            }

            if let Some(format) = out_format {
                if !["json", "html", "sarif", "markdown"].contains(&format.as_str()) {
                    eprintln!("Invalid out_format option. Expected one of 'json', 'html', 'sarif', 'markdown'.");
                    std::process::exit(1);
                }
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
                Scanner::Snyk => scan::run_snyk(&corgea_config, project_name.clone()),
                Scanner::Semgrep => scan::run_semgrep(&corgea_config, project_name.clone()),
                Scanner::Blast => scanners::blast::run(
                    &corgea_config,
                    fail_on.clone(),
                    fail,
                    only_uncommitted,
                    scan_type.clone(),
                    policy.clone(),
                    out_format.clone(),
                    out_file.clone(),
                    target.clone(),
                    project_name.clone(),
                ),
            }
        }
        Some(Commands::Wait { scan_id }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            wait::run(&corgea_config, scan_id.clone(), None);
        }
        Some(Commands::List {
            issues,
            json,
            page,
            page_size,
            scan_id,
            sca_issues,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            if *issues && *sca_issues {
                eprintln!("Cannot use both --issues and --sca-issues at the same time.");
                std::process::exit(1);
            }
            if scan_id.is_some() && !*issues && !*sca_issues {
                println!("scan_id option is only supported for issues list command.");
                std::process::exit(1);
            }
            list::run(
                &corgea_config,
                issues,
                sca_issues,
                json,
                page,
                page_size,
                scan_id,
            );
        }
        Some(Commands::Inspect {
            issue,
            json,
            id,
            summary,
            fix,
            diff,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            inspect::run(&corgea_config, issue, json, summary, fix, diff, id)
        }
        Some(Commands::SetupHooks { default_config }) => {
            setup_hooks::setup_pre_commit_hook(*default_config);
        }
        Some(Commands::Deps {
            ecosystem,
            threshold,
            include_dev,
            fail,
            fail_unpinned,
            json,
            path,
            check_cve,
            fail_cve,
        }) => {
            let parsed_ecosystem = match verify_deps::Ecosystem::parse(ecosystem) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(2);
                }
            };
            let parsed_threshold = match verify_deps::parse_threshold(threshold) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Invalid --threshold: {}", e);
                    std::process::exit(2);
                }
            };
            let project_path =
                std::path::PathBuf::from(path.clone().unwrap_or_else(|| ".".to_string()));

            let (vuln_api_url, vuln_api_token) = if *check_cve {
                let resolved_url = corgea_config.get_vuln_api_url();
                let raw_token = corgea_config.get_token();
                let trimmed_token = raw_token.trim().to_string();
                if trimmed_token.is_empty() {
                    (None, None)
                } else {
                    (Some(resolved_url), Some(trimmed_token))
                }
            } else {
                (None, None)
            };

            let opts = verify_deps::VerifyOptions {
                ecosystem: parsed_ecosystem,
                threshold: parsed_threshold,
                include_dev: *include_dev,
                fail: *fail,
                fail_unpinned: *fail_unpinned,
                fail_cve: *fail_cve,
                json: *json,
                path: project_path,
                npm_registry: utils::generic::get_env_var_if_exists("CORGEA_NPM_REGISTRY"),
                pypi_registry: utils::generic::get_env_var_if_exists("CORGEA_PYPI_REGISTRY"),
                check_cve: *check_cve,
                vuln_api_url,
                vuln_api_token,
            };

            match verify_deps::run(&opts) {
                Ok(report) => {
                    if opts.json {
                        verify_deps::report::print_json(&report);
                    } else {
                        verify_deps::report::print_text(&report);
                    }
                    let recent = !report.recent().is_empty();
                    let errors = !report.errors().is_empty();
                    let unpinned = report.has_unpinned();
                    let cve_vulnerable = !report.cve_findings().is_empty();
                    let cve_errored = !report.cve_errors().is_empty();
                    if (recent || errors || cve_vulnerable || cve_errored) && opts.fail {
                        std::process::exit(1);
                    }
                    if unpinned && opts.fail_unpinned {
                        std::process::exit(1);
                    }
                    let has_cves = !report.cve_findings().is_empty();
                    if has_cves && opts.fail_cve {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("deps failed: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Some(Commands::Npm(args)) => {
            run_install_wrap_command(precheck::PackageManager::Npm, args);
        }
        Some(Commands::Yarn(args)) => {
            run_install_wrap_command(precheck::PackageManager::Yarn, args);
        }
        Some(Commands::Pnpm(args)) => {
            run_install_wrap_command(precheck::PackageManager::Pnpm, args);
        }
        Some(Commands::Pip(args)) => {
            run_install_wrap_command(precheck::PackageManager::Pip, args);
        }
        Some(Commands::Uv(args)) => {
            run_install_wrap_command(precheck::PackageManager::Uv, args);
        }
        None => {
            utils::terminal::show_welcome_message();
            let _ = Cli::command().print_help();
            println!();
        }
    }
}
