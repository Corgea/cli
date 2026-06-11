mod authorize;
mod cicd;
mod config;
mod inspect;
mod list;
mod log;
mod scan;
mod setup_hooks;
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

use clap::{CommandFactory, Parser, Subcommand};
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
    /// Offline dependency inventory: scan, graph, explain, diff, sbom, policy
    Deps {
        #[command(subcommand)]
        command: corgea::deps::run::DepsSubcommand,
    },
    /// Wrap `npm` commands: verify install targets' publish recency, then run npm.
    Npm(InstallWrapArgs),
    /// Wrap `yarn` commands: verify install targets' publish recency, then run yarn.
    Yarn(InstallWrapArgs),
    /// Wrap `pnpm` commands: verify install targets' publish recency, then run pnpm.
    Pnpm(InstallWrapArgs),
    /// Wrap `pip` commands: verify install targets' publish recency, then run pip.
    Pip(InstallWrapArgs),
    /// Wrap `uv` commands: verify install targets' publish recency, then run uv.
    Uv(InstallWrapArgs),
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

/// Shared flags for the install-wrapper subcommands (`corgea npm|yarn|pnpm|pip|uv`).
#[derive(clap::Args, Debug, Clone)]
struct InstallWrapArgs {
    #[arg(
        long,
        short = 't',
        default_value = "2d",
        value_parser = corgea::verify_deps::parse_threshold,
        help = "Recency threshold. Resolved versions younger than this are blocked. e.g. '2d', '12h'."
    )]
    threshold: std::time::Duration,

    #[arg(
        long,
        help = "Demote a recency block to a printed warning. The install still runs."
    )]
    no_fail: bool,

    #[arg(
        long,
        help = "Proceed with the install despite vulnerable, unverifiable, or recent findings. Findings are still printed."
    )]
    force: bool,

    #[arg(
        long,
        help = "Output the result as JSON instead of human-readable text."
    )]
    json: bool,

    /// Arguments forwarded to the package manager (subcommand and package specs).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

fn install_wrap_options(
    args: &InstallWrapArgs,
    config: &Config,
) -> corgea::precheck::PrecheckOptions {
    let token = config.get_token();
    let token = token.trim();
    let verdict = if token.is_empty() {
        None
    } else {
        Some(corgea::precheck::VerdictConfig {
            base_url: config.get_vuln_api_url(),
            token: token.to_string(),
        })
    };
    corgea::precheck::PrecheckOptions {
        threshold: args.threshold,
        no_fail: args.no_fail,
        force: args.force,
        json: args.json,
        verdict,
        npm_registry: utils::generic::get_env_var_if_exists("CORGEA_NPM_REGISTRY"),
        pypi_registry: utils::generic::get_env_var_if_exists("CORGEA_PYPI_REGISTRY"),
    }
}

fn run_install_wrap_command(
    manager: corgea::precheck::PackageManager,
    args: &InstallWrapArgs,
    config: &Config,
) {
    let code =
        corgea::precheck::run_install(manager, &args.cmd, install_wrap_options(args, config));
    std::process::exit(code);
}

/// Initialize the global logger.
///
/// `CORGEA_DEBUG=1` (env var or config file) raises the default verbosity to
/// `debug`; `RUST_LOG` always takes precedence when set. Records are formatted
/// message-only (no timestamp or level prefix) so CLI errors and warnings read
/// exactly as they did when they were `eprintln!`s.
fn init_logging(config: &Config) {
    use std::io::Write;
    let default_level = default_log_level(config.get_debug());
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();
}

/// Map the resolved debug flag to env_logger's default filter level.
/// `RUST_LOG` still overrides this at runtime (env_logger precedence).
fn default_log_level(debug_flag: i8) -> &'static str {
    if debug_flag == 1 {
        "debug"
    } else {
        "info"
    }
}

fn main() {
    let cli = Cli::parse();
    let mut corgea_config = Config::load().expect("Failed to load config");
    init_logging(&corgea_config);
    fn verify_token_and_exit_when_fail(config: &Config) {
        if config.get_token().is_empty() {
            ::log::error!("No token set.\nPlease run 'corgea login' to authenticate.\nFor more info checkout our docs at Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli");
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
                ::log::error!("Error occurred: {}", e);
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
                            ::log::error!("Error occurred: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                // No token available - use OAuth flow
                None => {
                    if url.is_some() && scope.is_some() {
                        ::log::warn!("Warning: --url option is ignored when using OAuth flow with --scope. The scope determines the domain.");
                    }

                    match authorize::run(scope.clone(), url.clone()) {
                        Ok(()) => {}
                        Err(e) => {
                            ::log::error!("Authorization failed: {}", e);
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
                    ::log::error!("fail_on is only supported with blast scanner.");
                    std::process::exit(1);
                }
                if !["CR", "HI", "LO", "ME"].contains(&level.as_str()) {
                    ::log::error!(
                        "Invalid fail_on option. Expected one of 'CR', 'HI', 'ME', 'LO'."
                    );
                    std::process::exit(1);
                }
            }

            if *fail && *scanner != Scanner::Blast {
                ::log::error!("fail is only supported with blast scanner.");
                std::process::exit(1);
            }

            if *only_uncommitted && *scanner != Scanner::Blast {
                ::log::error!("only_uncommitted is only supported with blast scanner.");
                std::process::exit(1);
            }

            if out_file.is_some() && *scanner != Scanner::Blast {
                ::log::error!("out_file is only supported with blast scanner.");
                std::process::exit(1);
            }

            if out_format.is_some() && *scanner != Scanner::Blast {
                ::log::error!("out_format is only supported with blast scanner.");
                std::process::exit(1);
            }

            if out_file.is_some() && !out_format.is_some()
                || !out_file.is_some() && out_format.is_some()
            {
                ::log::error!("out_file and out_format must be used together.");
                std::process::exit(1);
            }

            if let Some(format) = out_format {
                if !["json", "html", "sarif", "markdown"].contains(&format.as_str()) {
                    ::log::error!("Invalid out_format option. Expected one of 'json', 'html', 'sarif', 'markdown'.");
                    std::process::exit(1);
                }
            }

            if *fail && fail_on.is_some() {
                ::log::error!("fail and fail_on cannot be used together.");
                std::process::exit(1);
            }

            if let Some(scan_type) = scan_type {
                if scan_type.is_empty() {
                    ::log::error!("scan_type cannot be empty.");
                    std::process::exit(1);
                }
                let supported_scan_types = ["blast", "malicious", "policy", "secrets", "pii"];
                let scan_types: Vec<_> = scan_type.split(',').map(|t| t.trim()).collect();
                for scan in scan_types {
                    if !supported_scan_types.contains(&scan) {
                        ::log::error!("Invalid scan_type: {}. Supported types are: blast, malicious, policy, secrets, pii.", scan);
                        std::process::exit(1);
                    }
                }
            }
            if let Some(policy) = policy {
                if policy.is_empty() {
                    ::log::error!("policy cannot be empty.");
                    std::process::exit(1);
                }
                let policy_ids: Vec<_> = policy.split(',').map(|t| t.trim()).collect();
                for policy_id in policy_ids {
                    if policy_id.is_empty() {
                        ::log::error!("One of the policy ids passed is empty.");
                        std::process::exit(1);
                    }
                }
                if scan_type.is_none() {
                    ::log::warn!("\nWarning: you didn't specify an only policy scan, so all other types of scans will run as well.");
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
                ::log::error!("Cannot use both --issues and --sca-issues at the same time.");
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
        Some(Commands::Deps { command }) => {
            // Offline: no token / network. Exit code propagates fail-on policy.
            std::process::exit(i32::from(corgea::deps::run::run(command.clone())));
        }
        // Install wrappers: no hard auth gate — the recency check is offline,
        // and a token (when present) additionally enables the vuln-api verdict.
        // Tokenless degrades to recency-only with a login prompt.
        Some(Commands::Npm(args)) => {
            run_install_wrap_command(corgea::precheck::PackageManager::Npm, args, &corgea_config)
        }
        Some(Commands::Yarn(args)) => {
            run_install_wrap_command(corgea::precheck::PackageManager::Yarn, args, &corgea_config)
        }
        Some(Commands::Pnpm(args)) => {
            run_install_wrap_command(corgea::precheck::PackageManager::Pnpm, args, &corgea_config)
        }
        Some(Commands::Pip(args)) => {
            run_install_wrap_command(corgea::precheck::PackageManager::Pip, args, &corgea_config)
        }
        Some(Commands::Uv(args)) => {
            run_install_wrap_command(corgea::precheck::PackageManager::Uv, args, &corgea_config)
        }
        None => {
            utils::terminal::show_welcome_message();
            let _ = Cli::command().print_help();
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_level_maps_debug_flag() {
        assert_eq!(default_log_level(1), "debug");
        assert_eq!(default_log_level(0), "info");
        assert_eq!(default_log_level(2), "info"); // only ==1 means debug
        assert_eq!(default_log_level(-1), "info");
    }
}
