mod authorize;
mod cicd;
mod config;
mod images;
mod include_rules;
mod incremental;
mod inspect;
mod list;
mod log;
mod scan;
mod setup_hooks;
mod skill;
mod skip_scan;
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

// `Scan` carries by far the largest flag set of any subcommand, and exactly one
// `Commands` value exists per process — parsed once at startup and destructured
// immediately — so the wasted stack in the other variants costs nothing that
// boxing would recover.
#[allow(clippy::large_enum_variant)]
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

        #[arg(
            long,
            help = "Wait for the uploaded scan to complete and print the results. Without this flag, the command prints the scan page URL so you can track the results."
        )]
        wait: bool,
    },
    /// Scan the current directory. Supports blast, semgrep and snyk.
    Scan {
        /// What scanner to use. Valid options are blast, semgrep and snyk.
        #[arg(default_value = "blast")]
        scanner: Scanner,

        #[arg(
            long,
            help = "Fail (exit code 1) on the listed conditions. Comma-separated list of severity thresholds ('CR', 'HI', 'ME', 'LO' — trips at or above the level) and/or 'malicious' (trips when any dependency in the scan is classified malicious). Examples: 'HI', 'malicious', 'HI,malicious'."
        )]
        fail_on: Option<String>,

        #[arg(long, help = "Only scan uncommitted changes.")]
        only_uncommitted: bool,

        #[arg(
            long = "disable-incremental",
            help = "Analyze every file, even when Corgea could have analyzed only what changed. Scans are incremental by default: the whole project is still uploaded, but only files that changed since this project's last scan are analyzed, and unchanged files keep their existing findings, so the result is a full picture either way. Use this to force a fresh analysis of every file — after changing scanner configuration outside corgea.yaml, for example. Incremental is skipped on its own, with a reason, when there is no git repository or commit to diff from, when the worktree is dirty, when no earlier scan of a clean worktree exists, or when the last scanned commit is missing from a shallow clone; and silently when --only-uncommitted, --target or --exclude already narrow the upload."
        )]
        disable_incremental: bool,

        #[arg(
            long = "metadata",
            value_name = "KEY=VALUE",
            help = "Attach scan-level metadata (repeatable), e.g. --metadata pipeline_url=... --metadata artifact_version=1.2.3"
        )]
        metadata: Vec<String>,

        #[arg(
            short,
            long,
            help = "Deprecated: use --block-on instead. Fail on (exits with error code 1) based on every active blocking rule defined in the web app, regardless of what it applies to."
        )]
        fail: bool,

        #[arg(
            long = "block-on",
            value_name = "SLUG",
            help = "Fail (exit code 1) if the scan violates the named CI blocking rules. Comma-separated rule slugs, e.g. --block-on criticals,malicious-deps. Slugs are shown next to each rule in the web app. Rules must exist, be active, and have 'Applies To' set to CI."
        )]
        block_on: Option<String>,

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
            help = "Exclude files matching glob patterns from the scan. Accepts comma-separated glob patterns. Examples: 'tests/**', 'src/**/*.test.ts,**/*.spec.js', '*.md'."
        )]
        exclude: Option<String>,

        #[arg(
            long = "include",
            value_name = "PATH",
            help = "Force files into the scan that Corgea would otherwise skip as vendored, third-party, generated or test code (repeatable), e.g. --include src/myProj/MyClass.java --include 'vendor/our-fork/**'. Accepts a path, a directory, or a glob pattern, and overrides this command's packaging filters, .gitignore, --exclude and the engine's own classification. Force-included files are analyzed on every run, including incremental ones. Your project's include rules in Corgea apply too; this flag adds to them for one run."
        )]
        include: Vec<String>,

        #[arg(
            long,
            help = "The name of the Corgea project. Defaults to git repository name if found, otherwise to the current directory name."
        )]
        project_name: Option<String>,

        #[arg(
            long,
            value_name = "FILE",
            num_args = 0..=1,
            default_missing_value = "bom.json",
            help = "Generate a CycloneDX SBOM of the project after the scan completes, alongside any report. Optionally specify the output file. Defaults to bom.json."
        )]
        sbom: Option<String>,

        #[arg(
            long = "include-image",
            value_name = "IMAGE:TAG",
            help = "Scan a fully built container image (repeatable), e.g. --include-image myapp:1.2.3 --include-image ghcr.io/acme/api:latest. Each image is exported with docker (or podman), pulled first if it isn't available locally, and uploaded with your project. Corgea scans the images you pass instead of searching your code for base images. Requires container scanning to be enabled for your account."
        )]
        include_image: Vec<String>,

        #[arg(
            long = "skip-if-commit-scanned-recently",
            conflicts_with_all = ["only_uncommitted", "target", "scan_type", "policy", "include_image", "include", "disable_incremental"],
            help = "Do not start a new scan when this commit already has a recent completed scan in the project. That scan then drives the rest of the command — results table, --block-on gate, --out-file report — so the pipeline behaves the same either way. Prints CORGEA_SCAN_SKIPPED=true/false so a pipeline can tell the two apart, and fails if no git commit can be resolved. What can be reused is a scan of the whole commit, and no API tells this run how a past scan was scoped or configured, so the flag is refused with --only-uncommitted, --target, --scan-type, --policy, --include-image, --include and --disable-incremental; with --exclude it warns instead, since a reused scan covers files this run would have skipped."
        )]
        skip_if_commit_scanned_recently: bool,

        #[arg(
            long = "scanned-within",
            value_name = "DURATION",
            requires = "skip_if_commit_scanned_recently",
            help = "How recent a prior scan of the same commit must be for --skip-if-commit-scanned-recently to reuse it, e.g. 90s, 30m, 24h, 7d (a bare number means hours). Defaults to 24h, because unchanged code is still exposed to advisories published since it was last scanned."
        )]
        scanned_within: Option<String>,

        #[arg(
            long = "ignore-dirty-worktree",
            help = "Do not let uncommitted changes stop this run from taking a shortcut. For an incremental scan, the diff is measured against the working tree instead of the last commit, so edited and untracked files are analyzed rather than skipped. With --skip-if-commit-scanned-recently, a recent scan of this commit may be reused even though this worktree is dirty or the prior scan recorded worktree_dirty. A new scan still reports the real dirty status."
        )]
        ignore_dirty_worktree: bool,
    },
    /// Wait for the latest in progress scan
    Wait {
        scan_id: Option<String>,
        #[arg(
            long,
            conflicts_with = "repo",
            help = "Query this exact Corgea project name directly (skips repo auto-resolution)."
        )]
        project_name: Option<String>,
        #[arg(
            long,
            help = "Resolve the project from this repo (org/repo slug or remote URL) instead of the git remote."
        )]
        repo: Option<String>,
        #[arg(
            long,
            requires = "scan_id",
            value_parser = clap::builder::NonEmptyStringValueParser::new(),
            help = "Use this known Corgea project id for the result link, skipping project resolution. Requires a scan id, which is what the id then belongs to."
        )]
        project_id: Option<String>,
    },
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

        #[arg(
            long,
            short = 'q',
            visible_alias = "quality",
            help = "List code quality issues instead of scans"
        )]
        code_quality: bool,

        #[arg(short, long, help = "Specify the scan id to list issues for.")]
        scan_id: Option<String>,

        #[arg(short, long, value_parser = clap::value_parser!(u16))]
        page: Option<u16>,

        #[arg(long, help = "Output the result in JSON format.")]
        json: bool,

        #[arg(long, value_parser = clap::value_parser!(u16), help = "Number of items per page")]
        page_size: Option<u16>,

        #[arg(
            long,
            conflicts_with = "repo",
            help = "Query this exact Corgea project name directly (skips repo auto-resolution)."
        )]
        project_name: Option<String>,

        #[arg(
            long,
            help = "Resolve the project from this repo (org/repo slug or remote URL) instead of the git remote."
        )]
        repo: Option<String>,
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
    /// Manage agent skills from the Corgea registry
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
    /// Offline dependency inventory: scan, graph, explain, diff, sbom, policy
    Deps {
        #[command(subcommand)]
        command: corgea::deps::run::DepsSubcommand,
    },
    /// Look up a package's known advisories before choosing or installing it
    Advisories {
        #[command(subcommand)]
        command: corgea::advisories::AdvisoriesSubcommand,
    },
    /// Wrap `npm` commands: gate install targets on Corgea's vuln verdicts, then run npm.
    Npm(InstallWrapArgs),
    /// Wrap `yarn` commands: gate install targets on Corgea's vuln verdicts, then run yarn.
    Yarn(InstallWrapArgs),
    /// Wrap `pnpm` commands: gate install targets on Corgea's vuln verdicts, then run pnpm.
    Pnpm(InstallWrapArgs),
    /// Wrap `pip` commands: gate install targets on Corgea's vuln verdicts, then run pip.
    Pip(InstallWrapArgs),
    /// Wrap `uv` commands: gate install targets on Corgea's vuln verdicts, then run uv.
    Uv(InstallWrapArgs),
}

/// Shared flags for the install-wrapper subcommands (`corgea npm|pip`).
#[derive(clap::Args, Debug, Clone)]
// Free `-V/--version` into `cmd` so the wrappers forward it to the package
// manager (`corgea --version` still prints the CLI version at the top level).
#[command(disable_version_flag = true)]
struct InstallWrapArgs {
    #[arg(
        long,
        help = "Proceed with the install despite vulnerable or malicious findings. Findings are still printed."
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

/// The vuln-api access policy shared by the install gate and `advisories`:
/// which base URL to hit and whether the Corgea token travels with the
/// request. `has_token` reports whether the user is logged in, independent
/// of the isolation decision that may keep the token off a custom URL.
struct VulnApiAccess {
    base_url: String,
    mode: corgea::precheck::VerdictMode,
    has_token: bool,
}

/// Resolve the shared vuln-api access policy once so both surfaces apply the
/// same base-URL/token-isolation rule (never send a token to an endpoint it
/// does not belong to without explicit opt-in).
fn resolve_vuln_api_access(config: &Config) -> VulnApiAccess {
    let token = config.get_token();
    let token = token.trim();
    let base_url = config::vuln_api_url();
    let custom_vuln_api_url = base_url != config::DEFAULT_VULN_API_URL;
    let send_token_to_custom =
        utils::generic::get_env_var_if_exists("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL")
            .is_some_and(|v| v.trim() == "1");
    VulnApiAccess {
        mode: select_verdict_mode(token, custom_vuln_api_url, send_token_to_custom),
        base_url,
        has_token: !token.is_empty(),
    }
}

fn install_wrap_options(
    args: &InstallWrapArgs,
    config: &Config,
) -> corgea::precheck::PrecheckOptions {
    let access = resolve_vuln_api_access(config);
    corgea::precheck::PrecheckOptions {
        force: args.force,
        json: args.json,
        verdict: Some(corgea::precheck::VerdictConfig {
            base_url: access.base_url,
            mode: access.mode,
            public_hint: Some(public_hint_for(access.has_token)),
        }),
        npm_registry: utils::generic::get_env_var_if_exists("CORGEA_NPM_REGISTRY"),
        pypi_registry: utils::generic::get_env_var_if_exists("CORGEA_PYPI_REGISTRY"),
        recency: config
            .get_recency_gate()
            .then(|| corgea::precheck::RecencyConfig {
                threshold_days: config.get_recency_threshold_days(),
            }),
    }
}

/// Advisories connection options. No token gate — tokenless (public) mode
/// must work — but the same isolation policy as the install wrap.
fn advisories_options(config: &Config) -> corgea::advisories::AdvisoriesOptions {
    let access = resolve_vuln_api_access(config);
    let token = match access.mode {
        corgea::precheck::VerdictMode::Authenticated { token } => Some(token),
        corgea::precheck::VerdictMode::Public => None,
    };
    corgea::advisories::AdvisoriesOptions {
        base_url: access.base_url,
        token,
    }
}

/// Which public-mode disclosure to print. A withheld token is not the same
/// situation as no token, and telling a logged-in user to log in is useless.
/// Only consulted in public mode — authenticated runs print no hint.
fn public_hint_for(has_token: bool) -> corgea::precheck::PublicHint {
    if has_token {
        corgea::precheck::PublicHint::TokenWithheld
    } else {
        corgea::precheck::PublicHint::NoToken
    }
}

/// A token enables authenticated (fail-closed) verdicts — but only against a
/// vuln-api the token belongs to. That means neither a custom URL nor a
/// non-production built-in default, unless the user explicitly opts in to
/// sending the token there.
fn select_verdict_mode(
    token: &str,
    custom_vuln_api_url: bool,
    send_token_to_custom: bool,
) -> corgea::precheck::VerdictMode {
    let trusted_default = !custom_vuln_api_url && config::DEFAULT_VULN_API_URL_IS_PRODUCTION;
    if !token.is_empty() && (trusted_default || send_token_to_custom) {
        corgea::precheck::VerdictMode::Authenticated {
            token: token.to_string(),
        }
    } else {
        corgea::precheck::VerdictMode::Public
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

#[derive(Subcommand, Debug)]
enum SkillCommands {
    /// Install an approved skill into your agent's skills directory
    Install {
        #[arg(help = "Skill name, optionally with a version: name or name@version")]
        name: String,

        #[arg(
            long,
            help = "Agent to install for (e.g. cursor, claude-code, codex). Defaults to the configured default agent."
        )]
        agent: Option<String>,

        #[arg(
            long,
            default_value = "project",
            help = "Installation scope: project or user."
        )]
        scope: String,

        #[arg(
            long,
            help = "Install to a custom directory (overrides --agent and --scope)."
        )]
        dir: Option<String>,

        #[arg(
            long,
            help = "Persist the provided --agent as the default for future installs."
        )]
        set_default: bool,
    },
    /// Configure the default agent used when --agent is not provided
    SetDefaultAgent {
        #[arg(help = "Agent id (e.g. cursor, claude-code, codex).")]
        agent: String,
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
    let mut corgea_config = match Config::load() {
        Ok(config) => config,
        // `config.toml` is a file the user can edit, so a bad one is theirs to
        // fix, not a Rust panic with a backtrace note.
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
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
            wait,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            let result = match report {
                Some(report) => {
                    if report.ends_with(".fpr") {
                        fortify_parse(&corgea_config, report, project_name.clone())
                    } else {
                        scan::read_file_report(&corgea_config, report, project_name.clone())
                    }
                }
                None => scan::read_stdin_report(&corgea_config, project_name.clone()),
            };

            if let Some(result) = result {
                if *wait {
                    wait::run(
                        &corgea_config,
                        wait::WaitArgs {
                            scan_id: Some(result.scan_id.clone()),
                            selector: utils::api::ProjectSelector {
                                name: Some(result.project_name.clone()),
                                ..Default::default()
                            },
                            project_id: result.project_id.clone(),
                        },
                    );
                } else {
                    scan::print_scan_tracking_url(&corgea_config, &result);
                }
            }
        }
        Some(Commands::Scan {
            scanner,
            fail_on,
            fail,
            block_on,
            only_uncommitted,
            disable_incremental,
            metadata,
            scan_type,
            policy,
            out_format,
            out_file,
            target,
            exclude,
            include,
            project_name,
            sbom,
            include_image,
            skip_if_commit_scanned_recently,
            scanned_within,
            ignore_dirty_worktree,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            if let Some(level) = fail_on {
                if *scanner != Scanner::Blast {
                    ::log::error!("fail_on is only supported with blast scanner.");
                    std::process::exit(1);
                }
                if let Err(msg) = scanners::blast::parse_fail_on_tokens(level) {
                    ::log::error!("{}", msg);
                    std::process::exit(1);
                }
            }

            if *fail && *scanner != Scanner::Blast {
                ::log::error!("fail is only supported with blast scanner.");
                std::process::exit(1);
            }

            if block_on.is_some() && *scanner != Scanner::Blast {
                ::log::error!("block-on is only supported with blast scanner.");
                std::process::exit(1);
            }

            if *only_uncommitted && *scanner != Scanner::Blast {
                ::log::error!("only_uncommitted is only supported with blast scanner.");
                std::process::exit(1);
            }

            if *disable_incremental && *scanner != Scanner::Blast {
                ::log::error!("--disable-incremental is only supported with blast scanner.");
                std::process::exit(1);
            }

            if !metadata.is_empty() && *scanner != Scanner::Blast {
                ::log::error!("--metadata is only supported with the blast scanner.");
                std::process::exit(1);
            }

            let metadata_json = match scanners::blast::metadata_json_from_pairs(metadata) {
                Ok(json) => json,
                Err(e) => {
                    ::log::error!("{}", e);
                    std::process::exit(1);
                }
            };

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

            if block_on.is_some() && (*fail || fail_on.is_some()) {
                ::log::error!("block-on cannot be used together with fail or fail_on.");
                std::process::exit(1);
            }

            let block_on = match scanners::blast::normalize_block_on(block_on.as_deref()) {
                Ok(slugs) => slugs,
                Err(msg) => {
                    ::log::error!("{}", msg);
                    std::process::exit(1);
                }
            };

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
            if exclude.is_some() && *scanner != Scanner::Blast {
                ::log::error!("exclude is only supported with blast scanner.");
                std::process::exit(1);
            }

            if !include.is_empty() && *scanner != Scanner::Blast {
                ::log::error!("--include is only supported with the blast scanner.");
                std::process::exit(1);
            }

            if sbom.is_some() && *scanner != Scanner::Blast {
                ::log::error!("sbom is only supported with blast scanner.");
                std::process::exit(1);
            }

            if !include_image.is_empty() && *scanner != Scanner::Blast {
                ::log::error!("--include-image is only supported with the blast scanner.");
                std::process::exit(1);
            }

            let include_images = match images::normalize_image_refs(include_image) {
                Ok(refs) => refs,
                Err(e) => {
                    ::log::error!("{}", e);
                    std::process::exit(1);
                }
            };

            if *skip_if_commit_scanned_recently && *scanner != Scanner::Blast {
                ::log::error!(
                    "skip-if-commit-scanned-recently is only supported with blast scanner."
                );
                std::process::exit(1);
            }

            let skip_recent = if *skip_if_commit_scanned_recently {
                match skip_scan::SkipRecentScan::new(scanned_within.as_deref()) {
                    Ok(skip) => Some(skip),
                    Err(msg) => {
                        ::log::error!("{}", msg);
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            match scanner {
                Scanner::Snyk => scan::run_snyk(&corgea_config, project_name.clone()),
                Scanner::Semgrep => scan::run_semgrep(&corgea_config, project_name.clone()),
                Scanner::Blast => scanners::blast::run(
                    &corgea_config,
                    fail_on.clone(),
                    fail,
                    block_on,
                    only_uncommitted,
                    disable_incremental,
                    ignore_dirty_worktree,
                    metadata_json,
                    scan_type.clone(),
                    policy.clone(),
                    out_format.clone(),
                    out_file.clone(),
                    target.clone(),
                    exclude.clone(),
                    include.clone(),
                    project_name.clone(),
                    sbom.clone(),
                    include_images,
                    skip_recent,
                    ignore_dirty_worktree,
                ),
            }
        }
        Some(Commands::Wait {
            scan_id,
            project_name,
            repo,
            project_id,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            wait::run(
                &corgea_config,
                wait::WaitArgs {
                    scan_id: scan_id.clone(),
                    selector: utils::api::ProjectSelector {
                        name: project_name.clone(),
                        repo: repo.clone(),
                    },
                    project_id: project_id.clone(),
                },
            );
        }
        Some(Commands::List {
            issues,
            json,
            page,
            page_size,
            scan_id,
            sca_issues,
            code_quality,
            project_name,
            repo,
        }) => {
            verify_token_and_exit_when_fail(&corgea_config);
            if [*issues, *sca_issues, *code_quality]
                .iter()
                .filter(|flag| **flag)
                .count()
                > 1
            {
                ::log::error!(
                    "Cannot use more than one of --issues, --sca-issues, and --code-quality at the same time."
                );
                std::process::exit(1);
            }
            if scan_id.is_some() && !*issues && !*sca_issues && !*code_quality {
                println!("scan_id option is only supported for issues list command.");
                std::process::exit(1);
            }
            list::run(
                &corgea_config,
                list::ListArgs {
                    issues: *issues,
                    sca_issues: *sca_issues,
                    code_quality: *code_quality,
                    json: *json,
                    page: *page,
                    page_size: *page_size,
                    scan_id: scan_id.clone(),
                    selector: utils::api::ProjectSelector {
                        name: project_name.clone(),
                        repo: repo.clone(),
                    },
                },
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
        Some(Commands::Skill { command }) => match command {
            SkillCommands::Install {
                name,
                agent,
                scope,
                dir,
                set_default,
            } => {
                verify_token_and_exit_when_fail(&corgea_config);
                skill::run_install(
                    &mut corgea_config,
                    name,
                    agent.clone(),
                    scope,
                    dir.clone(),
                    *set_default,
                );
            }
            SkillCommands::SetDefaultAgent { agent } => {
                skill::run_set_default_agent(&mut corgea_config, agent);
            }
        },
        Some(Commands::Deps { command }) => {
            // Offline: no token / network. Exit code propagates fail-on policy.
            std::process::exit(i32::from(corgea::deps::run::run(command.clone())));
        }
        Some(Commands::Advisories { command }) => {
            std::process::exit(corgea::advisories::run(
                command.clone(),
                advisories_options(&corgea_config),
            ));
        }
        // Install wrappers: no auth gate. Public CVE checks run without a
        // token and fail open on lookup outages.
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
            if let Some(message) = corgea::precheck::pip3_alias_message(&cli.args) {
                eprintln!("{message}");
                std::process::exit(1);
            }
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

    #[test]
    fn verdict_mode_selection_matrix() {
        use corgea::precheck::VerdictMode;

        // Built-in default: authenticated only when that default is production.
        let default_mode = select_verdict_mode("token", false, false);
        if config::DEFAULT_VULN_API_URL_IS_PRODUCTION {
            assert_eq!(
                default_mode,
                VerdictMode::Authenticated {
                    token: "token".to_string()
                }
            );
        } else {
            assert_eq!(default_mode, VerdictMode::Public);
        }
        assert_eq!(select_verdict_mode("", false, false), VerdictMode::Public);
        assert_eq!(
            select_verdict_mode("token", true, false),
            VerdictMode::Public
        );
        assert_eq!(
            select_verdict_mode("token", true, true),
            VerdictMode::Authenticated {
                token: "token".to_string()
            }
        );
    }

    /// A token reaches only an endpoint it belongs to. A custom vuln-api is
    /// not one, so it stays public and says so — the withheld hint exists for
    /// exactly that cohort. See COR-1549.
    #[test]
    fn withheld_token_selects_public_mode_and_withheld_hint() {
        use corgea::precheck::{PublicHint, VerdictMode};

        // token + custom URL + no opt-in
        assert_eq!(
            select_verdict_mode("token", true, false),
            VerdictMode::Public
        );
        assert_eq!(public_hint_for(true), PublicHint::TokenWithheld);
        // No token is a different situation with different advice.
        assert_eq!(public_hint_for(false), PublicHint::NoToken);
    }

    /// The opt-in is what makes an otherwise untrusted endpoint eligible for
    /// the token — and it never manufactures a token that does not exist.
    #[test]
    fn opt_in_enables_authenticated_for_untrusted_endpoints() {
        use corgea::precheck::VerdictMode;

        assert_eq!(
            select_verdict_mode("token", true, true),
            VerdictMode::Authenticated {
                token: "token".to_string()
            }
        );
        assert_eq!(select_verdict_mode("", true, true), VerdictMode::Public);
    }
}
