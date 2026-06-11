//! Standalone vuln-api stub for e2e dogfood and local development.

use clap::Parser;
use corgea::vuln_api_stub;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "vuln-api-stub",
    about = "Minimal TCP stub for vuln-api package-check routes"
)]
struct Args {
    /// JSON fixture file (`package_checks`).
    #[arg(long)]
    fixtures: PathBuf,

    /// TCP port to bind (`0` = ephemeral).
    #[arg(long, default_value = "0")]
    port: u16,

    /// Print base URL to stdout and keep serving until SIGTERM.
    #[arg(long)]
    print_url: bool,
}

fn main() {
    let args = Args::parse();
    let stub = if args.port == 0 {
        vuln_api_stub::spawn_from_file(&args.fixtures)
    } else {
        let fixtures = vuln_api_stub::load_from_file(&args.fixtures)
            .unwrap_or_else(|e| panic!("failed to load {}: {e}", args.fixtures.display()));
        vuln_api_stub::spawn_on_port(fixtures, args.port)
    };
    if args.print_url {
        println!("{}", stub.base_url);
    }
    eprintln!("vuln-api stub listening on {}", stub.base_url);
    stub.block();
}
