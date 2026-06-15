use std::path::Path;

use clap::{Command, CommandFactory, Parser};

use crate::deps::run::DepsSubcommand;

pub const BEGIN_MARKER: &str = "<!-- BEGIN GENERATED CORGEA DEPS SKILL -->";
pub const END_MARKER: &str = "<!-- END GENERATED CORGEA DEPS SKILL -->";

#[derive(Parser)]
#[command(
    name = "corgea deps",
    about = "Offline dependency inventory and policy checks"
)]
struct DepsSkillCli {
    #[command(subcommand)]
    command: DepsSubcommand,
}

struct SkillCommand<'a> {
    path: &'a [&'a str],
    signature: &'a str,
    examples: &'a [&'a str],
}

const COMMANDS: &[SkillCommand<'_>] = &[
    SkillCommand {
        path: &["scan"],
        signature: "corgea deps scan [PATH]",
        examples: &[
            "corgea deps scan --format agent",
            "corgea deps scan --format quiet --fail-on high",
        ],
    },
    SkillCommand {
        path: &["graph"],
        signature: "corgea deps graph [PATH]",
        examples: &[
            "corgea deps graph --format agent",
            "corgea deps graph tests/fixtures/node-app --format json",
        ],
    },
    SkillCommand {
        path: &["explain"],
        signature: "corgea deps explain <PACKAGE> [PATH]",
        examples: &[
            "corgea deps explain lodash --format agent",
            "corgea deps explain left-pad tests/fixtures/node-app --format json",
        ],
    },
    SkillCommand {
        path: &["diff"],
        signature: "corgea deps diff --base <BASE> [PATH]",
        examples: &[
            "corgea deps diff --base origin/main --format json",
            "corgea deps diff --base HEAD . --fail-on-new high",
        ],
    },
    SkillCommand {
        path: &["sbom"],
        signature: "corgea deps sbom [PATH]",
        examples: &[
            "corgea deps sbom --format cyclonedx",
            "corgea deps sbom --format cyclonedx --out bom.json",
        ],
    },
    SkillCommand {
        path: &["policy", "init"],
        signature: "corgea deps policy init [PATH]",
        examples: &[
            "corgea deps policy init",
            "corgea deps policy init --exist-ok --format quiet",
        ],
    },
];

pub fn generated_marked_section() -> String {
    format!(
        "{BEGIN_MARKER}\n{}\n{END_MARKER}",
        generated_deps_skill_section().trim_end()
    )
}

pub fn generated_deps_skill_section() -> String {
    let root = DepsSkillCli::command();
    let mut out = String::new();
    out.push_str("### Deps \u{2014} `corgea deps <command>`\n\n");
    out.push_str(
        "Offline dependency inventory and policy checks. No Corgea token or network required.\n",
    );
    out.push_str(
        "Agent environments default to compact TSV; force output with `--format human|agent|json|quiet`.\n\n",
    );

    for spec in COMMANDS {
        let command = find_command(&root, spec.path);
        let about = command
            .get_about()
            .map(|about| about.to_string())
            .unwrap_or_else(|| "No description".to_string());
        let flags = important_flags(command);

        out.push_str(&format!("- `{}` \u{2014} {}", spec.signature, about));
        if !flags.is_empty() {
            out.push_str(&format!(". Flags: {}", flags.join(", ")));
        }
        out.push('\n');
        out.push_str("  Examples: ");
        out.push_str(
            &spec
                .examples
                .iter()
                .map(|example| format!("`{example}`"))
                .collect::<Vec<_>>()
                .join("; "),
        );
        out.push('\n');
    }

    out.push_str(
        "\nNotes: `deps scan --out-format table|json|sarif` is the report/export selector; do not combine it with `deps scan --format`.\n",
    );
    out
}

pub fn check_skill_file(path: &Path) -> Result<(), String> {
    let current =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let expected = replace_generated_section(&current)?;
    if current == expected {
        return Ok(());
    }

    Err(format!(
        "{} is out of date. Run `cargo run --example deps_skill -- update`.",
        path.display()
    ))
}

pub fn update_skill_file(path: &Path) -> Result<(), String> {
    let current =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let updated = replace_generated_section(&current)?;
    std::fs::write(path, updated).map_err(|e| format!("write {}: {e}", path.display()))
}

fn replace_generated_section(content: &str) -> Result<String, String> {
    let start = content
        .find(BEGIN_MARKER)
        .ok_or_else(|| format!("missing {BEGIN_MARKER}"))?;
    let end = content
        .find(END_MARKER)
        .ok_or_else(|| format!("missing {END_MARKER}"))?;
    if end < start {
        return Err(format!("{END_MARKER} appears before {BEGIN_MARKER}"));
    }

    let after_end = end + END_MARKER.len();
    Ok(format!(
        "{}{}{}",
        &content[..start],
        generated_marked_section(),
        &content[after_end..]
    ))
}

fn find_command<'a>(root: &'a Command, path: &[&str]) -> &'a Command {
    let mut current = root;
    for part in path {
        current = current
            .get_subcommands()
            .find(|command| command.get_name() == *part)
            .unwrap_or_else(|| panic!("missing deps skill command metadata: {part}"));
    }
    current
}

fn important_flags(command: &Command) -> Vec<String> {
    command
        .get_arguments()
        .filter_map(|arg| arg.get_long())
        .filter(|long| *long != "help" && *long != "version")
        .map(|long| format!("`--{long}`"))
        .collect()
}
