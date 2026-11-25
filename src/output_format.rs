use std::fmt;
use std::io::IsTerminal;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Agent,
    Json,
    Quiet,
}

const AGENT_ENV_VARS: [&str; 8] = [
    "AI_AGENT",
    "CODEX_SANDBOX",
    "CLAUDECODE",
    "CLAUDE_CODE",
    "CURSOR_AGENT",
    "CURSOR_TRACE_ID",
    "GEMINI_CLI",
    "PI_AGENT",
];

impl OutputFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "human" => Ok(Self::Human),
            "agent" => Ok(Self::Agent),
            "json" => Ok(Self::Json),
            "quiet" => Ok(Self::Quiet),
            other => Err(format!(
                "unsupported --format: {other}; expected human, agent, json, or quiet"
            )),
        }
    }

    pub fn resolve(explicit: Option<Self>) -> Self {
        Self::resolve_with(explicit, |name| std::env::var(name).ok())
    }

    fn resolve_with(explicit: Option<Self>, env: impl Fn(&str) -> Option<String>) -> Self {
        match explicit {
            Some(format) => format,
            None if agent_env_detected(env) => Self::Agent,
            None => Self::Human,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Json => "json",
            Self::Quiet => "quiet",
        }
    }
}

fn agent_env_detected(env: impl Fn(&str) -> Option<String>) -> bool {
    AGENT_ENV_VARS.iter().any(|name| match env(name) {
        Some(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty() && normalized != "0" && normalized != "false"
        }
        None => false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessOutput {
    LegacyCommand,
    Format(OutputFormat),
}

static PROCESS_OUTPUT: OnceLock<ProcessOutput> = OnceLock::new();

fn process_output() -> ProcessOutput {
    PROCESS_OUTPUT
        .get()
        .copied()
        .unwrap_or(ProcessOutput::LegacyCommand)
}

pub fn set_process_format(format: OutputFormat) {
    let _ = PROCESS_OUTPUT.set(ProcessOutput::Format(format));
}

pub fn decorations_enabled() -> bool {
    match process_output() {
        ProcessOutput::LegacyCommand => true,
        ProcessOutput::Format(OutputFormat::Human) => std::io::stdout().is_terminal(),
        ProcessOutput::Format(_) => false,
    }
}

pub fn colors_enabled() -> bool {
    match process_output() {
        ProcessOutput::LegacyCommand => true,
        ProcessOutput::Format(_) => decorations_enabled() && std::env::var_os("NO_COLOR").is_none(),
    }
}

pub fn write_status(args: fmt::Arguments) {
    let text = args.to_string();
    let text = if decorations_enabled() {
        text
    } else {
        text.replace('\r', "")
    };
    match process_output() {
        ProcessOutput::LegacyCommand | ProcessOutput::Format(OutputFormat::Human) => {
            print!("{text}")
        }
        ProcessOutput::Format(_) => eprint!("{text}"),
    }
}

#[macro_export]
macro_rules! status {
    ($($arg:tt)*) => {
        $crate::output_format::write_status(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! statusln {
    () => {
        $crate::output_format::write_status(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output_format::write_status(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn explicit_format_beats_agent_env() {
        let env = env_of(&[("AI_AGENT", "1")]);
        assert_eq!(
            OutputFormat::resolve_with(Some(OutputFormat::Human), env),
            OutputFormat::Human
        );
    }

    #[test]
    fn agent_env_selects_agent_output() {
        for name in AGENT_ENV_VARS {
            let env = move |key: &str| (key == name).then(|| "1".to_string());
            assert_eq!(
                OutputFormat::resolve_with(None, env),
                OutputFormat::Agent,
                "{name}"
            );
        }
    }

    #[test]
    fn no_agent_env_selects_human_output() {
        assert_eq!(
            OutputFormat::resolve_with(None, env_of(&[])),
            OutputFormat::Human
        );
        for off in ["", "0", "false", " FALSE "] {
            let env = move |key: &str| (key == "CLAUDECODE").then(|| off.to_string());
            assert_eq!(
                OutputFormat::resolve_with(None, env),
                OutputFormat::Human,
                "{off:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_unknown_format() {
        assert_eq!(OutputFormat::parse("json"), Ok(OutputFormat::Json));
        assert!(OutputFormat::parse("table").is_err());
    }
}
