use sentry::{self, configure_scope};
use std::env;
use crate::utils::api::User;

pub fn init_error_reporting() -> sentry::ClientInitGuard {
    let sentry_dsn = env!("SENTRY_DSN");
    let guard = sentry::init((sentry_dsn, sentry::ClientOptions {
        release: sentry::release_name!(),
        traces_sample_rate: 1.0,
        // Capture user IPs and potentially sensitive headers when using HTTP server integrations
        // see https://docs.sentry.io/platforms/rust/data-management/data-collected for more info
        send_default_pii: true,
        ..Default::default()
      }));

    attach_cli_args_to_sentry_scope();
    set_custom_panic_hook();
    guard
}

pub fn log_error(error: &str, should_log_to_console: Option<bool>) {

    sentry::capture_message(error, sentry::Level::Error);
    if should_log_to_console.unwrap_or(true) {
        eprintln!(
            "Unexpected error occurred: {}\nDon't worry, we've already reported it to our team.",
            error
        );
    }

}

pub fn log_warning(warning: &str, should_log_to_console: Option<bool>) {
    sentry::capture_message(warning, sentry::Level::Warning);
    if should_log_to_console.unwrap_or(true) {
        eprintln!("Warning: {}", warning);
    }
}



pub fn wait_for_sentry_to_flush() {
    if let Some(client) = sentry::Hub::current().client() {
        client.flush(Some(std::time::Duration::from_secs(3)));
    }
}

pub fn log_info(info: &str, should_log_to_console: Option<bool>) {
    sentry::capture_message(info, sentry::Level::Info);
    if should_log_to_console.unwrap_or(true) {
        eprintln!("Info: {}", info);
    }
}

fn attach_cli_args_to_sentry_scope() {
    let args: Vec<String> = env::args().collect();
    let full_cmd = args.join(" ");

    configure_scope(|scope| {
        scope.set_extra("cli_command", full_cmd.into());
    });
}

fn set_custom_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let panic_message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.as_str()
        } else {
            "Unknown panic message"
        };

        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        let mut is_custom_error = false;
        let mut cleaned_message = String::new();
        if panic_message.contains("[CUSTOM]") {
            cleaned_message = panic_message.replace("[CUSTOM]", "");
            is_custom_error = true;
        }
        if is_custom_error {
            eprintln!("Error: {cleaned_message}\nDon't worry, we've already reported it to our team.");
        } else {
            eprintln!("Fatal error occurred at {location}: {cleaned_message}\nDon't worry, we've already reported it to our team.");
        }

        sentry::with_scope(|scope| {
            scope.set_level(Some(sentry::Level::Fatal));
            scope.set_extra("panic_location", location.clone().into());
        }, || {
            sentry::capture_message(
                &format!("Panic occurred: {cleaned_message}"),
                sentry::Level::Fatal,
            );
        });

        wait_for_sentry_to_flush();

        std::process::exit(1);
    }));
}

pub fn attach_user_info_to_error_reporting(user_info: &User) {
    configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(user_info.id.to_string()),
            email: Some(user_info.email.clone()),
            username: Some(user_info.name.clone()),
            ..Default::default()
        }));
        
        // Also set company info as extra context
        scope.set_extra("company_id", user_info.company.id.into());
        scope.set_extra("company_name", user_info.company.name.clone().into());
    });
}