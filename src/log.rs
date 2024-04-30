use std::env;

pub fn debug(input: &str) {
    if env::var("DEBUG").is_ok() {
        println!("DEBUG: {}", input);
    }
}