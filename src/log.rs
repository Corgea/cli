use crate::config::Config;  

pub fn debug(input: &str) {
    let config = Config::load().expect("Failed to load config");
    if config.get_debug() == 1 {
        println!("DEBUG: {}\n", input);
    }
}