use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::{thread, time};
use std::sync::{Arc, Mutex};
use crate::utils;

pub fn show_progress_bar(progress: f32) -> () {
    let total_bar_length = 50;
    if progress == -1.0 {
        print!("\r{}", " ".repeat(50));
        io::stdout().flush().unwrap();
        return;
    }
    let filled_length = (progress * total_bar_length as f32).round() as usize;
    let empty_length = total_bar_length - filled_length;

    let bar = format!(
        "[{}{}] {:.2}%",
        "=".repeat(filled_length),
        " ".repeat(empty_length),
        progress * 100.0
    );

    print!("\r{}", bar);
    io::stdout().flush().unwrap();
}

pub fn show_loading_message(message: &str, stop_signal: Arc<Mutex<bool>>) {
    let spinner = vec!["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];
    let spinner_colors = vec![Color::Cyan, Color::Magenta, Color::Yellow, Color::Green];
    let start_time = time::Instant::now();
    let mut i = 0;
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    print!("{} ", message);
    io::stdout().flush().unwrap();
    loop {
        stdout.set_color(ColorSpec::new().set_fg(Some(spinner_colors[i % spinner_colors.len()])).set_bg(Some(Color::Black))).unwrap();
        let message = message.replace("[T]", &format!("{:.0}", start_time.elapsed().as_secs()));
        print!("\r[{}] {}", spinner[i % spinner.len()], message);
        io::stdout().flush().unwrap();

        // Sleep for a bit before updating the spinner
        thread::sleep(time::Duration::from_millis(100));

        // Check for stop signal
        if *stop_signal.lock().unwrap() {
            break;
        }

        i = (i + 1) % spinner.len();
    }
    io::stdout().flush().unwrap();
    stdout.reset().unwrap();
}



pub fn set_text_color(txt: &str, color: TerminalColor) -> String {
    let color_code = match color {
        TerminalColor::Red => "\x1b[31m",
        TerminalColor::Green => "\x1b[32m",
        TerminalColor::Blue => "\x1b[34m",
        TerminalColor::Reset => "\x1b[0m",
    };
    return format!("{}{}{}", color_code, txt, "\x1b[0m");
}

pub fn show_welcome_message() {
    let corgea_text = r#"
      /$$$$$$                                                   
     /$$__  $$                                                  
    | $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$ 
    | $$       /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ |____  $$
    | $$      | $$  \ $$| $$  \__/| $$  \ $$| $$$$$$$$  /$$$$$$$
    | $$    $$| $$  | $$| $$      | $$  | $$| $$_____/ /$$__  $$
    |  $$$$$$/|  $$$$$$/| $$      |  $$$$$$$|  $$$$$$$|  $$$$$$$
     \______/  \______/ |__/       \____  $$ \_______/ \_______/
                                   /$$  \ $$                    
                                  |  $$$$$$/                    
                                   \______/                     
    
    "#;
    println!("{}", set_text_color(corgea_text, TerminalColor::Green));
} 

pub fn print_ascii_art() -> String {
    let corgea_title = r#"
  ____                                
 / ___| ___   _ __  __ _   ___   __ _ 
| |    / _ \ | '__|/ _` | / _ \ / _` |
| |___| (_) || |  | (_| ||  __/| (_| |
 \____|\___/ |_|   \__, | \___| \__,_|
                   |___/              
"#;
    let dog_art = r#"
        |`-.__
        / ' _/
       ****`  
      /    }} 
     /  \ /   
 \ /`   \\    
  `\    /_\\  
   `~~~~~``~` "#;
    let mut sum = String::new();
    let corgea_lines = corgea_title.lines();
    let dog_lines = dog_art.lines();
    let mut corgea_iter = corgea_lines.into_iter();
    let mut dog_iter = dog_lines.into_iter();
    loop {
        match (corgea_iter.next(), dog_iter.next()) {
            (Some(corgea_line), Some(dog_line)) => {
                sum.push_str(dog_line);
                sum.push_str("  ");
                sum.push_str(corgea_line);
                sum.push_str("\n");
            },
            (Some(corgea_line), None) | (None, Some(corgea_line)) => {
                sum.push_str(corgea_line);
                sum.push_str("\n");
            },
            (None, None) => break,
        }
    }
    sum
}


pub fn format_code(code: &str) -> String {
    let mut formatted_code = String::new();
    let regex = regex::Regex::new(r"<code>(.*?)</code>").unwrap();
    let mut last_end = 0;

    for capture in regex.captures_iter(code) {
        if let Some(matched) = capture.get(1) {
            // Append text before the code block
            formatted_code.push_str(&code[last_end..capture.get(0).unwrap().start()]);
            // Format the code block
            formatted_code.push_str(&format!("`{}`", utils::terminal::set_text_color(matched.as_str(), utils::terminal::TerminalColor::Green)));
            last_end = capture.get(0).unwrap().end();
        }
    }
    // Append any remaining text after the last code block
    formatted_code.push_str(&code[last_end..]);

    formatted_code
}


pub enum TerminalColor {
    Reset,
    Red,
    Green,
    Blue,
}