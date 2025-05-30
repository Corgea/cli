use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::{thread, time};
use std::sync::{Arc, Mutex};
use crate::utils;
use regex::Regex;

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
        print!("\r[{}] {}{}", spinner[i % spinner.len()], message, set_text_color("", TerminalColor::Reset));
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
    let dog_art = r#"
        |`-.__
        / ' _/
       ****`  
      /    }}    Corgea
     /  \ /   
 \ /`   \\    
  `\    /_\\  
   `~~~~~``~`
   
   "#;
    println!("{}", set_text_color(dog_art, TerminalColor::Green));
} 

pub fn format_code(code: &str) -> String {
    let mut formatted_code = String::new();
    let regex = regex::Regex::new(r"<code>(.*?)</code>").unwrap();
    let mut last_end = 0;

    for capture in regex.captures_iter(code) {
        if let Some(matched) = capture.get(1) {
            formatted_code.push_str(&code[last_end..capture.get(0).unwrap().start()]);
            formatted_code.push_str(&format!("`{}`", utils::terminal::set_text_color(matched.as_str(), utils::terminal::TerminalColor::Green)));
            last_end = capture.get(0).unwrap().end();
        }
    }
    formatted_code.push_str(&code[last_end..]);

    formatted_code
}

pub fn format_diff(diff: &str) -> String {
    let mut formatted_diff = String::new();
    let regex = Regex::new(r"(@@.*?@@)").unwrap();

    for line in diff.lines() {
        let formatted_line = if line.starts_with("diff --git") {
            format!("{}\n", line)
        } else if line.starts_with("index") {
            format!("{}\n", set_text_color(line, TerminalColor::Blue))
        } else if line.starts_with("---") {
            format!("{}\n", set_text_color(line, TerminalColor::Red))
        } else if line.starts_with("+++") {
            format!("{}\n", set_text_color(line, TerminalColor::Green))
        } else if line.starts_with("@@") {
            let formatted_text = regex.replace_all(line, |caps: &regex::Captures| {
                set_text_color(&caps[0], TerminalColor::Blue) 
            });
            format!("{}\n", formatted_text) 
        } else if line.starts_with("-") {
            format!("{}\n", set_text_color(line, TerminalColor::Red))
        } else if line.starts_with("+") {
            format!("{}\n", set_text_color(line, TerminalColor::Green))
        } else {
            format!("{}\n", line)
        };

        formatted_diff.push_str(&formatted_line);
    }

    formatted_diff
}

pub fn clear_line(length: usize) {
    print!("{:width$}\r", " ", width = length + 1);
}

pub fn print_with_pagination(str: &str) {
    let mut stdout = io::stdout();
    let mut lines = str.lines();
    let mut buffer = String::new();
    let stdin = io::stdin();
    let message ="-- More -- (Press Enter to continue, Ctrl+C to exit)";

    loop {
        clear_line(message.len());
        for _ in 0..7 {
            if let Some(line) = lines.next() {
                println!("{}", line);
            } else {
                clear_line(message.len());
                return;
            }

        }

        print!("{}", message);
        stdout.flush().unwrap();

        buffer.clear();
        stdin.read_line(&mut buffer).unwrap();


        print!("\x1B[2K\x1B[1A");
        stdout.flush().unwrap();
    }
}
pub fn prompt_to_continue_or_exit(message: Option<&str>) {
    if let Some(message) = message {
        println!("{}", message);
    } else {
        println!("Press Enter to continue, Ctrl+C to exit.");
    }
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

pub fn ask_yes_no(question: &str, should_default: bool) -> bool {
    loop {
        print!("{} (y/n): ", question);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => if should_default {
                return true;
            } else {
                println!("Please answer with yes/y or no/n");
            }
        }
    }
}

pub fn print_table(table: Vec<Vec<String>>, page: Option<u32>, total_pages: Option<u32>) {
    let columns = table.iter().enumerate().fold(vec![vec![]; table[0].len()], |mut acc, (_i, row)| {
        for (j, cell) in row.iter().enumerate() {
            acc[j].push(cell.clone());
        }
        acc
    });
    let column_lengths = columns.iter().map(|col| col.iter().map(|cell| cell.len()).max_by(|a, b| a.cmp(b)).unwrap_or(0)).collect::<Vec<_>>();
    for (j, row) in table.iter().enumerate() {
        for (i, cell) in row.iter().enumerate() {
            print!("{:<width$}   ", cell, width = column_lengths[i]);
        }
        if j == 0 {
            println!();
        }
        println!();
    }
    if let (Some(page), Some(total_pages)) = (page, total_pages) {
        println!("\nPage {} of {}", page, total_pages);
    }
}


pub enum TerminalColor {
    Reset,
    Red,
    Green,
    Blue,
}