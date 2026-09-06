#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = byrgi_lib::run() {
        eprintln!("byrgi failed to start: {error}");
        std::process::exit(1);
    }
}
