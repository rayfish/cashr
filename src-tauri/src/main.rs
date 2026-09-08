#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = cashr_lib::run() {
        eprintln!("cashr failed to start: {error}");
        std::process::exit(1);
    }
}
