#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = nostr_tray_lib::run() {
        eprintln!("nostr-tray failed to start: {error}");
        std::process::exit(1);
    }
}
