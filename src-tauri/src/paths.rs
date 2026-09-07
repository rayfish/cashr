//! Where the signer keeps its database and its log.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use tauri::{AppHandle, Manager};

/// `~/Library/Application Support/<bundle id>/signer.db` on macOS, and the
/// platform equivalent elsewhere. Created if it does not exist.
pub fn database(app: &AppHandle) -> Result<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow!("no application data directory: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("signer.db"))
}

/// `~/Library/Application Support/<bundle id>/keys`, where the NIP-49
/// encrypted key files live. Created if it does not exist.
pub fn keys(app: &AppHandle) -> Result<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow!("no application data directory: {e}"))?;
    Ok(dir.join("keys"))
}

/// `~/Library/Logs/Byrgi/byrgi.log`.
///
/// Worked out from the home directory rather than asked of Tauri, because
/// logging starts before there is an app to ask. A bundled app has nowhere to
/// write stderr, so without this the only way to see what the signer did is to
/// start it from a terminal, which is also a good way to stop notifications
/// registering.
pub fn log() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("no home directory"))?;
    let dir = PathBuf::from(home).join("Library/Logs/Byrgi");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("byrgi.log"))
}
