//! Where the signer keeps its database.

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
