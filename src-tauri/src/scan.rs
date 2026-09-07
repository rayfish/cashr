//! Explicit user-initiated capture; never a clipboard or screen watcher.

use std::sync::atomic::{AtomicBool, Ordering};

use macos_native::qr;
use tauri::AppHandle;

use crate::window;

static SCANNING: AtomicBool = AtomicBool::new(false);

struct ScanGuard;

impl ScanGuard {
    fn acquire() -> Result<Self, String> {
        SCANNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| "A QR scan is already in progress.".into())
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        SCANNING.store(false, Ordering::Release);
    }
}

async fn on_main<T: Send + 'static>(
    app: &AppHandle,
    task: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let _ = send.send(task());
    })
    .map_err(|_| "Could not access macOS image capture.".to_string())?;
    receive
        .await
        .map_err(|_| "Image capture was interrupted.".to_string())?
}

#[tauri::command]
pub async fn prepare_scan(app: AppHandle) -> Result<bool, String> {
    let _guard = ScanGuard::acquire()?;
    on_main(&app, || Ok(qr::request_screen_access())).await
}

#[tauri::command]
pub async fn scan_clipboard(app: AppHandle) -> Result<Vec<String>, String> {
    let _guard = ScanGuard::acquire()?;
    let bytes = on_main(&app, qr::clipboard_image).await?;
    tauri::async_runtime::spawn_blocking(move || qr::decode(&bytes))
        .await
        .map_err(|_| "QR decoding was interrupted.".to_string())?
}

#[tauri::command]
pub async fn scan_screen(app: AppHandle) -> Result<Option<Vec<String>>, String> {
    let _guard = ScanGuard::acquire()?;
    on_main(&app, qr::check_screen_access).await?;
    let window = window::get(&app).ok_or("Byrgi's window is unavailable.")?;
    window
        .hide()
        .map_err(|_| "Could not hide Byrgi for screen selection.")?;
    // Let the window disappear before the system selector freezes the screen.
    tokio::time::sleep(std::time::Duration::from_millis(180)).await;
    let result = tauri::async_runtime::spawn_blocking(qr::capture_screen).await;
    window::show(&app);
    result.map_err(|_| "Screen scanning was interrupted.".to_string())?
}
