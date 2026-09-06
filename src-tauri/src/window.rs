//! Showing and hiding the one window.

use tauri::{AppHandle, Manager, Runtime, WebviewWindow};

pub const MAIN: &str = "main";

pub fn get<R: Runtime>(app: &AppHandle<R>) -> Option<WebviewWindow<R>> {
    app.get_webview_window(MAIN)
}

pub fn show<R: Runtime>(app: &AppHandle<R>) {
    let Some(window) = get(app) else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
}

pub fn hide<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = get(app) {
        let _ = window.hide();
    }
}
