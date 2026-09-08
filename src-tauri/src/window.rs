//! Showing, hiding and placing the one window.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Rect, Runtime, WebviewWindow};

pub const MAIN: &str = "main";

/// Space between the menu bar and the top of the window, in logical points.
const GAP: f64 = 6.0;

/// How long after an automatic hide a tray click is ignored.
///
/// Clicking the icon while the window has focus fires the blur first, which
/// hides the window, and then the click, which would show it again. Without
/// this window the icon would look like it does nothing.
const SETTLE: Duration = Duration::from_millis(250);

/// The bits of window behaviour the tray and the frontend both steer.
#[derive(Debug, Default)]
pub struct WindowState {
    /// While set, losing focus does not hide the window. The frontend raises
    /// it for the pin button, for a pending approval, and around any call that
    /// can raise a system dialog of its own (Touch ID, most of all).
    pinned: AtomicBool,
    dialogs: AtomicUsize,
    hidden_at: Mutex<Option<Instant>>,
}

impl WindowState {
    pub fn set_pinned(&self, pinned: bool) {
        self.pinned.store(pinned, Ordering::Relaxed);
    }

    pub fn is_pinned(&self) -> bool {
        self.pinned.load(Ordering::Relaxed) || self.dialogs.load(Ordering::SeqCst) > 0
    }

    pub fn hold_for_dialog(&self) -> DialogHold<'_> {
        self.dialogs.fetch_add(1, Ordering::SeqCst);
        DialogHold(self)
    }

    fn mark_hidden(&self) {
        if let Ok(mut at) = self.hidden_at.lock() {
            *at = Some(Instant::now());
        }
    }

    fn just_hidden(&self) -> bool {
        self.hidden_at
            .lock()
            .ok()
            .and_then(|at| *at)
            .is_some_and(|at| at.elapsed() < SETTLE)
    }
}

pub struct DialogHold<'a>(&'a WindowState);

impl Drop for DialogHold<'_> {
    fn drop(&mut self) {
        self.0.dialogs.fetch_sub(1, Ordering::SeqCst);
    }
}

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

/// Explicit user opening, distinct from restoring the window after a scanner
/// or system dialog. Only an explicit opening should trigger wallet unlock.
pub fn open<R: Runtime>(app: &AppHandle<R>) {
    show(app);
    let _ = app.emit("cashr://opened", ());
}

pub fn hide<R: Runtime>(app: &AppHandle<R>, state: &WindowState) {
    if let Some(window) = get(app) {
        let _ = window.hide();
        state.mark_hidden();
    }
}

/// Left click on the icon: show the window under it, or put it away again.
pub fn toggle_under<R: Runtime>(app: &AppHandle<R>, state: &WindowState, anchor: Rect) {
    if state.just_hidden() {
        return;
    }
    let Some(window) = get(app) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        state.mark_hidden();
        return;
    }
    // A pinned window keeps the position the user dragged it to.
    if !state.is_pinned() {
        if let Err(error) = place_under(&window, anchor) {
            tracing::debug!("could not place the window under the icon: {error}");
        }
    }
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit("cashr://opened", ());
}

/// Centre the window on the icon, kept inside the screen's usable area.
fn place_under<R: Runtime>(window: &WebviewWindow<R>, anchor: Rect) -> tauri::Result<()> {
    let scale = window.scale_factor()?;
    let icon = anchor.position.to_physical::<f64>(scale);
    let icon_size = anchor.size.to_physical::<f64>(scale);
    let size = window.outer_size()?;
    let width = f64::from(size.width);

    let mut x = icon.x + icon_size.width / 2.0 - width / 2.0;
    let mut y = icon.y + icon_size.height + GAP * scale;

    if let Some(monitor) = window.current_monitor()? {
        let area = monitor.work_area();
        let left = f64::from(area.position.x);
        let right = left + f64::from(area.size.width) - width;
        // A narrow screen can leave no room at all; the left edge wins then.
        x = x.min(right).max(left);
        y = y.max(f64::from(area.position.y));
    }

    window.set_position(PhysicalPosition::new(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_dialog_stays_pinned_despite_late_frontend_updates() {
        let window = WindowState::default();
        let first = window.hold_for_dialog();
        let second = window.hold_for_dialog();
        window.set_pinned(false);
        assert!(window.is_pinned());
        drop(first);
        assert!(window.is_pinned());
        drop(second);
        assert!(!window.is_pinned());
    }
}
