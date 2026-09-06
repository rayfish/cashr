//! The menu bar icon and its menu.

use anyhow::Result;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::state::AppState;
use crate::window;

const OPEN: &str = "open";
const UNLOCK: &str = "unlock";
const LOCK: &str = "lock";
const QUIT: &str = "quit";

pub fn build<R: Runtime>(app: &AppHandle<R>) -> Result<TrayIcon<R>> {
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, OPEN, "Open nostr-tray", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, UNLOCK, "Unlock", true, None::<&str>)?,
            &MenuItem::with_id(app, LOCK, "Lock", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, QUIT, "Quit", true, None::<&str>)?,
        ],
    )?;

    let icon = TrayIconBuilder::with_id("main")
        .menu(&menu)
        // The menu belongs to the right button. A left click opens the window,
        // which is what a menu bar utility is expected to do.
        .show_menu_on_left_click(false)
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            anyhow::anyhow!("the bundle has no icon; tauri.conf.json bundle.icon is wrong")
        })?)
        .icon_as_template(true)
        .on_menu_event(on_menu_event)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { .. } = event {
                window::show(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(icon)
}

fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        OPEN => window::show(app),
        UNLOCK => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<AppState>();
                if let Err(error) = state.unlock().await {
                    tracing::error!("could not unlock: {error}");
                }
            });
        }
        LOCK => app.state::<AppState>().lock(),
        QUIT => app.exit(0),
        other => tracing::debug!("unhandled menu item: {other}"),
    }
}

/// Reflect pending requests on the icon.
///
/// This is the fallback that makes a Focus-suppressed notification survivable:
/// a request nobody saw still shows up here.
pub fn set_badge<R: Runtime>(app: &AppHandle<R>, pending: usize) {
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    let title = match pending {
        0 => None,
        n => Some(format!("{n}")),
    };
    if let Err(error) = tray.set_title(title) {
        tracing::debug!("could not set the tray badge: {error}");
    }
}
