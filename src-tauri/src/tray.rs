//! The menu bar icon and its menu.

use anyhow::Result;
use tauri::image::Image;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::state::AppState;
use crate::window;

/// The menu bar mark, as a template image: macOS reads only its alpha and
/// paints it to match the bar, so it follows dark mode and a tinted desktop
/// without a second asset. The source is `icons/tray.svg`.
const ICON: &[u8] = include_bytes!("../icons/tray.png");

const OPEN: &str = "open";
const UNLOCK: &str = "unlock";
const LOCK: &str = "lock";
const QUIT: &str = "quit";

pub fn build<R: Runtime>(app: &AppHandle<R>) -> Result<TrayIcon<R>> {
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, OPEN, "Open Cashr", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, UNLOCK, "Unlock", true, None::<&str>)?,
            &MenuItem::with_id(app, LOCK, "Lock", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, QUIT, "Quit", true, None::<&str>)?,
        ],
    )?;

    let icon = TrayIconBuilder::with_id("main")
        .menu(&menu)
        // The menu belongs to the right button. The left button opens the
        // window under the icon, which is what a menu bar utility does.
        .show_menu_on_left_click(false)
        .icon(Image::from_bytes(ICON)?)
        .icon_as_template(true)
        .on_menu_event(on_menu_event)
        .on_tray_icon_event(on_tray_event)
        .build(app)?;

    Ok(icon)
}

fn on_tray_event<R: Runtime>(tray: &TrayIcon<R>, event: TrayIconEvent) {
    // Only the release of the left button. The press arrives as its own event,
    // and the right button already has the menu, so acting on every click
    // would toggle the window twice per click and fight the menu.
    let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        rect,
        ..
    } = event
    else {
        return;
    };

    let app = tray.app_handle();
    window::toggle_under(app, &app.state::<AppState>().window, rect);
}

fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        OPEN | UNLOCK => window::open(app),
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
    // An empty string rather than `None`: clearing a menu bar title by passing
    // nothing does not reliably take, and a badge that will not go away says
    // there is a decision waiting when there is not.
    let title = match pending {
        0 => String::new(),
        n => format!("{n}"),
    };
    if let Err(error) = tray.set_title(Some(title)) {
        tracing::debug!("could not set the tray badge: {error}");
    }
}
