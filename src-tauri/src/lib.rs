//! Byrgi: a menu bar NIP-46 signer.

#![forbid(unsafe_code)]

mod commands;
mod paths;
mod state;
mod tray;
mod views;
mod window;

use anyhow::Result;
use signer_core::storage::Storage;
use tauri::{Manager, WindowEvent};
use tracing::Level;
use tracing_subscriber::fmt;

use crate::state::AppState;

pub fn run() -> Result<()> {
    fmt().with_max_level(Level::DEBUG).init();

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();

            // Menu bar only. The Info.plist LSUIElement key covers the bundled
            // app; this covers everything else, including `tauri dev`.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let storage = Storage::open(&paths::database(&handle)?)?;
            let state = AppState::build(&handle, storage, &app.config().identifier)?;
            app.manage(state);

            tray::build(&handle)?;

            // Relays come up now, not at the first unlock. A request that
            // arrives while the signer is locked is held and answered after
            // the unlock, which only works if something heard it arrive.
            let listen_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let state = listen_handle.state::<AppState>();
                if let Err(error) = state.start_listening().await {
                    tracing::error!("could not start listening: {error}");
                }
            });

            // The badge is the fallback for a notification a Focus mode
            // swallowed: a request nobody saw still shows on the icon.
            let badge_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let mut shown = usize::MAX;
                loop {
                    let pending = badge_handle.state::<AppState>().approver.pending_count();
                    if pending != shown {
                        tray::set_badge(&badge_handle, pending);
                        shown = pending;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            });

            Ok(())
        })
        .on_window_event(|target, event| match event {
            // Closing the window must not quit a signer that is meant to keep
            // answering requests. Quit is on the tray menu, deliberately.
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = target.hide();
            }
            // A popover goes away when you look elsewhere. The pin is the
            // escape hatch, and the frontend holds it while a pairing URI is
            // being pasted or while a system dialog has the focus.
            WindowEvent::Focused(false) => {
                let state = target.state::<AppState>();
                if !state.window.is_pinned() {
                    window::hide(target.app_handle(), &state.window);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::unlock,
            commands::lock,
            commands::create_account,
            commands::import_account,
            commands::delete_account,
            commands::set_default_account,
            commands::set_relays,
            commands::relay_health,
            commands::pair_bunker,
            commands::pair_client,
            commands::clients,
            commands::revoke_client,
            commands::rules,
            commands::set_rule,
            commands::clear_rule,
            commands::activity,
            commands::prompts,
            commands::answer_prompt,
            commands::set_pinned,
            commands::hide_window,
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
