//! Cashr: a menu bar NIP-46 signer.

#![forbid(unsafe_code)]

mod commands;
mod paths;
mod qr;
mod scan;
mod state;
mod tray;
mod views;
mod wallet;
mod window;

use std::fs::File;
use std::sync::Mutex;

use anyhow::Result;
use signer_core::storage::Storage;
use tauri::{Manager, WindowEvent};
use tracing::Level;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::state::AppState;

/// Log to stderr and, when there is somewhere to put it, to a file.
///
/// A bundled app has nowhere to write stderr, so the file is what makes a
/// misbehaving signer explicable without starting it from a terminal. It is
/// truncated per launch: what matters is the run in front of you, and an
/// unbounded log on a signer is its own problem.
fn start_logging() {
    let file = paths::log()
        .ok()
        .and_then(|path| File::create(path).ok())
        .map(|file| fmt::layer().with_ansi(false).with_writer(Mutex::new(file)));

    tracing_subscriber::registry()
        // SDK spans can contain wallet metadata. Keep payment and token data
        // out of the application's persistent diagnostic log.
        .with(tracing_subscriber::filter::filter_fn(|metadata| {
            !metadata.target().starts_with("cdk")
                && !metadata.target().starts_with("cashu")
                && !metadata.target().starts_with("reqwest")
                && !metadata.target().starts_with("hyper")
        }))
        .with(LevelFilter::from_level(Level::DEBUG))
        .with(fmt::layer())
        .with(file)
        .init();
}

pub fn run() -> Result<()> {
    start_logging();

    tauri::Builder::default()
        .manage(wallet::WalletService::default())
        .setup(|app| {
            let handle = app.handle().clone();

            // Menu bar only. The Info.plist LSUIElement key covers the bundled
            // app; this covers everything else, including `tauri dev`.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let storage = Storage::open(&paths::database(&handle)?)?;
            let state = AppState::build(
                &handle,
                storage,
                paths::keys(&handle)?,
                paths::unlock_passphrase(&handle)?,
                &app.config().identifier,
            )?;
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

            // What a waiting request looks like when the notification does not
            // arrive. A notification can be refused permission or swallowed by
            // a Focus mode, so the icon badges and the count is there to be
            // found. The window stays where it is: a signer that takes over
            // the screen every time an app asks for a signature is worse than
            // one you have to click.
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
            scan::scan_screen,
            scan::prepare_scan,
            scan::scan_clipboard,
            commands::status,
            wallet::wallet_open,
            wallet::wallet_list,
            wallet::wallet_select,
            wallet::wallet_set_mint,
            wallet::wallet_backup,
            wallet::wallet_inspect_token,
            wallet::wallet_review_send,
            wallet::wallet_send_token,
            wallet::wallet_show_token,
            wallet::wallet_reclaim_token,
            qr::encode_qr,
            wallet::wallet_fund,
            wallet::wallet_receive,
            wallet::wallet_review,
            wallet::wallet_pay,
            wallet::wallet_cancel,
            wallet::wallet_restore,
            wallet::wallet_zap,
            commands::lock,
            commands::forget_keychain,
            commands::unlock_with_touch_id,
            commands::create_account,
            commands::import_account,
            commands::delete_account,
            commands::rename_account,
            commands::set_default_account,
            commands::set_lightning_address,
            commands::find_lightning_address,
            commands::set_relays,
            commands::relay_health,
            commands::pair_bunker,
            commands::pair_client,
            commands::clients,
            commands::revoke_client,
            commands::remove_client,
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
