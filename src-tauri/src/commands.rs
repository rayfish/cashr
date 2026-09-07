//! The window's API. Each command is a thin call into the core.

use std::time::Duration;

use macos_native::notifications::RequestId;
use nostr::types::RelayUrl;
use signer_core::account::AccountId;
use signer_core::approval::ApprovalDecision;
use signer_core::client::ClientId;
use signer_core::kinds;
use signer_core::pairing::{accept_client_uri, mint_bunker_uri, parse_client_uri};
use signer_core::policy::Decision;
use tauri::{AppHandle, Runtime, State};

use crate::state::AppState;
use crate::views::{
    method_from_str, scope_from_parts, AccountView, ActivityView, ClientView, PairingView,
    PromptView, RelayView, RuleView, StatusView,
};
use crate::window;

/// How long a minted pairing URI stays usable. Long enough to paste it
/// somewhere, short enough that a stale one in a clipboard is worthless.
const PAIRING_TTL: Duration = Duration::from_secs(300);

/// Errors reaching the window are strings: it renders them, it does not match
/// on them.
type CommandResult<T> = Result<T, String>;

fn fail<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> CommandResult<StatusView> {
    let accounts = state.accounts().map_err(fail)?;

    // A passphrase and nothing left to load. The second half matters on a
    // fresh signer: with no accounts the vault holds nothing and would read as
    // locked forever, which would leave no way to set the passphrase that
    // making the first account needs.
    let unlocked = state.has_passphrase() && (accounts.is_empty() || state.is_unlocked());

    Ok(StatusView {
        unlocked,
        unlocked_accounts: accounts
            .iter()
            .filter(|account| state.session.vault().holds(account.id))
            .map(|account| account.id.get())
            .collect(),
        accounts: accounts.iter().map(AccountView::from).collect(),
        pending: state.approver.pending_count(),
        needs_migration: state.needs_migration(),
        has_keychain_copies: state.has_keychain_copies(),
        has_touch_id: state.has_touch_id(),
    })
}

/// Unlock by typing the passphrase. `remember` puts it behind Touch ID.
#[tauri::command]
pub async fn unlock(
    state: State<'_, AppState>,
    passphrase: String,
    remember: bool,
) -> CommandResult<()> {
    state.unlock(&passphrase, remember).await.map_err(fail)
}

/// Unlock with Touch ID, using the passphrase it guards.
#[tauri::command]
pub async fn unlock_with_touch_id(state: State<'_, AppState>) -> CommandResult<()> {
    state.unlock_with_touch_id().await.map_err(fail)
}

/// Stop unlocking with Touch ID, and delete the passphrase it was guarding.
#[tauri::command]
pub async fn forget_touch_id(state: State<'_, AppState>) -> CommandResult<()> {
    state.forget_touch_id().map_err(fail)
}

/// Delete the old Keychain copies, once the key files are the real ones.
#[tauri::command]
pub async fn forget_keychain(state: State<'_, AppState>) -> CommandResult<()> {
    state.forget_keychain().await.map_err(fail)
}

#[tauri::command]
pub fn lock(
    state: State<'_, AppState>,
    wallet: State<'_, crate::wallet::WalletService>,
) -> CommandResult<()> {
    wallet.lock();
    state.lock();
    Ok(())
}

#[tauri::command]
pub async fn create_account(
    state: State<'_, AppState>,
    label: String,
) -> CommandResult<AccountView> {
    let account = state.create_account(label).await.map_err(fail)?;
    Ok(AccountView::from(&account))
}

#[tauri::command]
pub async fn import_account(
    state: State<'_, AppState>,
    label: String,
    secret: String,
) -> CommandResult<AccountView> {
    let account = state.import_account(label, &secret).await.map_err(fail)?;
    Ok(AccountView::from(&account))
}

#[tauri::command]
pub async fn delete_account(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    wallet: State<'_, crate::wallet::WalletService>,
    account: i64,
) -> CommandResult<()> {
    let _guard = wallet.gate.lock().await;
    if crate::wallet::has_wallet(&app, &state, account).map_err(fail)? {
        return Err("This account has a Cashu wallet. Keep its keys and wallet backup; account deletion is disabled to protect its funds.".into());
    }
    state
        .delete_account(AccountId::new(account))
        .await
        .map_err(fail)
}

#[tauri::command]
pub fn set_default_account(state: State<'_, AppState>, account: i64) -> CommandResult<()> {
    state
        .storage
        .set_default_account(AccountId::new(account))
        .map_err(fail)
}

#[tauri::command]
pub fn set_lightning_address(
    state: State<'_, AppState>,
    account: i64,
    address: Option<String>,
) -> CommandResult<()> {
    state
        .storage
        .set_lightning_address(AccountId::new(account), address.as_deref())
        .map_err(fail)
}

#[tauri::command]
pub async fn set_relays(
    state: State<'_, AppState>,
    account: i64,
    relays: Vec<String>,
) -> CommandResult<()> {
    let parsed: Result<Vec<RelayUrl>, _> = relays.iter().map(|u| RelayUrl::parse(u)).collect();
    state
        .set_relays(AccountId::new(account), &parsed.map_err(fail)?)
        .await
        .map_err(fail)
}

/// Health comes from the pool rather than storage, so a relay that is
/// configured but unreachable reads as down instead of simply absent. A dead
/// relay and a broken signer look identical without this.
#[tauri::command]
pub async fn relay_health(
    state: State<'_, AppState>,
    account: i64,
) -> CommandResult<Vec<RelayView>> {
    let health = state
        .runner
        .transport()
        .health(AccountId::new(account))
        .await;
    Ok(health.iter().map(RelayView::from).collect())
}

/// Mint a `bunker://` URI to paste into a client.
#[tauri::command]
pub fn pair_bunker(state: State<'_, AppState>, account: i64) -> CommandResult<String> {
    let account = state
        .storage
        .account(AccountId::new(account))
        .map_err(fail)?;
    let uri = mint_bunker_uri(&state.storage, &account, PAIRING_TTL).map_err(fail)?;
    Ok(uri.to_string())
}

/// Accept a `nostrconnect://` URI a client produced.
#[tauri::command]
pub async fn pair_client(
    state: State<'_, AppState>,
    account: i64,
    uri: String,
) -> CommandResult<PairingView> {
    let id = AccountId::new(account);

    // Answering means signing, so a locked signer cannot finish this. Checked
    // before anything is written, so a refusal leaves no half-made pairing.
    if !state.session.vault().holds(id) {
        return Err("unlock the signer before pairing".to_string());
    }

    let account = state.storage.account(id).map_err(fail)?;
    let parsed = parse_client_uri(&uri).map_err(fail)?;
    let pairing =
        accept_client_uri(&state.storage, &account, &parsed, PAIRING_TTL).map_err(fail)?;

    // The client is listening only on the relays it named, so that is where
    // the signer has to answer. Adding them to the account is what makes the
    // listening loop pick them up, and leaves them visible and removable
    // rather than hidden in a pairing row.
    let added: Vec<RelayUrl> = pairing
        .relays
        .iter()
        .filter(|relay| !account.relays.contains(relay))
        .cloned()
        .collect();

    if !added.is_empty() {
        let mut relays = account.relays.clone();
        relays.extend(added.iter().cloned());
        state.set_relays(id, &relays).await.map_err(fail)?;
    }

    // This direction has the signer speak first: the client is waiting to be
    // answered, not to be asked, so nothing happens until the ack goes out.
    let ack = state
        .session
        .accept_pairing(&account, &pairing.client_public_key, &pairing.secret)
        .await
        .map_err(fail)?;
    state
        .runner
        .transport()
        .publish(id, ack, pairing.relays.clone())
        .await
        .map_err(fail)?;

    let name = pairing.metadata.name;
    Ok(PairingView {
        client_public_key: pairing.client_public_key.to_hex(),
        client_name: (!name.is_empty()).then_some(name),
        added_relays: added.iter().map(|relay| relay.to_string()).collect(),
    })
}

#[tauri::command]
pub fn clients(state: State<'_, AppState>, account: i64) -> CommandResult<Vec<ClientView>> {
    let clients = state
        .storage
        .clients(AccountId::new(account))
        .map_err(fail)?;
    Ok(clients.iter().map(ClientView::from).collect())
}

#[tauri::command]
pub fn revoke_client(state: State<'_, AppState>, client: i64) -> CommandResult<()> {
    state
        .storage
        .revoke_client(ClientId::new(client))
        .map_err(fail)
}

/// Revoke a client and take it off the list, rules and all. Strictly stronger
/// than revoking: the access goes the same way, and the record goes too.
#[tauri::command]
pub fn remove_client(state: State<'_, AppState>, client: i64) -> CommandResult<()> {
    state
        .storage
        .remove_client(ClientId::new(client))
        .map_err(fail)
}

#[tauri::command]
pub fn rules(state: State<'_, AppState>, client: i64) -> CommandResult<Vec<RuleView>> {
    let policy = state
        .storage
        .policy_set(ClientId::new(client))
        .map_err(fail)?;
    Ok(policy.rules().iter().map(RuleView::from).collect())
}

#[tauri::command]
pub fn set_rule(
    state: State<'_, AppState>,
    client: i64,
    method: String,
    kind: Option<u16>,
    allow: bool,
) -> CommandResult<()> {
    let method = method_from_str(&method).ok_or_else(|| format!("unknown method: {method}"))?;
    let decision = if allow {
        Decision::Allow
    } else {
        Decision::Deny
    };
    state
        .storage
        .set_rule(
            ClientId::new(client),
            scope_from_parts(method, kind),
            decision,
        )
        .map_err(fail)
}

#[tauri::command]
pub fn clear_rule(
    state: State<'_, AppState>,
    client: i64,
    method: String,
    kind: Option<u16>,
) -> CommandResult<()> {
    let method = method_from_str(&method).ok_or_else(|| format!("unknown method: {method}"))?;
    state
        .storage
        .clear_rule(ClientId::new(client), scope_from_parts(method, kind))
        .map_err(fail)
}

#[tauri::command]
pub fn activity(
    state: State<'_, AppState>,
    account: i64,
    limit: u32,
    before: Option<i64>,
) -> CommandResult<Vec<ActivityView>> {
    let entries = state
        .storage
        .activity(AccountId::new(account), limit.min(200), before)
        .map_err(fail)?;
    Ok(entries.iter().map(ActivityView::from).collect())
}

#[tauri::command]
pub fn prompts(state: State<'_, AppState>) -> CommandResult<Vec<PromptView>> {
    Ok(state
        .approver
        .pending()
        .into_iter()
        .map(|pending| PromptView {
            id: pending.id.get(),
            account: pending.request.account.get(),
            account_label: pending.request.account_label,
            client: pending.request.client.get(),
            client_name: pending.request.client_name,
            client_public_key: pending.request.client_public_key.to_hex(),
            detail: pending.request.detail,
            preview: pending.request.preview,
            method: pending.request.scope.method.to_string(),
            kind: pending.request.scope.kind.map(|k| k.as_u16()),
            kind_name: pending.request.scope.kind.and_then(kinds::name),
            requested_at: pending.request.requested_at.as_secs(),
        })
        .collect())
}

#[tauri::command]
pub fn answer_prompt(
    state: State<'_, AppState>,
    id: u64,
    allow: bool,
    remember: bool,
) -> CommandResult<bool> {
    let decision = ApprovalDecision {
        decision: if allow {
            Decision::Allow
        } else {
            Decision::Deny
        },
        remember,
    };
    let id = RequestId::parse(&id.to_string()).ok_or_else(|| "bad request id".to_string())?;
    Ok(state.approver.resolve(id, decision))
}

/// Keep the window open while it does not have focus.
///
/// The frontend raises this for the pin button, while an approval is waiting
/// and around any call that can put a system dialog in front of the window.
/// Without it a Touch ID prompt would send the window away mid-unlock.
#[tauri::command]
pub fn set_pinned(state: State<'_, AppState>, pinned: bool) {
    state.window.set_pinned(pinned);
}

#[tauri::command]
pub fn hide_window<R: Runtime>(app: AppHandle<R>, state: State<'_, AppState>) {
    window::hide(&app, &state.window);
}
