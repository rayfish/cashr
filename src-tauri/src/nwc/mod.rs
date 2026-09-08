//! NWC wallet service. Pairings contain public metadata only; every spend needs approval.
mod protocol;
mod relay;
mod store;

use crate::{
    state::AppState,
    wallet::{self, WalletService},
    window,
};
use anyhow::{ensure, Result};
use nostr::{
    event::Event,
    key::{Keys, PublicKey},
};
use protocol::{failure, now, success};
use serde::Serialize;
use serde_json::{json, Value};
use signer_core::account::AccountId;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use store::{Begin, Pairing, Store};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{broadcast, oneshot, Semaphore};
use zeroize::Zeroizing;

pub struct NwcService {
    store: Store,
    tasks: Mutex<HashMap<String, tokio::task::AbortHandle>>,
    waiting: Mutex<HashMap<String, Waiting>>,
    pub(crate) limit: Arc<Semaphore>,
    active_requests: Mutex<HashSet<String>>,
}
struct Waiting {
    prompt: Prompt,
    answer: oneshot::Sender<bool>,
}
#[derive(Clone, Serialize)]
pub struct Prompt {
    id: String,
    connection: String,
    account: i64,
    account_label: String,
    app: String,
    mint: String,
    amount: u64,
    max_fee: u64,
    maximum: u64,
    destination: String,
    expiry: u64,
}

impl NwcService {
    pub fn new(app: &AppHandle) -> Result<Self> {
        Ok(Self {
            store: Store::open(&app.path().app_data_dir()?.join("nwc.sqlite"))?,
            tasks: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            limit: Arc::new(Semaphore::new(16)),
            active_requests: Mutex::new(HashSet::new()),
        })
    }
    pub fn pending_count(&self) -> usize {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn start(&self, app: &AppHandle) -> Result<()> {
        for pairing in self.store.list()? {
            // Account deletion makes all of its old connections unusable.
            if app
                .state::<AppState>()
                .storage
                .account(AccountId::new(pairing.account))
                .is_ok()
            {
                self.listen(app, pairing);
            }
        }
        Ok(())
    }
    pub fn preserve_connection_keys(
        &self,
        account: i64,
        seed: &[u8; 64],
        seal: impl Fn(&str) -> Result<String>,
    ) -> Result<()> {
        for pairing in self
            .store
            .list()?
            .into_iter()
            .filter(|p| p.account == account)
        {
            if self.store.sealed_key(&pairing.id)?.is_some() {
                continue;
            }
            let keys = protocol::connection_keys(seed, PublicKey::from_hex(&pairing.client)?)?;
            ensure!(
                keys.public_key().to_hex() == pairing.wallet,
                "Connection identity mismatch during migration"
            );
            let secret = Zeroizing::new(keys.secret_key().to_secret_hex());
            self.store.save_key(&pairing.id, &seal(&secret)?)?;
        }
        Ok(())
    }
    pub fn remove_account(&self, account: i64) -> Result<()> {
        let connections = self.store.list()?;
        self.store.revoke_account(account)?;
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        for pairing in connections.into_iter().filter(|p| p.account == account) {
            if let Some(task) = tasks.remove(&pairing.id) {
                task.abort();
            }
        }
        self.waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, w| w.prompt.account != account);
        Ok(())
    }
    fn listen(&self, app: &AppHandle, pairing: Pairing) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        if tasks.contains_key(&pairing.id) {
            return;
        }
        let id = pairing.id.clone();
        let app = app.clone();
        let task = tauri::async_runtime::spawn(async move {
            relay::run(app, pairing).await;
        });
        tasks.insert(id, task.inner().abort_handle());
    }
}

fn keys(app: &AppHandle, state: &AppState, pairing: &Pairing) -> Result<Keys> {
    crate::migration::ensure_account(app, state, pairing.account)?;
    if let Some(sealed) = app.state::<NwcService>().store.sealed_key(&pairing.id)? {
        let id = AccountId::new(pairing.account);
        let public = state.storage.account(id)?.identity_public_key;
        let secret = Zeroizing::new(state.session.vault().nip44_decrypt(id, &public, &sealed)?);
        let keys = Keys::parse(secret.as_str())?;
        ensure!(
            keys.public_key().to_hex() == pairing.wallet,
            "Connection identity changed."
        );
        return Ok(keys);
    }
    let seed = Zeroizing::new(
        state
            .session
            .vault()
            .wallet_storage_seed(AccountId::new(pairing.account))?,
    );
    let keys = protocol::connection_keys(&seed, PublicKey::from_hex(&pairing.client)?)?;
    ensure!(
        keys.public_key().to_hex() == pairing.wallet,
        "Connection identity changed."
    );
    Ok(keys)
}

#[tauri::command]
pub async fn nwc_pair(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, NwcService>,
    wallet: State<'_, WalletService>,
    account: i64,
    label: String,
) -> Result<String, String> {
    async {
        let label = label.trim();
        ensure!(
            !label.is_empty()
                && label.chars().count() <= 60
                && !label.chars().any(char::is_control),
            "Enter an app name."
        );
        let mint = wallet::nwc_mint(&app, &state, &wallet, account).await?;
        let client = Keys::generate();
        let seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let server = protocol::connection_keys(&seed, client.public_key())?;
        let relay = "wss://relay.getalby.com/v1";
        let pairing = Pairing {
            id: client.public_key().to_hex(),
            account,
            label: label.into(),
            mint,
            relay: relay.into(),
            client: client.public_key().to_hex(),
            wallet: server.public_key().to_hex(),
            created: now(),
            info: serde_json::to_string(&protocol::info(&server)?)?,
        };
        service.store.add(&pairing)?;
        let mut uri = url::Url::parse(&format!("nostr+walletconnect://{}", pairing.wallet))?;
        uri.query_pairs_mut()
            .append_pair("relay", relay)
            .append_pair("secret", &client.secret_key().to_secret_hex());
        service.listen(&app, pairing);
        Ok(uri.to_string())
    }
    .await
    .map_err(|e: anyhow::Error| e.to_string())
}

#[tauri::command]
pub fn nwc_connections(
    service: State<'_, NwcService>,
    account: i64,
) -> Result<Vec<Pairing>, String> {
    service
        .store
        .list()
        .map(|p| p.into_iter().filter(|p| p.account == account).collect())
        .map_err(|_| "Could not load connections.".into())
}

#[tauri::command]
pub async fn nwc_revoke(
    service: State<'_, NwcService>,
    state: State<'_, AppState>,
    wallet: State<'_, WalletService>,
    account: i64,
    id: String,
) -> Result<(), String> {
    let _gate = wallet.gate.lock().await;
    if !state.session.vault().holds(AccountId::new(account)) {
        return Err("Unlock this wallet first.".into());
    }
    service
        .store
        .revoke(&id, account)
        .map_err(|e| e.to_string())?;
    if let Some(task) = service
        .tasks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
    {
        task.abort();
    }
    service
        .waiting
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, w| w.prompt.connection != id);
    Ok(())
}

#[tauri::command]
pub fn nwc_pending(service: State<'_, NwcService>) -> Vec<Prompt> {
    let mut pending: Vec<_> = service
        .waiting
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|w| w.prompt.clone())
        .collect();
    pending.sort_by(|a, b| a.id.cmp(&b.id));
    pending
}

#[tauri::command]
pub fn nwc_answer(
    service: State<'_, NwcService>,
    state: State<'_, AppState>,
    id: String,
    allow: bool,
) -> Result<(), String> {
    let mut waiting = service.waiting.lock().unwrap_or_else(|e| e.into_inner());
    let item = waiting.get(&id).ok_or("Request expired.")?;
    if allow
        && !state
            .session
            .vault()
            .holds(AccountId::new(item.prompt.account))
    {
        return Err("Unlock this wallet first.".into());
    }
    let item = waiting.remove(&id).ok_or("Request expired.")?;
    item.answer
        .send(allow)
        .map_err(|_| "Request expired.".into())
}

struct RequestGuard<'a> {
    service: &'a NwcService,
    id: String,
}
impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        self.service
            .active_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

// Called only after signature, client key, recipient and freshness validation.
pub(super) async fn handle(
    app: &AppHandle,
    pairing: &Pairing,
    event: Event,
    outgoing: &broadcast::Sender<String>,
) -> Result<()> {
    let service = app.state::<NwcService>();
    if !service.store.active(&pairing.id) {
        return Ok(());
    }
    let id = event.id.to_hex();
    if !service
        .active_requests
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone())
    {
        return Ok(());
    }
    let _guard = RequestGuard {
        service: &service,
        id: id.clone(),
    };
    let admission = service.store.begin(&id, &pairing.id)?;
    if admission == Begin::Replay {
        if let Some(reply) = service.store.cached(&id)? {
            if !reply.is_empty() {
                let _ = outgoing.send(reply);
            }
            return Ok(());
        }
    }
    let state = app.state::<AppState>();
    let account = AccountId::new(pairing.account);
    let deadline = protocol::deadline(&event);
    if !state.session.vault().holds(account) {
        let label = state
            .storage
            .account(account)
            .map(|a| a.label)
            .unwrap_or_default();
        macos_native::notifications::notify_locked(&label);
        let _ = app.emit("nwc://unlock-needed", json!({"account":pairing.account}));
        window::show(app);
    }
    while !state.session.vault().holds(account) {
        if now() >= deadline
            || !service.store.active(&pairing.id)
            || state.storage.account(account).is_err()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let keys = keys(app, &state, pairing)?;
    let request = match protocol::decode(&event, &keys) {
        Ok(r) => r,
        Err(_) => {
            service.store.finish(&id, "")?;
            return Ok(());
        }
    };
    let result = if admission == Begin::Limited {
        failure(
            &request.method,
            "RATE_LIMITED",
            "Too many requests. Try again in a minute.",
        )
    } else if admission == Begin::Replay {
        failure(
            &request.method,
            "OTHER",
            "Previous request interrupted. Check Cashr before retrying.",
        )
    } else {
        match request.method.as_str() {
            "get_info" => success(
                "get_info",
                json!({"alias":"Cashr", "color":"#000000", "pubkey":pairing.wallet,
            "network":"mainnet", "methods":protocol::METHODS.split_whitespace().collect::<Vec<_>>(), "extensions":[]}),
            ),
            "get_balance" => {
                match wallet::nwc_balance(
                    app,
                    &state,
                    &app.state::<WalletService>(),
                    pairing.account,
                    &pairing.mint,
                )
                .await
                .and_then(protocol::balance)
                {
                    Ok(result) => result,
                    Err(_) => failure(
                        "get_balance",
                        "INTERNAL",
                        "Could not read wallet balance. Unlock Cashr and retry.",
                    ),
                }
            }
            "pay_invoice" => match protocol::payment(&request.params) {
                Ok((invoice, hash)) => pay(app, pairing, &id, invoice, hash, deadline).await,
                Err(_) => failure(
                    "pay_invoice",
                    "OTHER",
                    "Use a valid invoice for 1–10,000 sats with a matching amount.",
                ),
            },
            other => failure(
                other,
                "NOT_IMPLEMENTED",
                "This connection supports get_info, get_balance and pay_invoice.",
            ),
        }
    };
    // Log only known method names and outcome; never parameters or decrypted data.
    let method = match request.method.as_str() {
        "get_info" => "get_info",
        "get_balance" => "get_balance",
        "pay_invoice" => "pay_invoice",
        _ => "unsupported",
    };
    tracing::info!(
        method,
        failed = !result["error"].is_null(),
        "NWC request handled"
    );
    let reply = serde_json::to_string(&protocol::response(&event, &keys, result)?)?;
    service.store.finish(&id, &reply)?;
    let _ = outgoing.send(reply);
    let _ = app.emit("nwc://changed", ());
    Ok(())
}

async fn pay(
    app: &AppHandle,
    pairing: &Pairing,
    id: &str,
    invoice: String,
    hash: String,
    deadline: u64,
) -> Value {
    let method = "pay_invoice";
    let service = app.state::<NwcService>();
    let state = app.state::<AppState>();
    let wallet = app.state::<WalletService>();
    let review = match wallet::nwc_review(
        app,
        &state,
        &wallet,
        pairing.account,
        invoice,
        &pairing.mint,
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            return failure(
                method,
                "OTHER",
                "Could not review payment. Check Cashr's balance, mint and connection.",
            )
        }
    };
    let expiry = review.expiry.min(deadline).min(now() + 120);
    wallet::limit_review(&wallet, &review.quote, expiry);
    let label = state
        .storage
        .account(AccountId::new(pairing.account))
        .map(|a| a.label)
        .unwrap_or_default();
    let prompt = Prompt {
        id: id.into(),
        connection: pairing.id.clone(),
        account: pairing.account,
        account_label: label,
        app: pairing.label.clone(),
        mint: pairing.mint.clone(),
        amount: review.amount,
        max_fee: review.max_fee,
        maximum: review.maximum,
        destination: review.destination.clone(),
        expiry,
    };
    let (answer, result) = oneshot::channel();
    service
        .waiting
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.into(), Waiting { prompt, answer });
    let _ = app.emit("nwc://changed", ());
    window::show(app);
    let approved = wait_for_approval(
        result,
        Duration::from_secs(expiry.saturating_sub(now())),
        || {
            service.store.active(&pairing.id)
                && state.session.vault().holds(AccountId::new(pairing.account))
        },
    )
    .await;
    service
        .waiting
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(id);
    let _ = app.emit("nwc://changed", ());
    if !approved {
        wallet::cancel_review(&wallet, &review.quote);
        return failure(
            method,
            "RESTRICTED",
            "Payment declined or approval expired.",
        );
    }
    let _gate = wallet.gate.lock().await;
    if now() >= expiry
        || !service.store.active(&pairing.id)
        || !state.session.vault().holds(AccountId::new(pairing.account))
    {
        wallet::cancel_review(&wallet, &review.quote);
        return failure(
            method,
            "RESTRICTED",
            "Connection revoked, wallet locked, or approval expired.",
        );
    }
    let identity = match state.storage.account(AccountId::new(pairing.account)) {
        Ok(a) => a.identity_public_key.to_hex(),
        Err(_) => return failure(method, "UNAUTHORIZED", "Wallet removed."),
    };
    match service.store.claim(&identity, &hash, id) {
        Ok(true) => {}
        Ok(false) => {
            wallet::cancel_review(&wallet, &review.quote);
            return failure(
                method,
                "OTHER",
                "Payment already attempted. Check Cashr's transactions.",
            );
        }
        Err(_) => {
            wallet::cancel_review(&wallet, &review.quote);
            return failure(
                method,
                "INTERNAL",
                "Could not record payment. Nothing sent.",
            );
        }
    }
    // From here to durable response, do not cancel for timeout, lock or revocation.
    match wallet::pay_reviewed(app, &state, &wallet, pairing.account, &review.quote).await {
        Ok((_, result)) => match result.payment_proof() {
            Some(preimage)
                if result.state() == cdk::nuts::MeltQuoteState::Paid
                    && protocol::paid(preimage, &hash) =>
            {
                success(
                    method,
                    json!({"preimage":preimage,"fees_paid":u64::from(result.fee_paid())*1000}),
                )
            }
            _ => failure(
                method,
                "OTHER",
                "Payment status unknown. Check Cashr before retrying.",
            ),
        },
        Err(_) => failure(
            method,
            "OTHER",
            "Payment could not be confirmed. Check Cashr before retrying.",
        ),
    }
}

async fn wait_for_approval(
    result: oneshot::Receiver<bool>,
    duration: Duration,
    permitted: impl Fn() -> bool,
) -> bool {
    let wait = async {
        tokio::pin!(result);
        loop {
            if !permitted() {
                return false;
            }
            tokio::select! {
                result = &mut result => return matches!(result, Ok(true)) && permitted(),
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    };
    matches!(tokio::time::timeout(duration, wait).await, Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_migration_preserves_connection_keys_encrypted() {
        use nostr::nips::nip44::Nip44;
        let root = tempfile::tempdir().unwrap();
        let service = NwcService {
            store: Store::open(&root.path().join("nwc.sqlite")).unwrap(),
            tasks: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            limit: Arc::new(Semaphore::new(16)),
            active_requests: Mutex::new(HashSet::new()),
        };
        let identity = Keys::generate();
        let client = Keys::generate();
        let previous = signer_core::vault::storage_seed_for_migration(&identity, "prototype");
        let current = signer_core::vault::wallet_storage_seed(&identity);
        let server = protocol::connection_keys(&previous, client.public_key()).unwrap();
        let id = client.public_key().to_hex();
        service
            .store
            .add(&Pairing {
                id: id.clone(),
                account: 1,
                label: "Jumble".into(),
                mint: "mint".into(),
                relay: "relay".into(),
                client: client.public_key().to_hex(),
                wallet: server.public_key().to_hex(),
                created: now(),
                info: "{}".into(),
            })
            .unwrap();
        let seal = |secret: &str| Ok(identity.nip44_encrypt(&identity.public_key(), secret)?);
        service
            .preserve_connection_keys(1, &previous, seal)
            .unwrap();
        let saved = service.store.sealed_key(&id).unwrap().unwrap();
        assert_ne!(saved, server.secret_key().to_secret_hex());
        let opened = identity
            .nip44_decrypt(&identity.public_key(), &saved)
            .unwrap();
        assert_eq!(
            Keys::parse(&opened).unwrap().public_key(),
            server.public_key()
        );
        assert_ne!(
            protocol::connection_keys(&current, client.public_key())
                .unwrap()
                .public_key(),
            server.public_key()
        );
        // Retrying conversion must not replace a connection already preserved.
        service.preserve_connection_keys(1, &current, seal).unwrap();
        assert_eq!(service.store.sealed_key(&id).unwrap().unwrap(), saved);
    }

    #[tokio::test]
    async fn approval_requires_an_explicit_yes_and_fails_closed() {
        let (send, receive) = oneshot::channel();
        let waiting = wait_for_approval(receive, Duration::from_secs(1), || true);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        send.send(true).unwrap();
        assert!(waiting.await);
        let (send, receive) = oneshot::channel();
        send.send(false).unwrap();
        assert!(!wait_for_approval(receive, Duration::from_secs(1), || true).await);
        let (send, receive) = oneshot::channel();
        send.send(true).unwrap();
        assert!(!wait_for_approval(receive, Duration::from_secs(1), || false).await);
        let (_send, receive) = oneshot::channel();
        assert!(!wait_for_approval(receive, Duration::from_millis(1), || true).await);
        let (send, receive) = oneshot::channel();
        drop(send);
        assert!(!wait_for_approval(receive, Duration::from_secs(1), || true).await);
    }
}
