//! What the app holds while it runs.

use std::sync::Arc;

use anyhow::Result;
use macos_native::notifications::NotificationApprover;
use macos_native::KeychainKeyStore;
use nostr::key::Keys;
use nostr::types::RelayUrl;
use relay_transport::RelayTransport;
use signer_core::account::{Account, AccountId};
use signer_core::approval::{Notifier, SignerEvent};
use signer_core::keystore::{KeyHandle, KeyRole, KeyStore};
use signer_core::runner::Runner;
use signer_core::session::{Session, SessionConfig, SessionParts};
use signer_core::storage::{NewAccount, Storage};
use signer_core::vault::Vault;
use signer_core::AsyncMutex;
use tauri::{AppHandle, Emitter};
use tokio::task::JoinHandle;

/// Relays the signer listens on when an account does not name its own.
///
/// Shipping defaults means pairing works out of the box; the cost is that
/// these operators see NIP-46 traffic and connection timing, which is why the
/// window shows per-relay health and the list is editable.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.nsec.app",
    "wss://relay.damus.io",
    "wss://nos.lol",
];

/// Forwards core events to the window as Tauri events.
struct WindowNotifier {
    app: AppHandle,
}

impl Notifier for WindowNotifier {
    fn notify(&self, event: SignerEvent) {
        let (name, payload) = match event {
            SignerEvent::Unlocked => ("signer://unlocked", serde_json::Value::Null),
            SignerEvent::Locked => ("signer://locked", serde_json::Value::Null),
            SignerEvent::RelayStatus {
                account,
                relay,
                connected,
            } => (
                "signer://relay",
                serde_json::json!({ "account": account.get(), "relay": relay, "connected": connected }),
            ),
            SignerEvent::ClientConnected { account, client } => (
                "signer://client-connected",
                serde_json::json!({ "account": account.get(), "client": client.get() }),
            ),
            SignerEvent::RequestHandled {
                account, client, ..
            } => (
                "signer://request-handled",
                serde_json::json!({ "account": account.get(), "client": client.get() }),
            ),
            SignerEvent::UnlockNeeded { account } => (
                "signer://unlock-needed",
                serde_json::json!({ "account": account.get() }),
            ),
        };

        if let Err(error) = self.app.emit(name, payload) {
            tracing::debug!("could not reach the window: {error}");
        }
    }
}

pub struct AppState {
    pub storage: Arc<Storage>,
    pub session: Arc<Session>,
    pub runner: Runner,
    pub approver: Arc<NotificationApprover>,
    pub keystore: Arc<KeychainKeyStore>,
    tasks: AsyncMutex<Vec<JoinHandle<()>>>,
}

impl AppState {
    pub fn build(app: &AppHandle, storage: Storage, bundle_id: &str) -> Result<Self> {
        let storage = Arc::new(storage);
        storage.prune_pairings()?;
        storage.prune_activity()?;

        let keystore = Arc::new(KeychainKeyStore::new(bundle_id));
        let approver = NotificationApprover::new();
        macos_native::notifications::install(approver.clone());

        let session = Arc::new(Session::new(SessionParts {
            storage: Arc::clone(&storage),
            vault: Arc::new(Vault::new()),
            keystore: keystore.clone(),
            approver: approver.clone(),
            notifier: Arc::new(WindowNotifier { app: app.clone() }),
            config: SessionConfig::default(),
        }));

        let transport = Arc::new(RelayTransport::new());
        let runner = Runner::new(Arc::clone(&session), transport);

        Ok(Self {
            storage,
            session,
            runner,
            approver,
            keystore,
            tasks: AsyncMutex::new(Vec::new()),
        })
    }

    pub fn accounts(&self) -> Result<Vec<Account>> {
        Ok(self.storage.accounts()?)
    }

    /// Unlock every account, start their listening loops, and answer whatever
    /// arrived while locked.
    pub async fn unlock(&self) -> Result<()> {
        let accounts = self.accounts()?;
        let ids: Vec<AccountId> = accounts.iter().map(|a| a.id).collect();
        self.session.unlock(&ids).await?;

        let mut tasks = self.tasks.lock().await;
        if tasks.is_empty() {
            for account in &accounts {
                tasks.push(self.runner.start(account.clone()).await?);
            }
        }
        drop(tasks);

        self.runner.replay_deferred(&accounts).await?;
        Ok(())
    }

    pub fn lock(&self) {
        self.session.lock();
    }

    /// Create a fresh identity, its transport key, and the account row.
    pub async fn create_account(&self, label: String) -> Result<Account> {
        self.add_account(label, Keys::generate()).await
    }

    /// Take an existing key. Accepts nsec or hex.
    pub async fn import_account(&self, label: String, secret: &str) -> Result<Account> {
        Ok(self.add_account(label, Keys::parse(secret)?).await?)
    }

    async fn add_account(&self, label: String, identity: Keys) -> Result<Account> {
        let transport = Keys::generate();
        let relays: Vec<RelayUrl> = DEFAULT_RELAYS
            .iter()
            .filter_map(|url| RelayUrl::parse(url).ok())
            .collect();

        let is_first = self.storage.accounts()?.is_empty();
        let account = self.storage.insert_account(NewAccount {
            identity_public_key: identity.public_key(),
            signer_public_key: transport.public_key(),
            label,
            relays,
            is_default: is_first,
        })?;

        // Keys go in only after the row exists, so a failed write leaves an
        // account with no keys rather than keys with no account.
        let store = |role, keys: &Keys| {
            self.keystore
                .store(KeyHandle::new(account.id, role), keys.secret_key().clone())
        };
        if let Err(error) = store(KeyRole::Identity, &identity).await {
            self.storage.delete_account(account.id)?;
            return Err(error.into());
        }
        if let Err(error) = store(KeyRole::Transport, &transport).await {
            self.storage.delete_account(account.id)?;
            return Err(error.into());
        }

        Ok(account)
    }

    /// Remove an account, its keys and everything hanging off it.
    pub async fn delete_account(&self, id: AccountId) -> Result<()> {
        self.keystore
            .delete(KeyHandle::new(id, KeyRole::Identity))
            .await?;
        self.keystore
            .delete(KeyHandle::new(id, KeyRole::Transport))
            .await?;
        self.storage.delete_account(id)?;
        Ok(())
    }
}
