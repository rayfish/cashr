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
use signer_core::keystore::{AccountKeys, KeyStore};
use signer_core::runner::Runner;
use signer_core::session::{Session, SessionConfig, SessionParts};
use signer_core::storage::{NewAccount, Storage};
use signer_core::vault::Vault;
use tauri::{AppHandle, Emitter};

use crate::window::WindowState;

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
    pub window: WindowState,
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
            window: WindowState::default(),
        })
    }

    pub fn accounts(&self) -> Result<Vec<Account>> {
        Ok(self.storage.accounts()?)
    }

    /// Connect every account's relays.
    ///
    /// Called at launch, before anything is unlocked. Listening does not need
    /// the keys: a request that arrives while the signer is locked is held by
    /// the session and answered after the unlock. Waiting for the unlock to
    /// connect would make that impossible, because nothing would have been
    /// there to hear the request.
    pub async fn start_listening(&self) -> Result<()> {
        for account in self.accounts()? {
            self.runner.ensure(account).await?;
        }
        Ok(())
    }

    /// Unlock every account and answer whatever arrived while locked.
    pub async fn unlock(&self) -> Result<()> {
        let accounts = self.accounts()?;
        let ids: Vec<AccountId> = accounts.iter().map(|a| a.id).collect();
        self.session.unlock(&ids).await?;

        // Ensure rather than start: an account already listening keeps its
        // connections, and one added since launch gets its own.
        for account in &accounts {
            self.runner.ensure(account.clone()).await?;
        }

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
        // account with no keys rather than keys with no account. If the write
        // fails the row goes too, so a half-made account cannot sit there
        // looking usable.
        let keys = AccountKeys {
            identity: identity.secret_key().clone(),
            transport: transport.secret_key().clone(),
        };
        if let Err(error) = self.keystore.store(account.id, &keys).await {
            self.storage.delete_account(account.id)?;
            return Err(error.into());
        }

        // Listening starts now rather than at the next launch, so a client can
        // be paired with the account as soon as it exists. A relay that will
        // not come up is not a reason to report the account as failed.
        if let Err(error) = self.runner.ensure(account.clone()).await {
            tracing::warn!("could not start listening for the new account: {error}");
        }

        Ok(account)
    }

    /// Point an account at a different relay list and reconnect.
    ///
    /// Without the restart the new list would only take effect on the next
    /// launch, which looks exactly like the setting not working.
    pub async fn set_relays(&self, id: AccountId, relays: &[RelayUrl]) -> Result<()> {
        self.storage.set_account_relays(id, relays)?;
        if self.session.vault().holds(id) {
            self.runner.start(self.storage.account(id)?).await?;
        }
        Ok(())
    }

    /// Remove an account, its keys and everything hanging off it.
    pub async fn delete_account(&self, id: AccountId) -> Result<()> {
        self.runner.stop(id).await;
        self.keystore.delete(id).await?;
        self.storage.delete_account(id)?;
        Ok(())
    }
}
