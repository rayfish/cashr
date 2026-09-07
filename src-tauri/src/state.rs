//! What the app holds while it runs.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use macos_native::notifications::{self, NotificationApprover};
use macos_native::{KeychainKeyStore, PassphraseStore};
use nostr::key::Keys;
use nostr::types::RelayUrl;
use relay_transport::RelayTransport;
use secrecy::ExposeSecret;
use signer_core::account::{Account, AccountId};
use signer_core::approval::{Notifier, SignerEvent};
use signer_core::keyfile::FileKeyStore;
use signer_core::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore};
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

/// Forwards core events to the window as Tauri events, and to Notification
/// Center where the user needs to know without the window being open.
struct WindowNotifier {
    app: AppHandle,
    storage: Arc<Storage>,
}

impl WindowNotifier {
    /// The account's label, falling back to its id. A notification naming a
    /// number is worth more than no notification.
    fn label(&self, account: AccountId) -> String {
        self.storage
            .account(account)
            .map(|account| account.label)
            .unwrap_or_else(|_| format!("account {account}"))
    }
}

impl Notifier for WindowNotifier {
    fn notify(&self, event: SignerEvent) {
        let (name, payload) = match event {
            SignerEvent::Unlocked => {
                notifications::clear_locked();
                ("signer://unlocked", serde_json::Value::Null)
            }
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
            SignerEvent::UnlockNeeded { account } => {
                // The client is waiting and the window is probably closed, so
                // this has to leave the app to be seen at all. The request is
                // held by the session and answered once the keys are loaded.
                notifications::notify_locked(&self.label(account));
                (
                    "signer://unlock-needed",
                    serde_json::json!({ "account": account.get() }),
                )
            }
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
    /// The key files. Private: the only thing outside this module needs to
    /// know is whether the signer is open, and that is `has_passphrase`.
    keystore: Arc<FileKeyStore>,
    /// Where keys used to live. Kept only to migrate accounts off it, and to
    /// clear an account's old copy when the user asks. Once no install in the
    /// field has an account left in the Keychain, this and the crate behind it
    /// can go.
    keychain: Arc<KeychainKeyStore>,
    /// The passphrase behind Touch ID, when the user has asked for that.
    passphrases: Arc<PassphraseStore>,
    pub window: WindowState,
}

impl AppState {
    pub fn build(
        app: &AppHandle,
        storage: Storage,
        keys_dir: PathBuf,
        bundle_id: &str,
    ) -> Result<Self> {
        let storage = Arc::new(storage);
        storage.prune_pairings()?;
        storage.prune_activity()?;

        let keystore = Arc::new(FileKeyStore::new(keys_dir)?);
        let keychain = Arc::new(KeychainKeyStore::new(bundle_id));
        let passphrases = Arc::new(PassphraseStore::new(bundle_id));
        let approver = NotificationApprover::new();
        notifications::install(approver.clone());

        let session = Arc::new(Session::new(SessionParts {
            storage: Arc::clone(&storage),
            vault: Arc::new(Vault::new()),
            keystore: keystore.clone(),
            approver: approver.clone(),
            notifier: Arc::new(WindowNotifier {
                app: app.clone(),
                storage: Arc::clone(&storage),
            }),
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
            keychain,
            passphrases,
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

    /// Whether any account still has its keys only in the Keychain.
    ///
    /// What the window asks to decide whether the passphrase box is setting a
    /// passphrase for the first time or being asked for one that exists.
    pub fn needs_migration(&self) -> bool {
        self.accounts()
            .map(|accounts| {
                accounts
                    .iter()
                    .any(|account| !self.keystore.holds(account.id))
            })
            .unwrap_or(false)
    }

    /// Whether any account has an old Keychain copy still sitting there.
    ///
    /// The window asks this on every refresh, which is after every request, so
    /// it goes through `holds` rather than reading a key. Reading is what puts
    /// the macOS password dialog on screen, and the answer to "is the old copy
    /// still there" is not worth a dialog.
    pub fn has_keychain_copies(&self) -> bool {
        self.accounts()
            .unwrap_or_default()
            .iter()
            .any(|account| self.keychain.holds(account.id).unwrap_or(false))
    }

    /// Unlock with a typed passphrase, and keep it for Touch ID if asked.
    pub async fn unlock(&self, passphrase: &str, remember: bool) -> Result<()> {
        self.unlock_with(passphrase).await?;

        // Only after the unlock worked. Storing a passphrase that opens
        // nothing would set up a Touch ID that fails every time, and the user
        // would have no way to tell that from the sensor being at fault.
        if remember {
            if let Err(error) = self.passphrases.store(passphrase) {
                // The unlock stands. Touch ID is a convenience, and losing it
                // is not a reason to refuse an unlock that has already worked.
                tracing::warn!("could not store the passphrase for Touch ID: {error}");
            }
        }
        Ok(())
    }

    /// Unlock with the passphrase kept behind Touch ID.
    ///
    /// A stored passphrase that no longer opens the files is deleted rather
    /// than left to fail again tomorrow. It cannot be repaired from here, and
    /// the passphrase box behind it still works.
    pub async fn unlock_with_touch_id(&self) -> Result<()> {
        let passphrase = self.passphrases.load().await?;
        match self.unlock_with(passphrase.expose_secret()).await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::warn!("the stored passphrase did not unlock; forgetting it");
                let _ = self.passphrases.forget();
                Err(error)
            }
        }
    }

    /// Stop offering Touch ID and delete the stored passphrase.
    pub fn forget_touch_id(&self) -> Result<()> {
        self.passphrases.forget()?;
        Ok(())
    }

    /// Whether Touch ID unlocking is set up. Silent, so the window can ask on
    /// every refresh.
    pub fn has_touch_id(&self) -> bool {
        self.passphrases.is_set()
    }

    /// Whether a passphrase is loaded, which is what makes the key files
    /// readable and a new account writable.
    pub fn has_passphrase(&self) -> bool {
        self.keystore.has_passphrase()
    }

    /// Whether any account's keys are loaded.
    pub fn is_unlocked(&self) -> bool {
        self.session.vault().is_unlocked()
    }

    /// Unlock every account and answer whatever arrived while locked.
    ///
    /// The passphrase is what opens the key files, and it is also what any
    /// account still living in the Keychain is migrated onto on the way
    /// through. That is deliberately the same step: an unlock that left half
    /// the accounts behind would be an unlock that has to be explained.
    async fn unlock_with(&self, passphrase: &str) -> Result<()> {
        if passphrase.is_empty() {
            anyhow::bail!("the passphrase cannot be empty");
        }
        self.keystore.set_passphrase(passphrase);

        let accounts = self.accounts()?;
        for account in &accounts {
            if !self.keystore.holds(account.id) {
                self.migrate(account.id).await?;
            }
        }

        let ids: Vec<AccountId> = accounts.iter().map(|a| a.id).collect();
        if let Err(error) = self.session.unlock(&ids).await {
            // A passphrase that opened nothing must not stay behind looking
            // like a working one, or the next account created would be sealed
            // with something the user never chose.
            self.keystore.clear_passphrase();
            return Err(error.into());
        }

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
        self.keystore.clear_passphrase();
    }

    /// Move one account's keys out of the Keychain and into a key file.
    ///
    /// This is the last time the Keychain is read, and it costs the one
    /// password dialog it has always cost. What comes out is encrypted under
    /// the passphrase, written, and then read back and compared before the
    /// migration is called done: a key file that does not decrypt to what went
    /// into it is an account nobody can unlock again.
    ///
    /// The Keychain copy is left alone. Deleting a key is not something to do
    /// on the way past, so it is a separate thing the user asks for.
    async fn migrate(&self, account: AccountId) -> Result<()> {
        let handles = [
            KeyHandle::new(account, KeyRole::Identity),
            KeyHandle::new(account, KeyRole::Transport),
        ];
        let old = self.keychain.load_many(&handles).await?;
        let [identity, transport] = old.as_slice() else {
            anyhow::bail!("the Keychain returned the wrong number of keys");
        };

        let keys = AccountKeys {
            identity: identity.secret_key().clone(),
            transport: transport.secret_key().clone(),
        };
        self.keystore.store(account, &keys).await?;

        let written = self.keystore.load_many(&handles).await?;
        if written.len() != old.len()
            || written
                .iter()
                .zip(old.iter())
                .any(|(a, b)| a.secret_key() != b.secret_key())
        {
            self.keystore.delete(account).await?;
            anyhow::bail!("the migrated keys did not read back; nothing was changed");
        }

        tracing::info!(%account, "keys migrated out of the Keychain");
        Ok(())
    }

    /// Delete the Keychain copies now that the key files are the real ones.
    ///
    /// Refuses while anything is unmigrated, so this can never be the step
    /// that loses a key.
    pub async fn forget_keychain(&self) -> Result<()> {
        if self.needs_migration() {
            anyhow::bail!("unlock first, so the keys are somewhere else before this removes them");
        }
        for account in self.accounts()? {
            self.keychain.delete(account.id).await?;
        }
        Ok(())
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
        // Without one there is nothing to seal the new key with, and an
        // account whose keys cannot be written is an account that should not
        // be made.
        if !self.keystore.has_passphrase() {
            anyhow::bail!("unlock the signer first, so there is a passphrase to protect the key");
        }

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
        // Any copy left over from before the move is part of the account too.
        self.keychain.delete(id).await?;
        self.storage.delete_account(id)?;
        Ok(())
    }
}
