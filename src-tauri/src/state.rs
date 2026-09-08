//! What the app holds while it runs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use macos_native::notifications::{self, NotificationApprover};
use macos_native::{passphrase, KeychainKeyStore, PassphraseStore};
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
    auth_epoch: AtomicU64,
    pub window: WindowState,
}

impl AppState {
    pub fn build(
        app: &AppHandle,
        storage: Storage,
        keys_dir: PathBuf,
        passphrase_file: PathBuf,
        bundle_id: &str,
    ) -> Result<Self> {
        let storage = Arc::new(storage);
        storage.prune_pairings()?;
        storage.prune_activity()?;

        let keystore = Arc::new(FileKeyStore::new(keys_dir)?);
        let keychain = Arc::new(KeychainKeyStore::new(bundle_id));

        // An earlier version kept the passphrase in the Keychain, where every
        // rebuild made the app a stranger to its own item. Nothing reads that
        // item any more, so the only thing left to do with it is take it away.
        passphrase::forget_keychain_copy(bundle_id);
        let passphrases = Arc::new(PassphraseStore::new(passphrase_file));
        let approver = NotificationApprover::new();
        notifications::install(approver.clone());

        let vault = Arc::new(Vault::new());
        let session = Arc::new(Session::new(SessionParts {
            storage: Arc::clone(&storage),
            vault: Arc::clone(&vault),
            keystore: keystore.clone(),
            approver: approver.clone(),
            notifier: Arc::new(WindowNotifier {
                app: app.clone(),
                storage: Arc::clone(&storage),
            }),
            config: SessionConfig::default(),
        }));

        let transport = Arc::new(RelayTransport::new(vault));
        let runner = Runner::new(Arc::clone(&session), transport);

        Ok(Self {
            storage,
            session,
            runner,
            approver,
            keystore,
            keychain,
            passphrases,
            auth_epoch: AtomicU64::new(0),
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

    /// macOS authentication gates both first setup and recovery of local access.
    pub(crate) async fn prepare_touch_id(&self) -> Result<()> {
        let _dialog = self.window.hold_for_dialog();
        let epoch = self.auth_epoch.load(Ordering::SeqCst);
        let secret = self.passphrases.load_or_create().await?;
        anyhow::ensure!(
            epoch == self.auth_epoch.load(Ordering::SeqCst),
            "Unlock cancelled."
        );
        self.keystore.set_passphrase(secret.expose_secret());
        Ok(())
    }

    pub async fn unlock_with_touch_id(&self, account: Option<AccountId>) -> Result<()> {
        let _dialog = self.window.hold_for_dialog();
        let epoch = self.auth_epoch.load(Ordering::SeqCst);
        if !self.passphrases.is_set() {
            anyhow::bail!("Recover this wallet with your recovery words to enable Touch ID.");
        }
        let secret = self.passphrases.load().await?;
        anyhow::ensure!(
            epoch == self.auth_epoch.load(Ordering::SeqCst),
            "Unlock cancelled."
        );
        let result = self.unlock_with(secret.expose_secret(), account).await;
        if epoch != self.auth_epoch.load(Ordering::SeqCst) {
            self.lock();
            anyhow::bail!("Unlock cancelled.");
        }
        result
    }

    /// The phrase proves the wallet identity. Only inaccessible local keys
    /// are replaced; the Cashu database and its encryption material stay put.
    pub(crate) async fn restore_account_keys(
        &self,
        account: &Account,
        identity: &Keys,
    ) -> Result<()> {
        anyhow::ensure!(
            identity.public_key() == account.identity_public_key,
            "recovery identity mismatch"
        );
        let handles = [
            KeyHandle::new(account.id, KeyRole::Identity),
            KeyHandle::new(account.id, KeyRole::Transport),
        ];
        if let Ok(keys) = self.keystore.load_many(&handles).await {
            anyhow::ensure!(
                keys[0].public_key() == account.identity_public_key,
                "stored identity mismatch"
            );
            self.storage
                .set_signer_public_key(account.id, keys[1].public_key())?;
            return Ok(());
        }
        let backup = if self.keystore.holds(account.id) {
            Some(self.keystore.recovery_backup(account.id)?)
        } else {
            None
        };
        let transport = Keys::generate();
        let keys = AccountKeys {
            identity: identity.secret_key().clone(),
            transport: transport.secret_key().clone(),
        };
        self.keystore.store(account.id, &keys).await?;
        let checked = self.keystore.load_many(&handles).await?;
        anyhow::ensure!(
            checked[0].public_key() == identity.public_key()
                && checked[1].public_key() == transport.public_key(),
            "could not verify recovered keys"
        );
        self.storage
            .set_signer_public_key(account.id, transport.public_key())?;
        if let Some(backup) = backup {
            backup.commit();
        }
        self.runner.stop(account.id).await;
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

    /// Unlock the selected account with the device password after macOS authentication.
    async fn unlock_with(&self, passphrase: &str, selected: Option<AccountId>) -> Result<()> {
        if passphrase.is_empty() {
            anyhow::bail!("the passphrase cannot be empty");
        }
        self.keystore.set_passphrase(passphrase);

        let mut accounts = match selected {
            Some(id) => vec![self.storage.account(id)?],
            None => self.accounts()?,
        };
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

        for account in &mut accounts {
            if self.session.vault().identity_public_key(account.id)? != account.identity_public_key
            {
                self.lock();
                anyhow::bail!("Stored wallet identity does not match.");
            }
            let transport = self.session.vault().transport_public_key(account.id)?;
            if transport != account.signer_public_key {
                // Complete a recovery interrupted between replacing the encrypted
                // key file and updating its public metadata.
                self.storage.set_signer_public_key(account.id, transport)?;
                account.signer_public_key = transport;
                self.runner.stop(account.id).await;
            }
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
        self.auth_epoch.fetch_add(1, Ordering::SeqCst);
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

    /// Store the identity derived from the wallet's recovery phrase.
    pub(crate) async fn add_account(&self, label: String, identity: Keys) -> Result<Account> {
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
        self.storage.account(id)?;
        self.runner.stop(id).await;
        self.session.vault().forget(id);
        self.keystore.delete(id).await?;
        // Any copy left over from before the move is part of the account too.
        self.keychain.delete(id).await?;
        self.storage.delete_account(id)?;
        Ok(())
    }
}
