//! Keys encrypted at rest with a passphrase, in files this app owns.
//!
//! The macOS Keychain holds a secret in the clear and lets an access control
//! list decide who may read it. That makes the operating system the boundary,
//! and it is a boundary bound to a code signature: a rebuilt app is a stranger
//! to an item it wrote yesterday, which reaches the user as a password dialog
//! that no amount of answering makes go away.
//!
//! This does it the other way round, which is how a password manager does it.
//! The bytes on disk are useless without the passphrase, so what protects them
//! travels with the file rather than with the process that wrote it. The
//! format is NIP-49 (`ncryptsec`: scrypt, then XChaCha20-Poly1305), so a key
//! written here is not trapped here.
//!
//! The passphrase is held for the session and cleared on lock. It arrives
//! out of band, through [`FileKeyStore::set_passphrase`], because the
//! [`KeyStore`] trait is shared with backends that have no such notion.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard};

use async_trait::async_trait;
use nostr::key::{Keys, SecretKey};
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::account::AccountId;
use crate::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore, KeyStoreError};

/// scrypt work factor, as `log2(N)`.
///
/// NIP-49 suggests 16. That is about a second of work on this hardware, which
/// is paid once per unlock and is the whole defence if the file is ever
/// copied, so it is not somewhere to economise.
const LOG_N: u8 = 16;

/// Both of an account's keys, each encrypted on its own.
///
/// Two `ncryptsec` strings rather than one blob of JSON: each is a standard
/// NIP-49 key that any other nostr tool can take, so a user who wants their
/// identity key out of here is not asking for a favour.
#[derive(Serialize, Deserialize)]
struct StoredKeys {
    identity: String,
    transport: String,
}

impl StoredKeys {
    fn role(&self, role: KeyRole) -> &str {
        match role {
            KeyRole::Identity => &self.identity,
            KeyRole::Transport => &self.transport,
        }
    }
}

pub struct FileKeyStore {
    dir: PathBuf,
    /// Held for the session, cleared on lock. `None` means nothing here can be
    /// read or written, which is the locked state.
    passphrase: RwLock<Option<SecretString>>,
    log_n: u8,
}

impl FileKeyStore {
    /// `dir` is created if it does not exist, and made unreadable to anyone
    /// else. Nothing is decrypted at rest, so this is depth rather than the
    /// defence, but a key file with a permission bit missing is still a key
    /// file that did not need to be world readable.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| io_error("could not make the key directory", e))?;
        restrict(&dir)?;
        Ok(Self {
            dir,
            passphrase: RwLock::new(None),
            log_n: LOG_N,
        })
    }

    /// The same store with the work factor turned down.
    ///
    /// Tests only. A second of scrypt per key is the point in production and
    /// dead weight in a test that is checking the plumbing around it.
    #[cfg(test)]
    fn with_log_n(dir: impl Into<PathBuf>, log_n: u8) -> Result<Self, KeyStoreError> {
        Ok(Self {
            log_n,
            ..Self::new(dir)?
        })
    }

    /// Hand over the passphrase for this session.
    ///
    /// Nothing is checked here. A wrong passphrase is indistinguishable from a
    /// right one until something is decrypted with it, which is a property of
    /// the format rather than an oversight: there is no verifier to check
    /// against, and adding one would be adding an oracle.
    pub fn set_passphrase(&self, passphrase: &str) {
        *self.write() = Some(SecretString::from(passphrase.to_string()));
    }

    pub fn clear_passphrase(&self) {
        *self.write() = None;
    }

    pub fn has_passphrase(&self) -> bool {
        self.read().is_some()
    }

    /// Whether this account's keys have been written here yet.
    ///
    /// What the app asks to decide between unlocking and migrating.
    pub fn holds(&self, account: AccountId) -> bool {
        self.path(account).is_file()
    }

    /// Whether any account has keys here. False on a signer that has accounts
    /// but has never been given a passphrase.
    pub fn is_empty(&self) -> bool {
        fs::read_dir(&self.dir)
            .map(|entries| {
                !entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.ends_with(".json"))
                })
            })
            .unwrap_or(true)
    }

    fn path(&self, account: AccountId) -> PathBuf {
        self.dir.join(format!("account.{account}.json"))
    }

    fn stored(&self, account: AccountId) -> Result<StoredKeys, KeyStoreError> {
        let path = self.path(account);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(KeyStoreError::NotFound(KeyHandle::new(
                    account,
                    KeyRole::Identity,
                )))
            }
            Err(e) => return Err(io_error("could not read the key file", e)),
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| KeyStoreError::Backend(format!("key file is unreadable: {e}")))
    }

    fn decrypt(&self, stored: &StoredKeys, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
        let passphrase = self.read();
        let passphrase = passphrase.as_ref().ok_or(KeyStoreError::NoPassphrase)?;

        let encrypted = EncryptedSecretKey::from_bech32(stored.role(handle.role))
            .map_err(|e| KeyStoreError::Backend(format!("stored key is unreadable: {e}")))?;

        // Every failure here is the same failure in practice. The ciphertext
        // is authenticated, so a wrong passphrase fails the tag check exactly
        // as a tampered file does, and telling them apart is not something the
        // user can act on differently.
        let secret = encrypted
            .decrypt(passphrase.expose_secret())
            .map_err(|_| KeyStoreError::BadPassphrase)?;
        Ok(Keys::new(secret))
    }

    fn encrypt(&self, secret: &SecretKey) -> Result<String, KeyStoreError> {
        let passphrase = self.read();
        let passphrase = passphrase.as_ref().ok_or(KeyStoreError::NoPassphrase)?;

        // `Medium` says this key is not known to have been handled insecurely.
        // Which is the truth for a generated key, and a lie for one migrated
        // out of the Keychain, where it sat in the clear. The caller that
        // knows the difference cannot express it through this trait, so the
        // honest reading is that this field describes the format, not the
        // history, and nothing in this app reads it back.
        EncryptedSecretKey::new(
            secret,
            passphrase.expose_secret(),
            self.log_n,
            KeySecurity::Medium,
        )
        .map_err(|e| KeyStoreError::Backend(format!("could not encrypt the key: {e}")))?
        .to_bech32()
        .map_err(|e| KeyStoreError::Backend(format!("could not encode the key: {e}")))
    }

    fn read(&self) -> RwLockReadGuard<'_, Option<SecretString>> {
        self.passphrase
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<SecretString>> {
        self.passphrase
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn load(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
        let stored = self.stored(handle.account)?;
        self.decrypt(&stored, handle)
    }

    /// Encrypting is the slow part, so both keys are done under one call and
    /// the file is replaced whole. A half-written key file is an account that
    /// cannot be unlocked, so the write goes to a temporary neighbour and is
    /// renamed over the top, which on the same filesystem is atomic.
    async fn store(&self, account: AccountId, keys: &AccountKeys) -> Result<(), KeyStoreError> {
        let stored = StoredKeys {
            identity: self.encrypt(&keys.identity)?,
            transport: self.encrypt(&keys.transport)?,
        };
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| KeyStoreError::Backend(format!("cannot serialise keys: {e}")))?;

        let path = self.path(account);
        let temp = path.with_extension("json.new");
        fs::write(&temp, &bytes).map_err(|e| io_error("could not write the key file", e))?;
        restrict(&temp)?;
        fs::rename(&temp, &path).map_err(|e| io_error("could not replace the key file", e))?;
        Ok(())
    }

    async fn delete(&self, account: AccountId) -> Result<(), KeyStoreError> {
        match fs::remove_file(self.path(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_error("could not remove the key file", e)),
        }
    }

    /// One scrypt run per key, and one file read per account.
    ///
    /// There is no prompt to save here, unlike the Keychain backend: the
    /// passphrase was given once, before this was called. What is saved is the
    /// file read, which matters less, and the shape is kept the same so the
    /// two backends stay interchangeable.
    async fn load_many(&self, handles: &[KeyHandle]) -> Result<Vec<Keys>, KeyStoreError> {
        let mut cached: Option<(AccountId, StoredKeys)> = None;
        let mut keys = Vec::with_capacity(handles.len());

        for handle in handles {
            let stored = match &cached {
                Some((account, stored)) if *account == handle.account => stored,
                _ => {
                    cached = Some((handle.account, self.stored(handle.account)?));
                    &cached.as_ref().expect("just set").1
                }
            };
            keys.push(self.decrypt(stored, *handle)?);
        }

        Ok(keys)
    }
}

fn io_error(what: &str, error: io::Error) -> KeyStoreError {
    KeyStoreError::Backend(format!("{what}: {error}"))
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| io_error("could not restrict the key file", e))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), KeyStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FileKeyStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileKeyStore::with_log_n(dir.path(), 8).expect("store opens");
        (dir, store)
    }

    fn account_keys() -> AccountKeys {
        AccountKeys {
            identity: Keys::generate().secret_key().clone(),
            transport: Keys::generate().secret_key().clone(),
        }
    }

    #[tokio::test]
    async fn keys_round_trip_through_the_passphrase() {
        let (_dir, store) = store();
        let id = AccountId::new(1);
        let keys = account_keys();
        store.set_passphrase("correct horse battery staple");
        store.store(id, &keys).await.expect("keys write");

        let loaded = store
            .load(KeyHandle::new(id, KeyRole::Identity))
            .await
            .expect("identity loads");
        assert_eq!(loaded.secret_key(), &keys.identity);

        let loaded = store
            .load(KeyHandle::new(id, KeyRole::Transport))
            .await
            .expect("transport loads");
        assert_eq!(loaded.secret_key(), &keys.transport);
    }

    #[tokio::test]
    async fn the_wrong_passphrase_says_so_and_yields_nothing() {
        let (_dir, store) = store();
        let id = AccountId::new(1);
        store.set_passphrase("right");
        store.store(id, &account_keys()).await.expect("keys write");

        store.set_passphrase("wrong");
        let error = store
            .load(KeyHandle::new(id, KeyRole::Identity))
            .await
            .expect_err("a wrong passphrase is refused");
        assert!(matches!(error, KeyStoreError::BadPassphrase));
    }

    #[tokio::test]
    async fn nothing_can_be_read_without_a_passphrase() {
        let (_dir, store) = store();
        let id = AccountId::new(1);
        store.set_passphrase("right");
        store.store(id, &account_keys()).await.expect("keys write");

        store.clear_passphrase();
        let error = store
            .load(KeyHandle::new(id, KeyRole::Identity))
            .await
            .expect_err("locking means locked");
        assert!(matches!(error, KeyStoreError::NoPassphrase));
    }

    #[tokio::test]
    async fn what_lands_on_disk_is_not_the_key() {
        let (dir, store) = store();
        let id = AccountId::new(1);
        let keys = account_keys();
        store.set_passphrase("passphrase");
        store.store(id, &keys).await.expect("keys write");

        let raw = fs::read_to_string(dir.path().join("account.1.json")).expect("file reads");
        assert!(!raw.contains(&keys.identity.to_secret_hex()));
        assert!(!raw.contains(&keys.transport.to_secret_hex()));
        // A standard NIP-49 key, so it is not trapped in this app.
        assert!(raw.contains("ncryptsec1"));
    }

    #[tokio::test]
    async fn both_keys_come_back_in_the_order_asked_for() {
        let (_dir, store) = store();
        let id = AccountId::new(1);
        let keys = account_keys();
        store.set_passphrase("passphrase");
        store.store(id, &keys).await.expect("keys write");

        let loaded = store
            .load_many(&[
                KeyHandle::new(id, KeyRole::Identity),
                KeyHandle::new(id, KeyRole::Transport),
            ])
            .await
            .expect("both load");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].secret_key(), &keys.identity);
        assert_eq!(loaded[1].secret_key(), &keys.transport);
    }

    #[tokio::test]
    async fn an_account_with_no_file_is_not_found() {
        let (_dir, store) = store();
        store.set_passphrase("passphrase");
        assert!(store.is_empty());
        assert!(!store.holds(AccountId::new(1)));

        let error = store
            .load(KeyHandle::new(AccountId::new(1), KeyRole::Identity))
            .await
            .expect_err("nothing is stored");
        assert!(matches!(error, KeyStoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn deleting_takes_the_file_and_is_not_an_error_twice() {
        let (_dir, store) = store();
        let id = AccountId::new(1);
        store.set_passphrase("passphrase");
        store.store(id, &account_keys()).await.expect("keys write");

        store.delete(id).await.expect("deletes");
        assert!(!store.holds(id));
        store.delete(id).await.expect("deleting again is harmless");
    }
}
