//! The unlock passphrase, kept in a file behind Touch ID.
//!
//! Opt in, and off until the user asks. It buys one Touch ID press in place of
//! typing, and it costs the thing the key files were for: the passphrase now
//! sits on disk beside them, so anything that can read your files can open
//! your keys. Touch ID here is the app asking and honouring the answer, not
//! the system refusing without it.
//!
//! The Keychain would be the better home, and this used to be there. An item
//! there is bound to the code signature that created it, and not to the
//! signature's designated requirement but to the binary, so every rebuild and
//! every app update makes the app a stranger to its own item and the user gets
//! a login password dialog. Sealing the secret under a Secure Enclave key
//! avoids both problems and is what a password manager does; `presence` has
//! the measured reason that is not open to us. A file asks for nothing and
//! never puts a dialog in the way, and buys correspondingly less.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use signer_core::keystore::KeyStoreError;

use crate::items;
use crate::presence;

/// Completes the sentence macOS shows: "Byrgi is trying to ...".
const REASON: &str = "unlock your nostr keys";

/// Where an earlier version kept the passphrase.
const LEGACY_ITEM: &str = "unlock.passphrase";

pub struct PassphraseStore {
    path: PathBuf,
}

impl PassphraseStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Whether Touch ID unlocking is set up.
    ///
    /// Asked on every status refresh, so it looks at the file rather than
    /// reading it. Reading it is what asks the user for a finger.
    pub fn is_set(&self) -> bool {
        self.path.exists()
    }

    /// Ask for Touch ID, then hand back the passphrase.
    ///
    /// Presence first, so a cancelled prompt never reaches the file.
    pub async fn load(&self) -> Result<SecretString, KeyStoreError> {
        presence::require(REASON).await?;

        let bytes = fs::read(&self.path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                KeyStoreError::Backend("no passphrase is stored".to_string())
            }
            _ => KeyStoreError::Backend(format!("could not read the passphrase: {e}")),
        })?;
        let text = String::from_utf8(bytes)
            .map_err(|_| KeyStoreError::Backend("stored passphrase is not text".to_string()))?;
        Ok(SecretString::from(text))
    }

    /// Write the passphrase, 0600, replaced whole.
    ///
    /// No prompt: the caller has just proved it knows the passphrase by
    /// unlocking with it, and asking again would be asking the user to
    /// authenticate over something they typed a moment ago.
    pub fn store(&self, passphrase: &str) -> Result<(), KeyStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KeyStoreError::Backend(format!("could not make the key dir: {e}")))?;
        }

        // Same shape as the key files: write a neighbour, restrict it, rename
        // over the top. A half-written passphrase would be a Touch ID that
        // silently stops working.
        let temp = self.path.with_extension("new");
        fs::write(&temp, passphrase.as_bytes())
            .map_err(|e| KeyStoreError::Backend(format!("could not write the passphrase: {e}")))?;
        restrict(&temp)?;
        fs::rename(&temp, &self.path).map_err(|e| {
            KeyStoreError::Backend(format!("could not replace the passphrase: {e}"))
        })?;
        Ok(())
    }

    /// Drop the stored copy. Missing is not an error: the point is that
    /// afterwards there is nothing there.
    pub fn forget(&self) -> Result<(), KeyStoreError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyStoreError::Backend(format!(
                "could not remove the passphrase: {e}"
            ))),
        }
    }
}

/// Delete the copy an earlier version kept in the Keychain.
///
/// Best effort and silent. Deleting an item does not go through its access
/// control, so this costs the user nothing, and leaving it would mean the
/// passphrase lived in a second place that "stop using Touch ID" does not
/// reach.
pub fn forget_keychain_copy(service: &str) {
    if let Err(error) = items::delete(service, LEGACY_ITEM) {
        tracing::debug!("could not remove the old Keychain passphrase: {error}");
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| KeyStoreError::Backend(format!("could not restrict the passphrase: {e}")))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), KeyStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn store() -> (tempfile::TempDir, PassphraseStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = PassphraseStore::new(dir.path().join("unlock.passphrase"));
        (dir, store)
    }

    #[test]
    fn nothing_is_set_to_begin_with() {
        let (_dir, store) = store();
        assert!(!store.is_set());
    }

    #[test]
    fn storing_then_forgetting_leaves_nothing() {
        let (_dir, store) = store();
        store.store("open sesame").expect("stores");
        assert!(store.is_set());

        store.forget().expect("forgets");
        assert!(!store.is_set());
    }

    #[test]
    fn forgetting_what_is_not_there_is_fine() {
        let (_dir, store) = store();
        store.forget().expect("forgets nothing");
    }

    #[test]
    fn storing_twice_keeps_the_second() {
        let (_dir, store) = store();
        store.store("first").expect("stores");
        store.store("second").expect("replaces");

        let text = fs::read_to_string(&store.path).expect("reads");
        assert_eq!(text, "second");
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, store) = store();
        store.store("open sesame").expect("stores");

        let mode = fs::metadata(&store.path)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// The presence check is what guards this, and it is not reachable in a
    /// test, so this covers the half underneath it: what `load` would read.
    #[test]
    fn what_lands_on_disk_is_what_comes_back() {
        let (_dir, store) = store();
        store.store("open sesame").expect("stores");

        let text = fs::read_to_string(&store.path).expect("reads");
        assert_eq!(SecretString::from(text).expose_secret(), "open sesame");
    }
}
