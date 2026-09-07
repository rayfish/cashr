//! The unlock passphrase, kept in the Keychain behind Touch ID.
//!
//! Opt in, and off until the user asks. The passphrase is what decrypts the
//! key files, so a copy here is a copy of the thing that opens everything.
//! Storing it buys one Touch ID prompt in place of typing, and costs the
//! property that nothing on disk opens the keys on its own. That trade is the
//! user's to make, which is why nothing here happens by default and `forget`
//! puts things back.
//!
//! What guards the copy is `presence`, not the Keychain. An item the Keychain
//! itself guards carries a `SecAccessControl` and therefore lives in the data
//! protection keychain, which needs an entitlement that comes with a paid
//! Developer ID. So this asks for Touch ID and honours the answer. The item is
//! still bound to the app's code signature, which is what keeps other programs
//! out of it, but code running as you inside this bundle would not have to
//! ask. See `presence` for the same trade spelled out.

use secrecy::SecretString;
use signer_core::keystore::KeyStoreError;

use crate::items;
use crate::presence;

/// Item name. Not `account.<id>`: the passphrase belongs to the signer, not to
/// any one account, and every account opens with it.
const ITEM: &str = "unlock.passphrase";

/// Completes the sentence macOS shows: "Byrgi is trying to ...".
const REASON: &str = "unlock your nostr keys";

pub struct PassphraseStore {
    service: String,
}

impl PassphraseStore {
    /// `service` is the bundle identifier, as for the key items.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Whether Touch ID unlocking is set up.
    ///
    /// Silent: this is asked on every status refresh, so it looks at the
    /// item's attributes and never at its contents. Reading the contents is
    /// what raises a dialog.
    pub fn is_set(&self) -> bool {
        items::exists(&self.service, ITEM).unwrap_or(false)
    }

    /// Ask for Touch ID, then hand back the passphrase.
    ///
    /// The order matters. Presence first means a cancelled prompt never
    /// reaches the Keychain at all.
    pub async fn load(&self) -> Result<SecretString, KeyStoreError> {
        presence::require(REASON).await?;

        let bytes = items::read(&self.service, ITEM)?
            .ok_or_else(|| KeyStoreError::Backend("no passphrase is stored".to_string()))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| KeyStoreError::Backend("stored passphrase is not text".to_string()))?;
        Ok(SecretString::from(text))
    }

    /// Write the passphrase. No prompt: the caller has just proved it knows
    /// the passphrase by unlocking with it, and asking again would be asking
    /// the user to authenticate to store something they typed a moment ago.
    pub fn store(&self, passphrase: &str) -> Result<(), KeyStoreError> {
        items::write(&self.service, ITEM, passphrase.as_bytes())
    }

    /// Drop the stored copy. Missing is not an error: the point is that
    /// afterwards there is nothing there.
    pub fn forget(&self) -> Result<(), KeyStoreError> {
        items::delete(&self.service, ITEM)
    }
}
