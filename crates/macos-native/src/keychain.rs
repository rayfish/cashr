//! Keys in the macOS Keychain, behind a Touch ID prompt.
//!
//! One item per account holds both of that account's secret keys, so unlocking
//! an account is one Keychain read rather than two.
//!
//! The prompt comes from `presence`, not from the Keychain: an item the
//! Keychain itself guards has to live in the data protection keychain, which
//! needs a restricted entitlement and therefore a paid Developer ID. The item
//! is still bound to this app's code signature, which is what keeps other
//! programs out of it. See `presence` for what that trade costs.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use async_trait::async_trait;
use nostr::key::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use signer_core::account::AccountId;
use signer_core::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore, KeyStoreError};

use crate::presence;

/// Both of an account's secret keys, as stored in one Keychain item.
///
/// Hex rather than bech32: this is never shown to anyone, and hex avoids a
/// human-readable nsec sitting in a blob that tooling might print.
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

impl From<&AccountKeys> for StoredKeys {
    fn from(keys: &AccountKeys) -> Self {
        Self {
            identity: keys.identity.to_secret_hex(),
            transport: keys.transport.to_secret_hex(),
        }
    }
}

pub struct KeychainKeyStore {
    service: String,
}

impl KeychainKeyStore {
    /// `service` is the bundle identifier. Keychain items are scoped to it, so
    /// changing it orphans every existing key.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn item_name(account: AccountId) -> String {
        format!("account.{account}")
    }

    /// The read itself. Presence is asked for once by the caller, so this must
    /// not be public: nothing outside should be able to reach a key without
    /// going past the prompt.
    fn read(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
        let stored = self.read_item(handle)?;
        key_from(&stored, handle)
    }

    /// The account's whole item. Every call is a separate `SecItemCopyMatching`
    /// and therefore a separate Keychain access check, so callers that want
    /// both roles read it once and take both out.
    fn read_item(&self, handle: KeyHandle) -> Result<StoredKeys, KeyStoreError> {
        platform::read(&self.service, &Self::item_name(handle.account))?
            .ok_or(KeyStoreError::NotFound(handle))
    }
}

/// Take one role's key out of the item both roles share.
fn key_from(stored: &StoredKeys, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
    let hex = stored.role(handle.role);
    if hex.is_empty() {
        return Err(KeyStoreError::NotFound(handle));
    }
    let secret = SecretKey::from_hex(hex)
        .map_err(|e| KeyStoreError::Backend(format!("stored key is unreadable: {e}")))?;
    Ok(Keys::new(secret))
}

/// Completes the sentence macOS shows: "Byrgi is trying to ...".
const UNLOCK_REASON: &str = "unlock your nostr keys";

#[async_trait]
impl KeyStore for KeychainKeyStore {
    async fn load(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
        presence::require(UNLOCK_REASON).await?;
        self.read(handle)
    }

    /// Both keys in one write, and no prompt: the item holds the pair, so
    /// writing one at a time would mean reading the other back first, and
    /// creating an account would ask for Touch ID over a key the app had just
    /// generated itself.
    async fn store(&self, account: AccountId, keys: &AccountKeys) -> Result<(), KeyStoreError> {
        platform::write(&self.service, &Self::item_name(account), &keys.into())
    }

    async fn delete(&self, account: AccountId) -> Result<(), KeyStoreError> {
        platform::delete(&self.service, &Self::item_name(account))
    }

    /// One presence prompt, and one Keychain read per account.
    ///
    /// The handles name a role each, but an account's two keys live in the
    /// same item, so reading per handle asks the Keychain twice for the same
    /// thing. Each of those reads is its own access check, and on a login
    /// keychain item that means a second password dialog for the user, so the
    /// item is read once and both keys come out of it.
    async fn load_many(&self, handles: &[KeyHandle]) -> Result<Vec<Keys>, KeyStoreError> {
        presence::require(UNLOCK_REASON).await?;

        let mut items: HashMap<AccountId, StoredKeys> = HashMap::new();
        let mut keys = Vec::with_capacity(handles.len());
        for handle in handles {
            let stored = match items.entry(handle.account) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(self.read_item(*handle)?),
            };
            keys.push(key_from(stored, *handle)?);
        }
        Ok(keys)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords::{delete_generic_password, generic_password};
    use security_framework::passwords_options::PasswordOptions;
    use signer_core::keystore::KeyStoreError;

    use super::StoredKeys;

    // OSStatus values from Security/SecBase.h. security-framework-sys exports
    // some of these but not all, so they are spelled out together rather than
    // half imported and half written down.
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const NOT_AVAILABLE: i32 = -25291; // errSecNotAvailable
    const AUTH_FAILED: i32 = -25293; // errSecAuthFailed
    const USER_CANCELED: i32 = -128; // errSecUserCanceled

    /// `Ok(None)` when the account has nothing stored. A missing item is an
    /// ordinary answer here, not a failure, and saying so in the type is what
    /// keeps a caller from treating it as one.
    pub(super) fn read(service: &str, account: &str) -> Result<Option<StoredKeys>, KeyStoreError> {
        let options = PasswordOptions::new_generic_password(service, account);
        let bytes = match generic_password(options) {
            Ok(bytes) => bytes,
            Err(e) if e.code() == NOT_FOUND => return Ok(None),
            Err(e) => return Err(translate(e)),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| KeyStoreError::Backend(format!("stored item is not readable: {e}")))
    }

    pub(super) fn write(
        service: &str,
        account: &str,
        keys: &StoredKeys,
    ) -> Result<(), KeyStoreError> {
        let bytes = serde_json::to_vec(keys)
            .map_err(|e| KeyStoreError::Backend(format!("cannot serialise keys: {e}")))?;

        // Replacing means deleting first: SecItemAdd refuses a duplicate.
        match delete_generic_password(service, account) {
            Ok(()) => {}
            Err(e) if e.code() == NOT_FOUND => {}
            Err(e) => return Err(translate(e)),
        }

        // No `kSecAttrAccessControl`: an item carrying one goes to the data
        // protection keychain, which refuses an app without the entitlement.
        // The item lands in the login keychain instead, readable only by this
        // signed app, and `presence` is what asks for Touch ID.
        let options = PasswordOptions::new_generic_password(service, account);
        set_generic_password_options(&bytes, options).map_err(translate)
    }

    pub(super) fn delete(service: &str, account: &str) -> Result<(), KeyStoreError> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(translate(e)),
        }
    }

    /// Every caller decides for itself what a missing item means, so
    /// `NOT_FOUND` never reaches here.
    fn translate(error: security_framework::base::Error) -> KeyStoreError {
        match error.code() {
            USER_CANCELED => KeyStoreError::Cancelled,
            // Touch ID refused, or the passcode was wrong. Distinct from a
            // Mac that cannot authenticate at all, which is NOT_AVAILABLE.
            AUTH_FAILED => KeyStoreError::AuthFailed,
            NOT_AVAILABLE => KeyStoreError::AuthUnavailable,
            code => KeyStoreError::Backend(match error.message() {
                Some(message) => format!("keychain error {code}: {message}"),
                None => format!("keychain error {code}"),
            }),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use signer_core::keystore::KeyStoreError;

    use super::StoredKeys;

    fn unsupported() -> KeyStoreError {
        KeyStoreError::Backend("the Keychain is only available on macOS".to_string())
    }

    pub(super) fn read(
        _service: &str,
        _account: &str,
    ) -> Result<Option<StoredKeys>, KeyStoreError> {
        Err(unsupported())
    }

    pub(super) fn write(
        _service: &str,
        _account: &str,
        _keys: &StoredKeys,
    ) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }

    pub(super) fn delete(_service: &str, _account: &str) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }
}
