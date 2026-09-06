//! Keys in the macOS Keychain, guarded by Touch ID.
//!
//! One item per account holds both of that account's secret keys. Keeping them
//! together means unlocking an account is one Keychain read and therefore one
//! Touch ID prompt, rather than two.

use async_trait::async_trait;
use nostr::key::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use signer_core::account::AccountId;
use signer_core::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore, KeyStoreError};

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
}

#[async_trait]
impl KeyStore for KeychainKeyStore {
    async fn load(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
        let stored = platform::read(&self.service, &Self::item_name(handle.account))?
            .ok_or(KeyStoreError::NotFound(handle))?;
        let hex = stored.role(handle.role);
        if hex.is_empty() {
            return Err(KeyStoreError::NotFound(handle));
        }
        let secret = SecretKey::from_hex(hex)
            .map_err(|e| KeyStoreError::Backend(format!("stored key is unreadable: {e}")))?;
        Ok(Keys::new(secret))
    }

    /// Both keys in one write. The item holds the pair, so writing one at a
    /// time would mean reading the other back first, and reading an item
    /// guarded by USER_PRESENCE asks for Touch ID: creating an account would
    /// prompt for a key the app had just generated itself.
    async fn store(&self, account: AccountId, keys: &AccountKeys) -> Result<(), KeyStoreError> {
        platform::write(&self.service, &Self::item_name(account), &keys.into())
    }

    async fn delete(&self, account: AccountId) -> Result<(), KeyStoreError> {
        platform::delete(&self.service, &Self::item_name(account))
    }

    async fn load_many(&self, handles: &[KeyHandle]) -> Result<Vec<Keys>, KeyStoreError> {
        // Both roles of one account come out of a single item, so a two-key
        // account costs one prompt. Several accounts still cost one prompt
        // each; sharing an `LAContext` across those reads would collapse them
        // into one, and is the obvious next refinement.
        let mut keys = Vec::with_capacity(handles.len());
        for handle in handles {
            keys.push(self.load(*handle).await?);
        }
        Ok(keys)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords::{delete_generic_password, generic_password};
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
    use signer_core::keystore::KeyStoreError;

    use super::StoredKeys;

    // OSStatus values from Security/SecBase.h. security-framework-sys exports
    // some of these but not all, so they are spelled out together rather than
    // half imported and half written down.
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const NOT_AVAILABLE: i32 = -25291; // errSecNotAvailable
    const AUTH_FAILED: i32 = -25293; // errSecAuthFailed
    const USER_CANCELED: i32 = -128; // errSecUserCanceled
    const MISSING_ENTITLEMENT: i32 = -34018; // errSecMissingEntitlement

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

        // `ThisDeviceOnly` keeps the item off iCloud Keychain and out of
        // backups, so a key cannot leave this machine by accident.
        // `USER_PRESENCE` accepts Touch ID or the device passcode, which is
        // what makes this usable on a Mac with no working sensor.
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            AccessControlOptions::USER_PRESENCE.bits(),
        )
        .map_err(|e| KeyStoreError::Backend(format!("cannot build access control: {e}")))?;

        // Replacing means deleting first: SecItemAdd refuses a duplicate, and
        // SecItemUpdate cannot change the access control.
        match delete_generic_password(service, account) {
            Ok(()) => {}
            Err(e) if e.code() == NOT_FOUND => {}
            Err(e) => return Err(translate(e)),
        }

        let mut options = PasswordOptions::new_generic_password(service, account);
        options.set_access_control(access);
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
            // An item guarded by Touch ID sits in the data protection
            // keychain, which macOS only opens to an app signed with a
            // keychain access group. The bundle carries one; a binary run
            // straight from cargo does not.
            MISSING_ENTITLEMENT => KeyStoreError::Backend(
                "this build is not signed with the keychain entitlement, \
                 so macOS will not store keys. Run a bundle from `just build`."
                    .to_string(),
            ),
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
