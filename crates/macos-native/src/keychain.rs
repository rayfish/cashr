//! Keys in the macOS Keychain, guarded by Touch ID.
//!
//! One item per account holds both of that account's secret keys. Keeping them
//! together means unlocking an account is one Keychain read and therefore one
//! Touch ID prompt, rather than two.

use async_trait::async_trait;
use nostr::key::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use signer_core::account::AccountId;
use signer_core::keystore::{KeyHandle, KeyRole, KeyStore, KeyStoreError};

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

    fn with(mut self, role: KeyRole, secret: &SecretKey) -> Self {
        let hex = secret.to_secret_hex();
        match role {
            KeyRole::Identity => self.identity = hex,
            KeyRole::Transport => self.transport = hex,
        }
        self
    }

    fn empty() -> Self {
        Self {
            identity: String::new(),
            transport: String::new(),
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
        let stored = platform::read(&self.service, &Self::item_name(handle.account))?;
        let hex = stored.role(handle.role);
        if hex.is_empty() {
            return Err(KeyStoreError::NotFound(handle));
        }
        let secret = SecretKey::from_hex(hex)
            .map_err(|e| KeyStoreError::Backend(format!("stored key is unreadable: {e}")))?;
        Ok(Keys::new(secret))
    }

    async fn store(&self, handle: KeyHandle, secret: SecretKey) -> Result<(), KeyStoreError> {
        let name = Self::item_name(handle.account);
        let existing = match platform::read(&self.service, &name) {
            Ok(stored) => stored,
            Err(KeyStoreError::NotFound(_)) => StoredKeys::empty(),
            Err(other) => return Err(other),
        };
        platform::write(&self.service, &name, &existing.with(handle.role, &secret))
    }

    async fn delete(&self, handle: KeyHandle) -> Result<(), KeyStoreError> {
        platform::delete(&self.service, &Self::item_name(handle.account))
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

    /// errSecItemNotFound. Anything else is a real failure worth surfacing.
    const NOT_FOUND: i32 = -25300;
    /// errSecUserCanceled, and the LocalAuthentication equivalent.
    const USER_CANCELED: i32 = -128;
    const AUTH_FAILED: i32 = -25293;

    pub(super) fn read(service: &str, account: &str) -> Result<StoredKeys, KeyStoreError> {
        let options = PasswordOptions::new_generic_password(service, account);
        let bytes = generic_password(options).map_err(|e| translate(e, account))?;
        serde_json::from_slice(&bytes)
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
            Err(e) => return Err(translate(e, account)),
        }

        let mut options = PasswordOptions::new_generic_password(service, account);
        options.set_access_control(access);
        set_generic_password_options(&bytes, options).map_err(|e| translate(e, account))
    }

    pub(super) fn delete(service: &str, account: &str) -> Result<(), KeyStoreError> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(translate(e, account)),
        }
    }

    fn translate(error: security_framework::base::Error, account: &str) -> KeyStoreError {
        match error.code() {
            NOT_FOUND => KeyStoreError::Backend(format!("no keychain item for {account}")),
            USER_CANCELED => KeyStoreError::Cancelled,
            AUTH_FAILED => KeyStoreError::AuthUnavailable,
            code => KeyStoreError::Backend(format!("keychain error {code}")),
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

    pub(super) fn read(_service: &str, _account: &str) -> Result<StoredKeys, KeyStoreError> {
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
