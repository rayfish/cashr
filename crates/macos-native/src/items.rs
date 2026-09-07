//! Generic password items in the login keychain, as bytes.
//!
//! The Security framework glue lives here once. What goes inside an item, and
//! whether reading it should cost the user a Touch ID prompt, is decided by
//! the modules above this one.

pub(crate) use platform::{delete, exists, read, write};

#[cfg(target_os = "macos")]
mod platform {
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords::{delete_generic_password, generic_password};
    use security_framework::passwords_options::PasswordOptions;
    use signer_core::keystore::KeyStoreError;

    // OSStatus values from Security/SecBase.h. security-framework-sys exports
    // some of these but not all, so they are spelled out together rather than
    // half imported and half written down.
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const NOT_AVAILABLE: i32 = -25291; // errSecNotAvailable
    const AUTH_FAILED: i32 = -25293; // errSecAuthFailed
    const USER_CANCELED: i32 = -128; // errSecUserCanceled

    /// `Ok(None)` when there is nothing stored. A missing item is an ordinary
    /// answer here, not a failure, and saying so in the type is what keeps a
    /// caller from treating it as one.
    pub(crate) fn read(service: &str, account: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let options = PasswordOptions::new_generic_password(service, account);
        match generic_password(options) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(translate(e)),
        }
    }

    pub(crate) fn write(service: &str, account: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
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
        set_generic_password_options(bytes, options).map_err(translate)
    }

    pub(crate) fn delete(service: &str, account: &str) -> Result<(), KeyStoreError> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(translate(e)),
        }
    }

    /// Whether the item is there, without reading it.
    ///
    /// Attributes only, deliberately. It is asking for the data that makes the
    /// Keychain check the item's access control and put a password dialog in
    /// front of the user, and "is it there" is not worth a dialog.
    pub(crate) fn exists(service: &str, account: &str) -> Result<bool, KeyStoreError> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_attributes(true)
            .limit(Limit::Max(1));

        match options.search() {
            Ok(found) => Ok(!found.is_empty()),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
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

    fn unsupported() -> KeyStoreError {
        KeyStoreError::Backend("the Keychain is only available on macOS".to_string())
    }

    pub(crate) fn read(_service: &str, _account: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        Err(unsupported())
    }

    pub(crate) fn write(
        _service: &str,
        _account: &str,
        _bytes: &[u8],
    ) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }

    pub(crate) fn delete(_service: &str, _account: &str) -> Result<(), KeyStoreError> {
        Err(unsupported())
    }

    /// Nothing is ever there, which is the truthful answer off a Mac and lets
    /// the app treat Touch ID as simply not set up.
    pub(crate) fn exists(_service: &str, _account: &str) -> Result<bool, KeyStoreError> {
        Ok(false)
    }
}
