//! Asking the user to prove they are there, through LocalAuthentication.
//!
//! Touch ID could be left to the Keychain itself, by giving the item a
//! `SecAccessControl` with `USER_PRESENCE`. That puts the item in the data
//! protection keychain, which macOS only opens to an app signed with a
//! keychain access group, and that entitlement is restricted: a build carrying
//! it without a provisioning profile is refused at launch, so it needs a paid
//! Developer ID. Asking here instead keeps the same prompt without one.
//!
//! What is lost is who enforces it. The Keychain would refuse the read itself;
//! here the app refuses to read. The item is still bound to this app's code
//! signature, so another program reading it faces the login password prompt,
//! but code running as you inside this bundle would not have to ask.

use signer_core::keystore::KeyStoreError;

/// Ask for Touch ID, the watch, or the login password, whichever the Mac has.
///
/// `reason` completes the sentence macOS shows: "Byrgi is trying to ...".
pub async fn require(reason: &str) -> Result<(), KeyStoreError> {
    platform::require(reason).await
}

#[cfg(target_os = "macos")]
mod platform {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSInteger, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use signer_core::keystore::KeyStoreError;
    use tokio::sync::oneshot::{channel, Sender};

    use std::sync::Mutex;

    /// What the reply block hands back: the code when it refused, or nothing
    /// when it passed.
    type Answer = Option<NSInteger>;

    pub(super) async fn require(reason: &str) -> Result<(), KeyStoreError> {
        let (tx, rx) = channel::<Answer>();
        // The block is `Fn`, so it could in principle run twice; the sender
        // can only be used once. Taking it out of the Mutex makes a second
        // call a no-op rather than a panic.
        let tx: Mutex<Option<Sender<Answer>>> = Mutex::new(Some(tx));

        let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
            let answer = if ok.as_bool() {
                None
            } else {
                Some(unsafe { error.as_ref() }.map_or(0, |error| error.code()))
            };
            if let Some(tx) = tx.lock().ok().and_then(|mut held| held.take()) {
                let _ = tx.send(answer);
            }
        });

        // `DeviceOwnerAuthentication` is Touch ID with the login password
        // behind it, which is what makes this usable on a Mac with no sensor
        // or with a finger that will not read.
        let context: Retained<LAContext> = unsafe { LAContext::new() };
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(reason),
                &reply,
            );
        }

        match rx.await {
            Ok(None) => Ok(()),
            Ok(Some(code)) => Err(translate(code)),
            // The block was dropped without answering, which should not
            // happen. Refusing is the safe reading of it.
            Err(_) => Err(KeyStoreError::AuthFailed),
        }
    }

    fn translate(code: NSInteger) -> KeyStoreError {
        match LAError(code) {
            LAError::UserCancel | LAError::AppCancel | LAError::SystemCancel => {
                KeyStoreError::Cancelled
            }
            // No sensor, nothing enrolled, or no password set. Distinct from
            // a refusal, and worth a different sentence. The TouchID names for
            // these are the same numbers under an older spelling.
            LAError::BiometryNotAvailable
            | LAError::BiometryNotEnrolled
            | LAError::PasscodeNotSet => KeyStoreError::AuthUnavailable,
            _ => KeyStoreError::AuthFailed,
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use signer_core::keystore::KeyStoreError;

    pub(super) async fn require(_reason: &str) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Backend(
            "Touch ID is only available on macOS".to_string(),
        ))
    }
}
