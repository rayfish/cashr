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
    use std::sync::mpsc::channel;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSInteger, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use signer_core::keystore::KeyStoreError;
    use tokio::task::spawn_blocking;

    /// What the reply block hands back: the code when it refused, or nothing
    /// when it passed.
    type Answer = Option<NSInteger>;

    pub(super) async fn require(reason: &str) -> Result<(), KeyStoreError> {
        let reason = reason.to_string();

        // On a blocking thread, and not because the call is slow. Neither the
        // context nor the block is `Send`, and an `LAContext` that is released
        // cancels the evaluation it started, so it has to stay alive until the
        // answer arrives. Holding both on one thread that waits keeps that
        // simple, and keeps the non-Send half out of the future entirely.
        let answer = spawn_blocking(move || {
            let (tx, rx) = channel::<Answer>();

            let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
                let answer = (!ok.as_bool())
                    .then(|| unsafe { error.as_ref() }.map_or(0, |error| error.code()));
                let _ = tx.send(answer);
            });

            // `DeviceOwnerAuthentication` is Touch ID with the login password
            // behind it, which is what makes this usable on a Mac with no
            // sensor or with a finger that will not read.
            let context = unsafe { LAContext::new() };
            unsafe {
                context.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthentication,
                    &NSString::from_str(&reason),
                    &reply,
                );
            }

            rx.recv()
        })
        .await;

        match answer {
            Ok(Ok(None)) => Ok(()),
            Ok(Ok(Some(code))) => Err(translate(code)),
            // The block went away without answering, or the thread did.
            // Neither should happen, and refusing is the safe reading of it.
            Ok(Err(_)) | Err(_) => Err(KeyStoreError::AuthFailed),
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
