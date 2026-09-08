//! Asking the user to prove they are there, through LocalAuthentication.
//!
//! Touch ID could be left to the system itself, by keeping the secret under a
//! Secure Enclave key with a `SecAccessControl` requiring presence. That is
//! what a password manager does, and it is the only version where the
//! biometric is in the data path rather than beside it.
//!
//! It is not available here, and the reason was measured rather than assumed.
//! Generating the key works: the Enclave hands back a P-256 key. Keeping it
//! does not. An Enclave key has to live in the data protection keychain, and
//! `SecKeyCreateRandomKey` with `kSecAttrIsPermanent` returns OSStatus -34018,
//! `errSecMissingEntitlement`, because that keychain needs a keychain access
//! group, which needs an application identifier, which comes from a
//! provisioning profile and therefore from a paid Developer ID. Asking here
//! keeps the same prompt without one.
//!
//! What is lost is who enforces it. The Keychain would refuse the read itself;
//! here the app refuses to read. The item is still bound to this app's code
//! signature, so another program reading it faces the login password prompt,
//! but code running as you inside this bundle would not have to ask.

use signer_core::keystore::KeyStoreError;

/// Prefer Touch ID, with the Mac login password handled by macOS when needed.
///
/// `reason` completes the sentence macOS shows: "Cashr is trying to ...".
pub async fn require(reason: &str) -> Result<(), KeyStoreError> {
    platform::require(reason).await
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc::channel;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSDebugDescriptionErrorKey, NSError, NSInteger, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use signer_core::keystore::KeyStoreError;
    use tokio::task::spawn_blocking;

    /// What the reply block hands back: the code when it refused, or nothing
    /// when it passed.
    type Answer = Option<(NSInteger, bool)>;

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
                let answer = (!ok.as_bool()).then(|| {
                    unsafe { error.as_ref() }.map_or((0, false), |error| {
                        let debug = error
                            .userInfo()
                            .objectForKey(unsafe { NSDebugDescriptionErrorKey });
                        let debug = debug
                            .as_ref()
                            .and_then(|value| value.downcast_ref::<NSString>())
                            .map(|value| value.to_string())
                            .unwrap_or_default();
                        let reason = format!(
                            "{} {} {}",
                            debug,
                            error.localizedDescription(),
                            error
                                .localizedFailureReason()
                                .map(|value| value.to_string())
                                .unwrap_or_default()
                        )
                        .to_lowercase();
                        let closed_lid = reason.contains("closed lid")
                            || reason.contains("lid is closed")
                            || reason.contains("closed clamshell");
                        (error.code(), closed_lid)
                    })
                });
                let _ = tx.send(answer);
            });

            let context = unsafe { LAContext::new() };
            unsafe {
                // macOS chooses Touch ID when available and offers the login
                // password itself when unavailable (including a closed lid).
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
            Ok(Ok(Some((code, closed_lid)))) => Err(translate(code, closed_lid)),
            // The block went away without answering, or the thread did.
            // Neither should happen, and refusing is the safe reading of it.
            Ok(Err(_)) | Err(_) => Err(KeyStoreError::AuthFailed),
        }
    }

    fn translate(code: NSInteger, closed_lid: bool) -> KeyStoreError {
        tracing::info!(code, closed_lid, "LocalAuthentication did not complete");
        match LAError(code) {
            LAError::UserCancel => KeyStoreError::Cancelled,
            LAError::AppCancel | LAError::SystemCancel => KeyStoreError::AuthInterrupted,
            // No sensor, nothing enrolled, or no password set. Distinct from
            // a refusal, and worth a different sentence. The TouchID names for
            // these are the same numbers under an older spelling.
            LAError::BiometryNotAvailable
            | LAError::BiometryNotEnrolled
            | LAError::PasscodeNotSet => KeyStoreError::AuthUnavailable,
            _ => KeyStoreError::AuthFailed,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn system_interruption_and_user_cancellation_remain_distinct() {
            assert!(matches!(
                translate(LAError::SystemCancel.0, true),
                KeyStoreError::AuthInterrupted
            ));
            assert!(matches!(
                translate(LAError::SystemCancel.0, false),
                KeyStoreError::AuthInterrupted
            ));
            assert!(matches!(
                translate(LAError::UserCancel.0, true),
                KeyStoreError::Cancelled
            ));
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
