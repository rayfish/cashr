//! The macOS surface: Keychain-backed keys and notification prompts.
//!
//! Everything unsafe lives here, behind safe wrappers, and nothing here makes
//! a decision about what may be signed. If business logic starts appearing in
//! this crate, it belongs in `signer-core` instead.
//!
//! On other platforms the same types compile as stubs that refuse at runtime,
//! so the workspace still builds and tests where there is no Mac.
//!
//! Unsafe Objective-C calls are confined to the notification delegate, Touch ID
//! prompt, and Vision QR decoder. These modules expose safe wrappers; the other
//! crates in this workspace forbid unsafe outright.

mod items;

pub mod keychain;
pub mod notifications;
pub mod passphrase;
pub mod presence;
pub mod qr;

pub use keychain::KeychainKeyStore;
pub use notifications::NotificationApprover;
pub use passphrase::PassphraseStore;
