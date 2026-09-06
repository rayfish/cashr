//! The macOS surface: Keychain-backed keys and notification prompts.
//!
//! Everything unsafe lives here, behind safe wrappers, and nothing here makes
//! a decision about what may be signed. If business logic starts appearing in
//! this crate, it belongs in `signer-core` instead.
//!
//! On other platforms the same types compile as stubs that refuse at runtime,
//! so the workspace still builds and tests where there is no Mac.

pub mod keychain;
pub mod notifications;

pub use keychain::KeychainKeyStore;
pub use notifications::NotificationApprover;
