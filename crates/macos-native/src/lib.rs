//! The macOS surface: Keychain-backed keys and notification prompts.
//!
//! Everything unsafe lives here, behind safe wrappers, and nothing here makes
//! a decision about what may be signed. If business logic starts appearing in
//! this crate, it belongs in `signer-core` instead.
//!
//! On other platforms the same types compile as stubs that refuse at runtime,
//! so the workspace still builds and tests where there is no Mac.
//!
//! Unsafe is confined to two places, both in `notifications`: the
//! `define_class!` block that declares the notification delegate class, and
//! the one `init` message that makes its first instance. Objective-C offers no
//! safe way to do either. Everything else, the Keychain included, goes through
//! safe bindings, and the other crates in this workspace forbid unsafe
//! outright.

pub mod keychain;
pub mod notifications;

pub use keychain::KeychainKeyStore;
pub use notifications::NotificationApprover;
