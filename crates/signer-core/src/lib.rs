//! Core of the Byrgi signer: accounts, NIP-46 sessions, permission
//! policy and storage.
//!
//! Nothing here depends on Tauri or on macOS. The platform is reached through
//! the [`keystore::KeyStore`], [`approval::Approver`] and
//! [`transport::Transport`] traits, which is what makes this crate testable
//! away from a Mac.

#![forbid(unsafe_code)]

pub mod account;
pub mod approval;
pub mod client;
pub mod error;
pub mod keyfile;
pub mod keystore;
pub mod kinds;
pub mod pairing;
pub mod policy;
pub mod request;
pub mod runner;
pub mod session;
pub mod storage;
pub mod transport;
pub mod vault;

pub use error::{Result, SignerError};

/// Project-wide alias so async and sync mutexes never look alike at a glance.
pub type AsyncMutex<T> = tokio::sync::Mutex<T>;
