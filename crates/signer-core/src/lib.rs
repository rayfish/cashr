//! Core of the nostr-tray signer: accounts, NIP-46 sessions, permission
//! policy and storage.
//!
//! Nothing here depends on Tauri or on macOS. The platform is reached through
//! the [`keystore::KeyStore`], [`approval::Approver`] and
//! [`transport::Transport`] traits, which is what makes this crate testable
//! away from a Mac.

pub mod account;
pub mod approval;
pub mod client;
pub mod error;
pub mod keystore;
pub mod policy;
pub mod storage;
pub mod transport;

pub use error::{Result, SignerError};
