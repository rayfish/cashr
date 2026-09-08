//! The key storage boundary.
//!
//! Production backs this with the macOS Keychain. Tests back it with memory.
//! Nothing in this crate below the trait knows which it is talking to.

use async_trait::async_trait;
use nostr::key::{Keys, PublicKey, SecretKey};
use thiserror::Error;

use crate::account::AccountId;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("no key stored for {0}")]
    NotFound(KeyHandle),

    #[error("the user cancelled authentication")]
    Cancelled,

    #[error("Authentication was interrupted. Try again.")]
    AuthInterrupted,

    #[error("authentication failed")]
    AuthFailed,

    #[error("authentication is not available on this device")]
    AuthUnavailable,

    #[error("the passphrase is wrong")]
    BadPassphrase,

    #[error("the signer is locked")]
    NoPassphrase,

    #[error("keystore backend: {0}")]
    Backend(String),
}

/// Which of an account's two keys is meant.
///
/// The identity key is the npub. The transport key is what the bunker listens
/// on, so relay operators do not get a log of the identity's connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    Identity,
    Transport,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Transport => "transport",
        }
    }
}

/// Both of an account's secret keys.
///
/// They are written together. A backend that keeps them in one item, which is
/// what the Keychain one does, can then write an account without reading
/// anything back, and reading back an item guarded by Touch ID would ask the
/// user to prove presence in the middle of creating an account.
pub struct AccountKeys {
    pub identity: SecretKey,
    pub transport: SecretKey,
}

impl AccountKeys {
    pub fn role(&self, role: KeyRole) -> &SecretKey {
        match role {
            KeyRole::Identity => &self.identity,
            KeyRole::Transport => &self.transport,
        }
    }
}

/// Names one stored key. Used as the Keychain item account attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle {
    pub account: AccountId,
    pub role: KeyRole,
}

impl KeyHandle {
    pub fn new(account: AccountId, role: KeyRole) -> Self {
        Self { account, role }
    }
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.account, self.role.as_str())
    }
}

#[async_trait]
pub trait KeyStore: Send + Sync + 'static {
    /// Read a key out of storage. On macOS this is what triggers Touch ID.
    async fn load(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError>;

    /// Write both of an account's keys.
    async fn store(&self, account: AccountId, keys: &AccountKeys) -> Result<(), KeyStoreError>;

    /// Forget everything stored for an account. Missing keys are not an error.
    async fn delete(&self, account: AccountId) -> Result<(), KeyStoreError>;

    /// Public key without unlocking, when the backend can manage it.
    async fn public_key(&self, handle: KeyHandle) -> Result<PublicKey, KeyStoreError> {
        Ok(self.load(handle).await?.public_key())
    }

    /// Load several keys under one authentication.
    ///
    /// The default loops, which on macOS would be one Touch ID prompt per key.
    /// The Keychain backend overrides it with a shared `LAContext` so the user
    /// is asked once, which is what "unlock once per launch" actually means
    /// with more than one account.
    async fn load_many(&self, handles: &[KeyHandle]) -> Result<Vec<Keys>, KeyStoreError> {
        let mut keys = Vec::with_capacity(handles.len());
        for handle in handles {
            keys.push(self.load(*handle).await?);
        }
        Ok(keys)
    }
}
