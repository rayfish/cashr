//! Accounts: one npub the signer holds keys for.

use nostr::key::PublicKey;
use nostr::types::{RelayUrl, Timestamp};

/// Row id of an account. Newtype so it cannot be confused with a [`ClientId`].
///
/// [`ClientId`]: crate::client::ClientId
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(i64);

impl AccountId {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn get(&self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An account's public half. The secret halves live in the [`KeyStore`].
///
/// [`KeyStore`]: crate::keystore::KeyStore
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    /// The npub. What `get_public_key` returns.
    pub identity_public_key: PublicKey,
    /// What the bunker listens on, kept distinct from the identity so relay
    /// operators do not see which apps connect to which npub.
    pub signer_public_key: PublicKey,
    pub label: String,
    pub created_at: Timestamp,
    pub is_default: bool,
    pub relays: Vec<RelayUrl>,
}
