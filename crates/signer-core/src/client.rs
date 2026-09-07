//! Clients: apps paired with an account over NIP-46.

use nostr::key::PublicKey;
use nostr::types::Timestamp;

use crate::account::AccountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(i64);

impl ClientId {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn get(&self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: ClientId,
    pub account: AccountId,
    pub public_key: PublicKey,
    /// Name the client sent at connect time, if any. Not trustworthy: it is
    /// self-reported, so the UI shows it alongside the pubkey, never instead.
    pub name: Option<String>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub revoked_at: Option<Timestamp>,
    /// When the user took this client off the list. Removing revokes too, so
    /// a removed client is always a revoked one.
    pub removed_at: Option<Timestamp>,
}

impl Client {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_removed(&self) -> bool {
        self.removed_at.is_some()
    }
}

/// Which side minted the pairing URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingDirection {
    /// `bunker://`, minted here and pasted into the client.
    Bunker,
    /// `nostrconnect://`, minted by the client and pasted in here.
    NostrConnect,
}

impl PairingDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bunker => "bunker",
            Self::NostrConnect => "nostrconnect",
        }
    }
}
