//! The relay boundary.
//!
//! Keeping this a trait is what lets the session machine be tested without a
//! relay, and keeps `nostr-sdk` out of the logic that decides what to sign.

use async_trait::async_trait;
use nostr::event::Event;
use nostr::key::PublicKey;
use nostr::types::RelayUrl;
use tokio::sync::mpsc::Receiver;

use crate::account::AccountId;
use crate::error::Result;

/// One account's listening position: which pubkey, on which relays.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub account: AccountId,
    pub signer_public_key: PublicKey,
    pub relays: Vec<RelayUrl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHealth {
    pub relay: RelayUrl,
    pub connected: bool,
    /// Last error the relay reported, if it is not connected.
    pub last_error: Option<String>,
}

#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Begin receiving NIP-46 events addressed to the subscription's pubkey.
    async fn listen(&self, subscription: Subscription) -> Result<Receiver<Event>>;

    /// Publish `event` on behalf of `account`.
    ///
    /// The account is part of the signature because connections are per
    /// account: two accounts sharing one socket to a relay would tie them
    /// together for that operator, which is the thing separate transport keys
    /// exist to avoid.
    async fn publish(&self, account: AccountId, event: Event, relays: Vec<RelayUrl>) -> Result<()>;

    async fn health(&self, account: AccountId) -> Vec<RelayHealth>;

    /// Close an account's connections.
    ///
    /// Called when an account is deleted or its relay list changes. The
    /// default does nothing, which is right for a transport that holds no
    /// connections of its own.
    async fn stop(&self, account: AccountId) {
        let _ = account;
    }
}
