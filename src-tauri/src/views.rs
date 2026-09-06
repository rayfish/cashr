//! What the window sees.
//!
//! Deliberately separate from the core types: the UI gets strings and numbers
//! it can render, and no shape here can carry key material.

use nostr::nips::nip19::ToBech32;
use nostr::nips::nip46::NostrConnectMethod;
use serde::Serialize;
use signer_core::account::Account;
use signer_core::client::Client;
use signer_core::policy::{Decision, Rule, Scope};
use signer_core::storage::ActivityEntry;
use signer_core::transport::RelayHealth;

#[derive(Debug, Serialize)]
pub struct AccountView {
    pub id: i64,
    pub label: String,
    /// The npub, bech32 encoded for display.
    pub npub: String,
    pub is_default: bool,
    pub relays: Vec<String>,
}

impl From<&Account> for AccountView {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id.get(),
            label: account.label.clone(),
            npub: account
                .identity_public_key
                .to_bech32()
                .unwrap_or_else(|_| account.identity_public_key.to_hex()),
            is_default: account.is_default,
            relays: account.relays.iter().map(|r| r.to_string()).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ClientView {
    pub id: i64,
    pub public_key: String,
    pub name: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub revoked: bool,
}

impl From<&Client> for ClientView {
    fn from(client: &Client) -> Self {
        Self {
            id: client.id.get(),
            public_key: client.public_key.to_hex(),
            name: client.name.clone(),
            first_seen: client.first_seen.as_secs(),
            last_seen: client.last_seen.as_secs(),
            revoked: client.is_revoked(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RuleView {
    pub method: String,
    /// `null` means the rule covers every kind for that method.
    pub kind: Option<u16>,
    pub allow: bool,
}

impl From<&Rule> for RuleView {
    fn from(rule: &Rule) -> Self {
        Self {
            method: rule.scope.method.to_string(),
            kind: rule.scope.kind.map(|k| k.as_u16()),
            allow: rule.decision == Decision::Allow,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ActivityView {
    pub id: i64,
    pub client: Option<i64>,
    pub method: String,
    pub kind: Option<u16>,
    pub outcome: String,
    pub source: String,
    pub detail: Option<String>,
    pub at: u64,
}

impl From<&ActivityEntry> for ActivityView {
    fn from(entry: &ActivityEntry) -> Self {
        Self {
            id: entry.id,
            client: entry.client.map(|c| c.get()),
            method: entry.method.to_string(),
            kind: entry.kind.map(|k| k.as_u16()),
            outcome: entry.outcome.as_str().to_string(),
            source: entry.source.as_str().to_string(),
            detail: entry.detail.clone(),
            at: entry.created_at.as_secs(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RelayView {
    pub url: String,
    pub connected: bool,
    pub last_error: Option<String>,
}

impl From<&RelayHealth> for RelayView {
    fn from(health: &RelayHealth) -> Self {
        Self {
            url: health.relay.to_string(),
            connected: health.connected,
            last_error: health.last_error.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PromptView {
    pub id: u64,
    pub account: i64,
    pub account_label: String,
    pub client: i64,
    pub client_name: Option<String>,
    pub client_public_key: String,
    pub detail: String,
    pub method: String,
    pub kind: Option<u16>,
    pub requested_at: u64,
}

#[derive(Debug, Serialize)]
pub struct StatusView {
    pub unlocked: bool,
    pub accounts: Vec<AccountView>,
    pub pending: usize,
}

/// Parse a method name coming back from the window.
pub fn method_from_str(value: &str) -> Option<NostrConnectMethod> {
    value.parse().ok()
}

pub fn scope_from_parts(method: NostrConnectMethod, kind: Option<u16>) -> Scope {
    Scope {
        method,
        kind: kind.map(nostr::event::Kind::from_u16),
    }
}
