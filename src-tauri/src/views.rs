//! What the window sees.
//!
//! Deliberately separate from the core types: the UI gets strings and numbers
//! it can render, and no shape here can carry key material.

use nostr::nips::nip19::ToBech32;
use nostr::nips::nip46::NostrConnectMethod;
use serde::Serialize;
use signer_core::account::Account;
use signer_core::approval::{describe, RequestPreview};
use signer_core::client::Client;
use signer_core::kinds;
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
    pub description: String,
    pub method: String,
    /// `null` means the rule covers every kind for that method.
    pub kind: Option<u16>,
    /// A name for the kind where there is one, so the window does not have to
    /// carry its own copy of the list.
    pub kind_name: Option<&'static str>,
    pub allow: bool,
}

impl From<&Rule> for RuleView {
    fn from(rule: &Rule) -> Self {
        Self {
            description: describe(rule.scope, rule.scope.kind),
            method: rule.scope.method.to_string(),
            kind: rule.scope.kind.map(|k| k.as_u16()),
            kind_name: rule.scope.kind.and_then(kinds::name),
            allow: rule.decision == Decision::Allow,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ActivityView {
    pub description: String,
    pub id: i64,
    pub client: Option<i64>,
    pub method: String,
    pub kind: Option<u16>,
    pub kind_name: Option<&'static str>,
    pub outcome: String,
    pub source: String,
    pub detail: Option<String>,
    pub at: u64,
}

impl From<&ActivityEntry> for ActivityView {
    fn from(entry: &ActivityEntry) -> Self {
        Self {
            description: describe(
                Scope {
                    method: entry.method,
                    kind: entry.kind,
                },
                entry.kind,
            ),
            id: entry.id,
            client: entry.client.map(|c| c.get()),
            method: entry.method.to_string(),
            kind: entry.kind.map(|k| k.as_u16()),
            kind_name: entry.kind.and_then(kinds::name),
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
    pub preview: RequestPreview,
    pub method: String,
    pub kind: Option<u16>,
    pub kind_name: Option<&'static str>,
    pub requested_at: u64,
}

/// The result of accepting a `nostrconnect://` URI.
#[derive(Debug, Serialize)]
pub struct PairingView {
    pub client_public_key: String,
    pub client_name: Option<String>,
    /// Relays the client named that the account was not already using. The
    /// window reports them, because the account is now listening there.
    pub added_relays: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusView {
    pub unlocked: bool,
    pub unlocked_accounts: Vec<i64>,
    pub accounts: Vec<AccountView>,
    pub pending: usize,
    /// An account still has its keys only in the Keychain, so the passphrase
    /// box is setting one rather than asking for one that exists.
    pub needs_migration: bool,
    /// Keys are in files now, but the old Keychain copies are still there.
    pub has_keychain_copies: bool,
    /// The passphrase is stored behind Touch ID, so unlocking can be a tap.
    pub has_touch_id: bool,
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
