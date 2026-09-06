//! Asking the user, and what they answer.

use async_trait::async_trait;
use nostr::event::Kind;
use nostr::key::PublicKey;
use nostr::nips::nip46::NostrConnectMethod;
use nostr::types::Timestamp;

use crate::account::AccountId;
use crate::client::ClientId;
use crate::error::Result;
use crate::kinds;
use crate::policy::{Decision, Scope};

/// Everything the prompt needs to show. Assembled by the session, rendered by
/// the shell, so the shell never has to query storage to draw a prompt.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub account: AccountId,
    pub account_label: String,
    pub client: ClientId,
    pub client_public_key: PublicKey,
    /// Self-reported, shown next to the pubkey rather than in place of it.
    pub client_name: Option<String>,
    pub scope: Scope,
    /// A short line describing what is being signed or decrypted. Never
    /// contains key material.
    pub detail: String,
    pub requested_at: Timestamp,
}

/// What the user chose, and whether it becomes a stored rule.
///
/// `remember` covers "allow always" and "deny always" without a second enum:
/// the pair is exactly what gets written to the policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub decision: Decision,
    pub remember: bool,
}

impl ApprovalDecision {
    pub fn allow_once() -> Self {
        Self {
            decision: Decision::Allow,
            remember: false,
        }
    }

    pub fn allow_always() -> Self {
        Self {
            decision: Decision::Allow,
            remember: true,
        }
    }

    pub fn deny() -> Self {
        Self {
            decision: Decision::Deny,
            remember: false,
        }
    }

    pub fn deny_always() -> Self {
        Self {
            decision: Decision::Deny,
            remember: true,
        }
    }
}

#[async_trait]
pub trait Approver: Send + Sync + 'static {
    /// Ask the user. Returns [`SignerError::Expired`] if the request times out
    /// rather than blocking a client forever.
    ///
    /// [`SignerError::Expired`]: crate::error::SignerError::Expired
    async fn request(&self, request: ApprovalRequest) -> Result<ApprovalDecision>;
}

/// Things the UI wants to know about but does not have to answer.
#[derive(Debug, Clone)]
pub enum SignerEvent {
    Unlocked,
    Locked,
    RelayStatus {
        account: AccountId,
        relay: String,
        connected: bool,
    },
    ClientConnected {
        account: AccountId,
        client: ClientId,
    },
    RequestHandled {
        account: AccountId,
        client: ClientId,
        scope: Scope,
        decision: Decision,
    },
    /// A request arrived while locked and is waiting for an unlock.
    UnlockNeeded {
        account: AccountId,
    },
}

pub trait Notifier: Send + Sync + 'static {
    fn notify(&self, event: SignerEvent);
}

/// Drops every event. Used in tests and on platforms with no UI attached.
pub struct NullNotifier;

impl Notifier for NullNotifier {
    fn notify(&self, _event: SignerEvent) {}
}

/// A one-line description of a request for the prompt and the activity log.
pub fn describe(scope: Scope, event_kind: Option<Kind>) -> String {
    match scope.method {
        NostrConnectMethod::SignEvent => match event_kind {
            // The number stays next to the name. The name is our gloss, and a
            // client asking for something unusual should still be legible.
            Some(kind) => match kinds::name(kind) {
                Some(name) => format!("sign a {name} (kind {})", kind.as_u16()),
                None => format!("sign a kind {} event", kind.as_u16()),
            },
            None => "sign an event".to_string(),
        },
        other => other.to_string(),
    }
}
