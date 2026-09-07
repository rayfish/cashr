//! Asking the user, and what they answer.

use async_trait::async_trait;
use nostr::event::Kind;
use nostr::key::PublicKey;
use nostr::nips::nip46::{NostrConnectMethod, NostrConnectRequest};
use nostr::types::Timestamp;
use serde::Serialize;

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
    /// Self-reported; the shell also makes the client public key available.
    pub client_name: Option<String>,
    pub scope: Scope,
    /// A short line describing what is being signed or decrypted. Never
    /// contains key material.
    pub detail: String,
    /// Request content for the app only, never notifications or activity storage.
    pub preview: RequestPreview,
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
            Some(kind) => match kind.as_u16() {
                0 => "update your profile".into(),
                1 => "publish a note".into(),
                3 => "update your follow list".into(),
                4 => "send a legacy private message".into(),
                5 => "request deletion of events".into(),
                6 | 16 => "repost an event".into(),
                7 => "react to an event".into(),
                13 | 1059 => "sign an encrypted message envelope".into(),
                14 => "sign a private message".into(),
                1063 => "publish file information".into(),
                1111 => "publish a comment".into(),
                1984 => "submit a report".into(),
                9734 => "sign a zap request".into(),
                10000 => "update your mute list".into(),
                10002 => "update your relay list".into(),
                22242 => "authenticate with a relay".into(),
                27235 => "authenticate a web request".into(),
                30023 => "publish an article".into(),
                30078 => "save application data".into(),
                _ => match kinds::name(kind) {
                    Some(name) => format!("sign an event: {name}"),
                    None => format!("sign an event of kind {}", kind.as_u16()),
                },
            },
            None => "sign an event".to_string(),
        },
        NostrConnectMethod::Connect => "connect to your account".into(),
        NostrConnectMethod::GetPublicKey => "read your public identity".into(),
        NostrConnectMethod::Nip04Encrypt => "encrypt a legacy private message".into(),
        NostrConnectMethod::Nip04Decrypt => "decrypt a legacy private message".into(),
        NostrConnectMethod::Nip44Encrypt => "encrypt a private message".into(),
        NostrConnectMethod::Nip44Decrypt => "decrypt a private message".into(),
        NostrConnectMethod::Ping => "check whether Byrgi is available".into(),
    }
}

#[derive(Clone, Default, Serialize)]
pub struct RequestPreview {
    pub explanation: String,
    pub fields: Vec<PreviewField>,
    pub content: Option<String>,
}

// Prevent accidental logging of draft posts or request-provided content.
impl std::fmt::Debug for RequestPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestPreview(<request content>)")
    }
}

#[derive(Clone, Serialize)]
pub struct PreviewField {
    pub label: String,
    pub value: String,
}

impl RequestPreview {
    fn field(&mut self, label: &str, value: &str) {
        self.fields.push(PreviewField {
            label: label.into(),
            value: excerpt(value, 300),
        });
    }

    pub fn from_request(request: &NostrConnectRequest) -> Self {
        let mut preview = Self::default();
        match request {
            NostrConnectRequest::GetPublicKey => {
                preview.explanation = "Share your public key so the app can identify your account. Your private key stays in Byrgi.".into();
            }
            NostrConnectRequest::Nip04Encrypt { public_key, .. }
            | NostrConnectRequest::Nip44Encrypt { public_key, .. } => {
                preview.explanation =
                    "Encrypt content for the public key below and return it to the app.".into();
                preview.field("Recipient", &public_key.to_hex());
            }
            NostrConnectRequest::Nip04Decrypt { public_key, .. }
            | NostrConnectRequest::Nip44Decrypt { public_key, .. } => {
                preview.explanation = "Decrypt content from the public key below and share the readable result with the app.".into();
                preview.field("Sender", &public_key.to_hex());
            }
            NostrConnectRequest::SignEvent(event) => {
                preview.explanation = "Byrgi signs this event with your identity. The app decides whether to publish it.".into();
                let tag = |name: &str| {
                    let mut matches = event.tags.iter().filter_map(|tag| {
                        let values = tag.as_slice();
                        (values.first().is_some_and(|key| key == name))
                            .then(|| values.get(1))
                            .flatten()
                    });
                    let first = matches.next();
                    if matches.next().is_some() {
                        None
                    } else {
                        first.map(String::as_str)
                    }
                };
                match event.kind.as_u16() {
                    22242 | 27235 => {
                        let relay = event.kind.as_u16() == 22242;
                        preview.explanation =
                            "Prove control of your identity for this authentication request."
                                .into();
                        let destination = tag(if relay { "relay" } else { "u" });
                        let parsed = destination
                            .and_then(|value| url::Url::parse(value).ok())
                            .filter(|url| matches!(url.scheme(), "http" | "https" | "ws" | "wss"));
                        if let Some(mut url) = parsed {
                            let _ = url.set_username("");
                            let _ = url.set_password(None);
                            let query = url.query().is_some();
                            url.set_query(None);
                            url.set_fragment(None);
                            preview.field(
                                if query {
                                    "Destination (query omitted)"
                                } else {
                                    "Destination"
                                },
                                url.as_str(),
                            );
                        } else {
                            preview
                                .field("Destination", "Missing, invalid, or conflicting URL tags");
                        }
                        if !relay {
                            preview.field(
                                "HTTP method",
                                tag("method").unwrap_or("Missing or conflicting method tags"),
                            );
                        }
                    }
                    9734 => {
                        preview.explanation = "Authorize a zap request. This signature does not send money or authorize a wallet payment.".into();
                        if let Some(msats) =
                            tag("amount").and_then(|value| value.parse::<u64>().ok())
                        {
                            let sats = if msats % 1000 == 0 {
                                format!("{} sats", msats / 1000)
                            } else {
                                format!("{}.{:03} sats", msats / 1000, msats % 1000)
                            };
                            preview.field("Requested amount", &sats);
                        } else {
                            preview.field("Requested amount", "Not specified or invalid");
                        }
                        preview.field(
                            "Recipient",
                            tag("p").unwrap_or("Missing or conflicting recipient tags"),
                        );
                    }
                    0 => {
                        if let Ok(profile) =
                            serde_json::from_str::<serde_json::Value>(&event.content)
                        {
                            for (key, label) in [
                                ("name", "Name"),
                                ("display_name", "Display name"),
                                ("about", "About"),
                            ] {
                                if let Some(value) =
                                    profile.get(key).and_then(|value| value.as_str())
                                {
                                    preview.field(label, value);
                                }
                            }
                        }
                    }
                    4 | 13 | 14 | 1059 => {
                        preview.explanation =
                            "Sign private-message data. Its content is hidden in this prompt."
                                .into();
                        if let Some(recipient) = tag("p") {
                            preview.field("Recipient", recipient);
                        }
                    }
                    _ => {}
                }
                if matches!(event.kind.as_u16(), 1 | 5 | 7 | 1111 | 30023)
                    && !event.content.is_empty()
                {
                    preview.content = Some(excerpt(&event.content, 600));
                }
            }
            NostrConnectRequest::Connect { .. } => {
                preview.explanation = "Pair this app with your account. Signing and decryption have separate permissions.".into();
            }
            NostrConnectRequest::Ping => {}
        }
        preview
    }
}

fn excerpt(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let mut text: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        text.push_str("… (preview truncated)");
    }
    text
}

#[cfg(test)]
mod tests {
    use nostr::event::UnsignedEvent;
    use nostr::key::Keys;
    use serde_json::json;

    use super::*;

    fn event(kind: u16, content: &str, tags: serde_json::Value) -> NostrConnectRequest {
        let event: UnsignedEvent = serde_json::from_value(json!({
            "pubkey": Keys::generate().public_key().to_hex(),
            "created_at": 1, "kind": kind, "content": content, "tags": tags,
        }))
        .unwrap();
        NostrConnectRequest::SignEvent(event)
    }

    #[test]
    fn descriptions_explain_actions_without_confusing_identity_with_payment() {
        assert_eq!(
            describe(Scope::method(NostrConnectMethod::Connect), None),
            "connect to your account"
        );
        assert_eq!(
            describe(Scope::method(NostrConnectMethod::GetPublicKey), None),
            "read your public identity"
        );
        assert_eq!(
            describe(
                Scope::sign_event(Kind::from_u16(1)),
                Some(Kind::from_u16(1))
            ),
            "publish a note"
        );
        assert_eq!(
            describe(
                Scope::sign_event(Kind::from_u16(9734)),
                Some(Kind::from_u16(9734))
            ),
            "sign a zap request"
        );
        assert_eq!(
            describe(
                Scope::sign_event(Kind::from_u16(31337)),
                Some(Kind::from_u16(31337))
            ),
            "sign an event of kind 31337"
        );
        assert_eq!(
            describe(Scope::method(NostrConnectMethod::Nip44Decrypt), None),
            "decrypt a private message"
        );
    }

    #[test]
    fn authentication_shows_the_actual_destination_without_credentials_or_query() {
        let request = event(
            27235,
            "",
            json!([
                [
                    "u",
                    "https://user:password@example.com/api/login?token=secret#fragment"
                ],
                ["method", "POST"],
            ]),
        );
        let preview = RequestPreview::from_request(&request);
        assert_eq!(preview.fields[0].value, "https://example.com/api/login");
        assert!(preview.fields[0].label.contains("query omitted"));
        assert_eq!(preview.fields[1].value, "POST");
        let conflicting = event(
            27235,
            "",
            json!([
                ["u", "https://good.example"],
                ["u", "https://other.example"]
            ]),
        );
        assert!(RequestPreview::from_request(&conflicting).fields[0]
            .value
            .contains("conflicting"));
    }

    #[test]
    fn zap_amount_keeps_millisat_precision_and_does_not_claim_payment() {
        let request = event(9734, "", json!([["amount", "21001"], ["p", "recipient"]]));
        let preview = RequestPreview::from_request(&request);
        assert_eq!(preview.fields[0].value, "21.001 sats");
        assert!(preview.explanation.contains("does not send money"));
        let invalid = event(9734, "", json!([["amount", "not a number"]]));
        assert_eq!(
            RequestPreview::from_request(&invalid).fields[0].value,
            "Not specified or invalid"
        );
    }

    #[test]
    fn public_drafts_are_bounded_and_private_contents_stay_hidden() {
        let note = event(1, &"🦀".repeat(601), json!([]));
        let preview = RequestPreview::from_request(&note);
        assert!(preview
            .content
            .as_ref()
            .unwrap()
            .ends_with("… (preview truncated)"));
        assert!(!format!("{preview:?}").contains('🦀'));
        for kind in [4, 13, 14, 1059, 30078] {
            let preview = RequestPreview::from_request(&event(kind, "private draft", json!([])));
            assert!(preview.content.is_none());
            assert!(!serde_json::to_string(&preview)
                .unwrap()
                .contains("private draft"));
        }
    }
}
