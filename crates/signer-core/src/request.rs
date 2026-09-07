//! Turning a client's request params into a [`NostrConnectRequest`].
//!
//! The parser in `nostr` wants a whole [`UnsignedEvent`]. NIP-46 clients do
//! not send one, so this is where the gap is closed.
//!
//! [`UnsignedEvent`]: nostr::event::UnsignedEvent

use nostr::nips::nip46::{NostrConnectMethod, NostrConnectRequest};
use nostr::types::Timestamp;
use serde_json::{json, Value};

use crate::account::Account;
use crate::error::{Result, SignerError};

/// Build the request a client asked for, filling in what it left out.
pub fn parse(
    account: &Account,
    method: NostrConnectMethod,
    mut params: Vec<String>,
) -> Result<NostrConnectRequest> {
    if method == NostrConnectMethod::SignEvent {
        let Some(template) = params.first() else {
            return Err(SignerError::InvalidRequest("sign_event wants an event"));
        };
        let completed = complete_event(account, template)?;
        params[0] = completed;
    }

    Ok(NostrConnectRequest::from_message(method, params)?)
}

/// Fill in the fields a `sign_event` template is allowed to leave out, and
/// overwrite the ones the client does not get to choose.
///
/// NIP-46 has the client send `{kind, content, tags, created_at}` and nothing
/// else: the signer owns the identity, so the client cannot know the pubkey
/// and cannot compute the id. `UnsignedEvent` requires both, which is why
/// every real posting client was refused with "missing field `pubkey`" and
/// nothing could be published.
///
/// A pubkey or an id that did arrive is replaced rather than trusted. The id
/// is the only thing actually signed, so taking the client's would put the
/// signature over bytes nobody looked at, whatever the prompt said the request
/// was, and a pubkey other than this account's would produce an event no relay
/// accepts.
fn complete_event(account: &Account, template: &str) -> Result<String> {
    let Ok(Value::Object(mut event)) = serde_json::from_str::<Value>(template) else {
        return Err(SignerError::InvalidRequest(
            "sign_event wants an event object",
        ));
    };

    event.insert(
        "pubkey".to_string(),
        json!(account.identity_public_key.to_hex()),
    );
    event.remove("id");
    event.remove("sig");
    event
        .entry("created_at")
        .or_insert_with(|| json!(Timestamp::now().as_secs()));
    event.entry("tags").or_insert_with(|| json!([]));

    Ok(Value::Object(event).to_string())
}

#[cfg(test)]
mod tests {
    use nostr::event::{Kind, UnsignedEvent};
    use nostr::key::Keys;
    use nostr::types::RelayUrl;

    use super::*;
    use crate::account::AccountId;

    fn account() -> Account {
        Account {
            id: AccountId::new(1),
            identity_public_key: Keys::generate().public_key(),
            signer_public_key: Keys::generate().public_key(),
            label: "test".to_string(),
            created_at: Timestamp::now(),
            is_default: true,
            relays: Vec::<RelayUrl>::new(),
            lightning_address: None,
        }
    }

    fn sign_event(account: &Account, template: Value) -> Result<UnsignedEvent> {
        let request = parse(
            account,
            NostrConnectMethod::SignEvent,
            vec![template.to_string()],
        )?;
        match request {
            NostrConnectRequest::SignEvent(unsigned) => Ok(unsigned),
            other => panic!("parsed the wrong request: {other:?}"),
        }
    }

    #[test]
    fn a_template_without_a_pubkey_gets_the_account_s() {
        let account = account();
        let unsigned = sign_event(
            &account,
            json!({"kind": 1, "content": "hello", "tags": [], "created_at": 1_700_000_000u64}),
        )
        .expect("a bare template parses");

        assert_eq!(unsigned.pubkey, account.identity_public_key);
        assert_eq!(unsigned.kind, Kind::TextNote);
        assert_eq!(unsigned.content, "hello");
        assert_eq!(unsigned.created_at, Timestamp::from_secs(1_700_000_000));
    }

    #[test]
    fn a_pubkey_the_client_chose_is_replaced() {
        let account = account();
        let stranger = Keys::generate().public_key();
        let unsigned = sign_event(
            &account,
            json!({"pubkey": stranger.to_hex(), "kind": 1, "content": "hi", "tags": []}),
        )
        .expect("template parses");

        assert_eq!(unsigned.pubkey, account.identity_public_key);
    }

    #[test]
    fn an_id_the_client_chose_is_dropped() {
        let account = account();
        let unsigned = sign_event(
            &account,
            json!({"id": "00".repeat(32), "kind": 1, "content": "hi", "tags": []}),
        )
        .expect("template parses");

        assert_eq!(unsigned.id, None);
        assert_eq!(unsigned.compute_id(), unsigned.clone().id());
    }

    #[test]
    fn the_omitted_fields_get_defaults() {
        let account = account();
        let before = Timestamp::now();
        let unsigned =
            sign_event(&account, json!({"kind": 1, "content": ""})).expect("template parses");

        assert!(unsigned.tags.is_empty());
        assert!(unsigned.created_at >= before);
    }

    #[test]
    fn something_that_is_not_an_event_object_is_refused() {
        let account = account();
        assert!(sign_event(&account, json!("not an event")).is_err());
        assert!(parse(&account, NostrConnectMethod::SignEvent, Vec::new()).is_err());
    }

    #[test]
    fn other_methods_are_passed_through_untouched() {
        let account = account();
        let peer = Keys::generate().public_key();
        let request = parse(
            &account,
            NostrConnectMethod::Nip44Encrypt,
            vec![peer.to_hex(), "text".to_string()],
        )
        .expect("nip44_encrypt parses");

        assert!(matches!(
            request,
            NostrConnectRequest::Nip44Encrypt { public_key, text }
                if public_key == peer && text == "text"
        ));
    }
}
