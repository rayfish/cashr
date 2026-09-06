//! Minting and accepting pairing URIs.
//!
//! Both NIP-46 directions end in the same place: a one-shot secret in the
//! `pairings` table that the next matching `connect` consumes.

use std::fmt;

use nostr::key::PublicKey;
use nostr::nips::nip46::{NostrConnectMetadata, NostrConnectUri};
use nostr::types::url::Url;
use nostr::types::{RelayUrl, Timestamp};

use crate::account::Account;
use crate::client::PairingDirection;
use crate::error::{Result, SignerError};
use crate::storage::{NewPairing, Storage};

/// Bytes of entropy in a minted secret. 16 bytes is what the reference
/// implementations use and what fits comfortably in a pasted URI.
const SECRET_BYTES: usize = 16;

/// Scheme of a client-minted pairing URI.
const NOSTR_CONNECT_SCHEME: &str = "nostrconnect";

/// What the user pastes into a client.
///
/// The URI carries the secret, so it is shown once and treated as sensitive
/// until it is consumed.
pub fn mint_bunker_uri(
    storage: &Storage,
    account: &Account,
    ttl: std::time::Duration,
) -> Result<NostrConnectUri> {
    let secret = random_hex(SECRET_BYTES)?;

    storage.insert_pairing(NewPairing {
        account: account.id,
        secret: secret.clone(),
        direction: PairingDirection::Bunker,
        client_public_key: None,
        client_name: None,
        expires_at: Timestamp::now() + ttl.as_secs(),
    })?;

    Ok(NostrConnectUri::Bunker {
        remote_signer_public_key: account.signer_public_key,
        relays: account.relays.clone(),
        secret: Some(secret),
    })
}

/// Read a `nostrconnect://` URI a client minted.
///
/// NIP-46 puts the app's details in flat `name`, `url` and `image`
/// parameters. `NostrConnectUri::parse` still expects the older `metadata=`
/// JSON blob and rejects every URI that lacks one, which is every URI a
/// current client produces, so the client direction is read here instead.
pub fn parse_client_uri(uri: &str) -> Result<NostrConnectUri> {
    let parsed = Url::parse(uri).map_err(|_| SignerError::InvalidRequest("not a URI"))?;

    if parsed.scheme() != NOSTR_CONNECT_SCHEME {
        return Err(SignerError::InvalidRequest(
            "expected a nostrconnect:// URI",
        ));
    }

    let host = parsed.host_str().ok_or(SignerError::InvalidRequest(
        "the URI names no client public key",
    ))?;
    let public_key = PublicKey::from_hex(host)
        .map_err(|_| SignerError::InvalidRequest("the URI does not start with a public key"))?;

    let mut relays: Vec<RelayUrl> = Vec::new();
    let mut icons: Vec<Url> = Vec::new();
    let mut secret: Option<String> = None;
    let mut name: Option<String> = None;
    let mut url: Option<Url> = None;
    let mut description: Option<String> = None;
    // Clients written against the first draft send one JSON blob in place of
    // the separate fields. Cheap to keep reading.
    let mut legacy: Option<NostrConnectMetadata> = None;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "relay" => relays.push(RelayUrl::parse(&value).map_err(|_| {
                SignerError::InvalidRequest("the URI lists something that is not a relay URL")
            })?),
            "secret" => secret = Some(value.into_owned()),
            "name" => name = Some(value.into_owned()),
            "url" => url = Url::parse(&value).ok(),
            "image" => icons.extend(Url::parse(&value).ok()),
            "description" => description = Some(value.into_owned()),
            "metadata" => legacy = serde_json::from_str(&value).ok(),
            _ => (),
        }
    }

    if relays.is_empty() {
        return Err(SignerError::InvalidRequest(
            "the URI names no relay, so there is nowhere to answer",
        ));
    }

    // NIP-46 makes the secret mandatory in this direction: it is what tells
    // the client that the signer answering is the one the user pasted into.
    let secret = secret.ok_or(SignerError::InvalidRequest("the URI carries no secret"))?;

    let metadata = legacy.unwrap_or(NostrConnectMetadata {
        name: name.unwrap_or_default(),
        url,
        description,
        icons: (!icons.is_empty()).then_some(icons),
    });

    Ok(NostrConnectUri::Client {
        public_key,
        relays,
        metadata,
        secret,
    })
}

/// What the client minted and the user pasted in here.
///
/// The client's pubkey is recorded with the pairing, so the secret only works
/// for the app that produced it.
pub fn accept_client_uri(
    storage: &Storage,
    account: &Account,
    uri: &NostrConnectUri,
    ttl: std::time::Duration,
) -> Result<ClientPairing> {
    let NostrConnectUri::Client {
        public_key,
        relays,
        metadata,
        secret,
    } = uri
    else {
        return Err(SignerError::InvalidRequest(
            "expected a nostrconnect:// URI",
        ));
    };

    storage.insert_pairing(NewPairing {
        account: account.id,
        secret: secret.clone(),
        direction: PairingDirection::NostrConnect,
        client_public_key: Some(*public_key),
        client_name: (!metadata.name.is_empty()).then(|| metadata.name.clone()),
        expires_at: Timestamp::now() + ttl.as_secs(),
    })?;

    Ok(ClientPairing {
        client_public_key: *public_key,
        relays: relays.clone(),
        metadata: metadata.clone(),
        secret: secret.clone(),
    })
}

/// What accepting a `nostrconnect://` URI told us about the client.
#[derive(Clone)]
pub struct ClientPairing {
    pub client_public_key: PublicKey,
    /// Relays the client listens on. The signer must answer there, whether or
    /// not they overlap with the account's own relays.
    pub relays: Vec<RelayUrl>,
    pub metadata: NostrConnectMetadata,
    /// The secret the client minted. It goes back to the client in the ack,
    /// which is how the client tells this signer from a spoof.
    pub secret: String,
}

/// Hand-written so a stray `{:?}` cannot print the secret.
impl fmt::Debug for ClientPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPairing")
            .field("client_public_key", &self.client_public_key)
            .field("relays", &self.relays)
            .field("metadata", &self.metadata)
            .field("secret", &"[redacted]")
            .finish()
    }
}

pub(crate) fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|e| SignerError::Crypto(format!("no system entropy: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape a current client produces: flat `name` and `url`, no `metadata`.
    const MODERN: &str =
        "nostrconnect://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
?relay=wss%3A%2F%2Frelay.example%2F&relay=wss%3A%2F%2Fother.example%2F\
&secret=abc123&name=example.app&url=https%3A%2F%2Fexample.app";

    fn client_parts(uri: &NostrConnectUri) -> (&Vec<RelayUrl>, &NostrConnectMetadata, &String) {
        match uri {
            NostrConnectUri::Client {
                relays,
                metadata,
                secret,
                ..
            } => (relays, metadata, secret),
            _ => panic!("not a client URI"),
        }
    }

    #[test]
    fn reads_the_flat_parameters_a_client_actually_sends() {
        let uri = parse_client_uri(MODERN).expect("a current client URI should parse");
        let (relays, metadata, secret) = client_parts(&uri);

        assert_eq!(relays.len(), 2);
        assert_eq!(metadata.name, "example.app");
        assert_eq!(
            metadata.url.as_ref().map(|u| u.as_str()),
            Some("https://example.app/")
        );
        assert_eq!(secret, "abc123");
    }

    #[test]
    fn still_reads_the_older_metadata_blob() {
        let uri = parse_client_uri(
            "nostrconnect://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
?relay=wss%3A%2F%2Frelay.example%2F&secret=abc123&metadata=%7B%22name%22%3A%22old.app%22%7D",
        )
        .expect("a first-draft URI should still parse");
        let (_, metadata, _) = client_parts(&uri);

        assert_eq!(metadata.name, "old.app");
    }

    #[test]
    fn refuses_a_uri_with_no_secret() {
        let uri = "nostrconnect://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
?relay=wss%3A%2F%2Frelay.example%2F&name=example.app";
        assert!(parse_client_uri(uri).is_err());
    }

    #[test]
    fn refuses_a_uri_with_no_relay() {
        let uri = "nostrconnect://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
?secret=abc123&name=example.app";
        assert!(parse_client_uri(uri).is_err());
    }

    #[test]
    fn refuses_a_bunker_uri() {
        let uri = "bunker://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
?relay=wss%3A%2F%2Frelay.example%2F&secret=abc123";
        assert!(parse_client_uri(uri).is_err());
    }
}
