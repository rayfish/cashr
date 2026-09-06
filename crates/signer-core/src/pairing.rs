//! Minting and accepting pairing URIs.
//!
//! Both NIP-46 directions end in the same place: a one-shot secret in the
//! `pairings` table that the next matching `connect` consumes.

use nostr::key::PublicKey;
use nostr::nips::nip46::{NostrConnectMetadata, NostrConnectUri};
use nostr::types::Timestamp;

use crate::account::Account;
use crate::client::PairingDirection;
use crate::error::{Result, SignerError};
use crate::storage::{NewPairing, Storage};

/// Bytes of entropy in a minted secret. 16 bytes is what the reference
/// implementations use and what fits comfortably in a pasted URI.
const SECRET_BYTES: usize = 16;

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
        expires_at: Timestamp::now() + ttl.as_secs(),
    })?;

    Ok(NostrConnectUri::Bunker {
        remote_signer_public_key: account.signer_public_key,
        relays: account.relays.clone(),
        secret: Some(secret),
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
        expires_at: Timestamp::now() + ttl.as_secs(),
    })?;

    Ok(ClientPairing {
        client_public_key: *public_key,
        relays: relays.clone(),
        metadata: metadata.clone(),
    })
}

/// What accepting a `nostrconnect://` URI told us about the client.
#[derive(Debug, Clone)]
pub struct ClientPairing {
    pub client_public_key: PublicKey,
    /// Relays the client listens on. The signer must answer there, whether or
    /// not they overlap with the account's own relays.
    pub relays: Vec<nostr::types::RelayUrl>,
    pub metadata: NostrConnectMetadata,
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|e| SignerError::Crypto(format!("no system entropy: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}
