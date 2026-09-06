//! Errors the signer produces, and how they reach a NIP-46 client.

use nostr::error::Error as NostrError;
use thiserror::Error;

use crate::keystore::KeyStoreError;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("signer is locked")]
    Locked,

    #[error("unknown client")]
    UnknownClient,

    #[error("client access was revoked")]
    ClientRevoked,

    #[error("no such account")]
    UnknownAccount,

    #[error("request denied by the user")]
    Denied,

    #[error("request expired before it was answered")]
    Expired,

    #[error("pairing secret does not match any pending pairing")]
    BadPairingSecret,

    #[error("method not supported: {0}")]
    UnsupportedMethod(String),

    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),

    #[error("nostr: {0}")]
    Nostr(#[from] NostrError),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("keystore: {0}")]
    KeyStore(#[from] KeyStoreError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("transport: {0}")]
    Transport(String),
}

impl SignerError {
    /// The message sent back to the client in a NIP-46 error response.
    ///
    /// Deliberately coarse: a client learns that it was refused, not why, so
    /// probing the signer reveals nothing about stored policy or accounts.
    pub fn client_message(&self) -> &'static str {
        match self {
            Self::Locked => "signer is locked",
            Self::Denied => "denied",
            Self::Expired => "timed out",
            Self::UnknownClient | Self::ClientRevoked | Self::BadPairingSecret => "unauthorized",
            Self::UnsupportedMethod(_) => "unsupported method",
            Self::InvalidRequest(_) => "invalid request",
            _ => "internal error",
        }
    }
}

pub type Result<T, E = SignerError> = std::result::Result<T, E>;
