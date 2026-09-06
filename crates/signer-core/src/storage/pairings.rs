//! Pending pairings.
//!
//! A pairing is a one-shot capability: a secret that turns the next matching
//! `connect` into a trusted client. It is consumed on use and expires on its
//! own, so a URI that leaks after the fact is worth nothing.

use nostr::key::PublicKey;
use nostr::types::Timestamp;
use rusqlite::{params, OptionalExtension, Row};

use super::Storage;
use crate::account::AccountId;
use crate::client::PairingDirection;
use crate::error::{Result, SignerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PairingId(i64);

impl PairingId {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn get(&self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct Pairing {
    pub id: PairingId,
    pub account: AccountId,
    pub secret: String,
    pub direction: PairingDirection,
    /// Known up front for `nostrconnect://`, learned at connect time for
    /// `bunker://`.
    pub client_public_key: Option<PublicKey>,
    /// The name the app gave in its URI. `bunker://` carries none.
    pub client_name: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
}

impl Pairing {
    pub fn is_usable(&self, now: Timestamp) -> bool {
        self.consumed_at.is_none() && self.expires_at > now
    }
}

#[derive(Debug, Clone)]
pub struct NewPairing {
    pub account: AccountId,
    pub secret: String,
    pub direction: PairingDirection,
    pub client_public_key: Option<PublicKey>,
    pub client_name: Option<String>,
    pub expires_at: Timestamp,
}

impl Storage {
    pub fn insert_pairing(&self, new: NewPairing) -> Result<Pairing> {
        let created_at = Timestamp::now();
        let conn = self.conn();

        conn.execute(
            "INSERT INTO pairings
                (account_id, secret, direction, client_public_key, client_name,
                 created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                new.account.get(),
                new.secret,
                new.direction.as_str(),
                new.client_public_key.map(|pk| pk.to_hex()),
                new.client_name,
                created_at.as_secs() as i64,
                new.expires_at.as_secs() as i64,
            ],
        )?;

        Ok(Pairing {
            id: PairingId::new(conn.last_insert_rowid()),
            account: new.account,
            secret: new.secret,
            direction: new.direction,
            client_public_key: new.client_public_key,
            client_name: new.client_name,
            created_at,
            expires_at: new.expires_at,
            consumed_at: None,
        })
    }

    /// Find an unconsumed, unexpired pairing by its secret.
    pub fn usable_pairing(&self, secret: &str) -> Result<Option<Pairing>> {
        let now = Timestamp::now().as_secs() as i64;
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, account_id, secret, direction, client_public_key,
                        created_at, expires_at, consumed_at, client_name
                 FROM pairings
                 WHERE secret = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                params![secret, now],
                row_to_pairing,
            )
            .optional()?)
    }

    pub fn consume_pairing(&self, id: PairingId, client_public_key: &PublicKey) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE pairings SET consumed_at = ?2, client_public_key = ?3
             WHERE id = ?1 AND consumed_at IS NULL",
            params![
                id.get(),
                Timestamp::now().as_secs() as i64,
                client_public_key.to_hex()
            ],
        )?;
        if changed == 0 {
            return Err(SignerError::BadPairingSecret);
        }
        Ok(())
    }

    /// Drop pairings that expired or were used. Called on startup.
    pub fn prune_pairings(&self) -> Result<usize> {
        let now = Timestamp::now().as_secs() as i64;
        Ok(self.conn().execute(
            "DELETE FROM pairings WHERE consumed_at IS NOT NULL OR expires_at <= ?1",
            params![now],
        )?)
    }
}

fn row_to_pairing(row: &Row<'_>) -> rusqlite::Result<Pairing> {
    let direction: String = row.get(3)?;
    let client_public_key: Option<String> = row.get(4)?;
    let created_at: i64 = row.get(5)?;
    let expires_at: i64 = row.get(6)?;
    let consumed_at: Option<i64> = row.get(7)?;
    let client_name: Option<String> = row.get(8)?;

    let direction = match direction.as_str() {
        "bunker" => PairingDirection::Bunker,
        "nostrconnect" => PairingDirection::NostrConnect,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                "unknown pairing direction".into(),
            ))
        }
    };

    let client_public_key = client_public_key
        .map(|hex| PublicKey::from_hex(&hex))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(Pairing {
        id: PairingId::new(row.get(0)?),
        account: AccountId::new(row.get(1)?),
        secret: row.get(2)?,
        direction,
        client_public_key,
        client_name,
        created_at: Timestamp::from_secs(created_at.max(0) as u64),
        expires_at: Timestamp::from_secs(expires_at.max(0) as u64),
        consumed_at: consumed_at.map(|secs| Timestamp::from_secs(secs.max(0) as u64)),
    })
}
