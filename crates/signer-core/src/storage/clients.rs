//! Paired clients.

use nostr::key::PublicKey;
use nostr::types::Timestamp;
use rusqlite::{params, OptionalExtension, Row};

use super::Storage;
use crate::account::AccountId;
use crate::client::{Client, ClientId};
use crate::error::{Result, SignerError};

impl Storage {
    /// Record a client pairing, or refresh the row if this client is already
    /// known to the account.
    pub fn upsert_client(
        &self,
        account: AccountId,
        public_key: &PublicKey,
        name: Option<&str>,
    ) -> Result<Client> {
        let now = Timestamp::now().as_secs() as i64;
        let conn = self.conn();

        conn.execute(
            "INSERT INTO clients (account_id, public_key, name, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT (account_id, public_key) DO UPDATE SET
                 last_seen = ?4,
                 name = coalesce(?3, clients.name)",
            params![account.get(), public_key.to_hex(), name, now],
        )?;
        drop(conn);

        self.client_by_public_key(account, public_key)?
            .ok_or(SignerError::UnknownClient)
    }

    pub fn client_by_public_key(
        &self,
        account: AccountId,
        public_key: &PublicKey,
    ) -> Result<Option<Client>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, account_id, public_key, name, first_seen, last_seen, revoked_at
                 FROM clients WHERE account_id = ?1 AND public_key = ?2",
                params![account.get(), public_key.to_hex()],
                row_to_client,
            )
            .optional()?)
    }

    pub fn clients(&self, account: AccountId) -> Result<Vec<Client>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, account_id, public_key, name, first_seen, last_seen, revoked_at
             FROM clients WHERE account_id = ?1 ORDER BY last_seen DESC",
        )?;
        let clients: Vec<Client> = stmt
            .query_map(params![account.get()], row_to_client)?
            .collect::<std::result::Result<_, _>>()?;
        Ok(clients)
    }

    pub fn touch_client(&self, id: ClientId) -> Result<()> {
        self.conn().execute(
            "UPDATE clients SET last_seen = ?2 WHERE id = ?1",
            params![id.get(), Timestamp::now().as_secs() as i64],
        )?;
        Ok(())
    }

    /// Revoke access. Stored rules go with it, so re-pairing starts from a
    /// clean slate rather than silently inheriting old permissions.
    pub fn revoke_client(&self, id: ClientId) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE clients SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id.get(), Timestamp::now().as_secs() as i64],
        )?;
        if changed == 0 {
            return Err(SignerError::UnknownClient);
        }
        tx.execute(
            "DELETE FROM policies WHERE client_id = ?1",
            params![id.get()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn row_to_client(row: &Row<'_>) -> rusqlite::Result<Client> {
    let public_key: String = row.get(2)?;
    let first_seen: i64 = row.get(4)?;
    let last_seen: i64 = row.get(5)?;
    let revoked_at: Option<i64> = row.get(6)?;

    Ok(Client {
        id: ClientId::new(row.get(0)?),
        account: AccountId::new(row.get(1)?),
        public_key: PublicKey::from_hex(&public_key).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?,
        name: row.get(3)?,
        first_seen: Timestamp::from_secs(first_seen.max(0) as u64),
        last_seen: Timestamp::from_secs(last_seen.max(0) as u64),
        revoked_at: revoked_at.map(|secs| Timestamp::from_secs(secs.max(0) as u64)),
    })
}
