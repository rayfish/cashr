//! Account rows and their relay lists.

use nostr::key::PublicKey;
use nostr::types::{RelayUrl, Timestamp};
use rusqlite::{params, OptionalExtension, Row};

use super::Storage;
use crate::account::{Account, AccountId};
use crate::error::{Result, SignerError};

/// What an account needs at creation time.
#[derive(Debug, Clone)]
pub struct NewAccount {
    pub identity_public_key: PublicKey,
    pub signer_public_key: PublicKey,
    pub label: String,
    pub relays: Vec<RelayUrl>,
    pub is_default: bool,
}

impl Storage {
    pub fn insert_account(&self, new: NewAccount) -> Result<Account> {
        let created_at = Timestamp::now();
        let mut conn = self.conn();
        let tx = conn.transaction()?;

        if new.is_default {
            tx.execute("UPDATE accounts SET is_default = 0", [])?;
        }

        tx.execute(
            "INSERT INTO accounts
                (identity_public_key, signer_public_key, label, created_at, is_default)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                new.identity_public_key.to_hex(),
                new.signer_public_key.to_hex(),
                new.label,
                created_at.as_secs() as i64,
                new.is_default,
            ],
        )?;
        let id = AccountId::new(tx.last_insert_rowid());

        for (position, relay) in new.relays.iter().enumerate() {
            tx.execute(
                "INSERT INTO account_relays (account_id, url, position) VALUES (?1, ?2, ?3)",
                params![id.get(), relay.as_str(), position as i64],
            )?;
        }

        tx.commit()?;

        Ok(Account {
            id,
            identity_public_key: new.identity_public_key,
            signer_public_key: new.signer_public_key,
            label: new.label,
            created_at,
            is_default: new.is_default,
            relays: new.relays,
            lightning_address: None,
        })
    }

    pub fn accounts(&self) -> Result<Vec<Account>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, identity_public_key, signer_public_key, label, created_at, is_default, lightning_address
             FROM accounts ORDER BY created_at",
        )?;
        let rows: Vec<Account> = stmt
            .query_map([], row_to_account)?
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        drop(conn);

        rows.into_iter()
            .map(|mut account| {
                account.relays = self.account_relays(account.id)?;
                Ok(account)
            })
            .collect()
    }

    pub fn account(&self, id: AccountId) -> Result<Account> {
        let mut account = {
            let conn = self.conn();
            conn.query_row(
                "SELECT id, identity_public_key, signer_public_key, label, created_at, is_default, lightning_address
                 FROM accounts WHERE id = ?1",
                params![id.get()],
                row_to_account,
            )
            .optional()?
            .ok_or(SignerError::UnknownAccount)?
        };
        account.relays = self.account_relays(id)?;
        Ok(account)
    }

    /// Look up the account a NIP-46 event was addressed to.
    pub fn account_by_signer_key(&self, signer_public_key: &PublicKey) -> Result<Option<Account>> {
        let found = {
            let conn = self.conn();
            conn.query_row(
                "SELECT id, identity_public_key, signer_public_key, label, created_at, is_default, lightning_address
                 FROM accounts WHERE signer_public_key = ?1",
                params![signer_public_key.to_hex()],
                row_to_account,
            )
            .optional()?
        };

        match found {
            Some(mut account) => {
                account.relays = self.account_relays(account.id)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    pub fn account_relays(&self, id: AccountId) -> Result<Vec<RelayUrl>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT url FROM account_relays WHERE account_id = ?1 ORDER BY position")?;
        let urls: Vec<String> = stmt
            .query_map(params![id.get()], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;

        urls.iter()
            .map(|url| RelayUrl::parse(url).map_err(SignerError::Nostr))
            .collect()
    }

    pub fn set_account_relays(&self, id: AccountId, relays: &[RelayUrl]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM account_relays WHERE account_id = ?1",
            params![id.get()],
        )?;
        for (position, relay) in relays.iter().enumerate() {
            tx.execute(
                "INSERT INTO account_relays (account_id, url, position) VALUES (?1, ?2, ?3)",
                params![id.get(), relay.as_str(), position as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_default_account(&self, id: AccountId) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE accounts SET is_default = 0", [])?;
        let changed = tx.execute(
            "UPDATE accounts SET is_default = 1 WHERE id = ?1",
            params![id.get()],
        )?;
        if changed == 0 {
            return Err(SignerError::UnknownAccount);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_account(&self, id: AccountId) -> Result<()> {
        let changed = self
            .conn()
            .execute("DELETE FROM accounts WHERE id = ?1", params![id.get()])?;
        if changed == 0 {
            return Err(SignerError::UnknownAccount);
        }
        Ok(())
    }

    /// Save an address only; this does not verify its provider or publish a profile.
    pub fn set_lightning_address(&self, id: AccountId, address: Option<&str>) -> Result<()> {
        let address = address.map(str::trim).filter(|value| !value.is_empty());
        if let Some(value) = address {
            let (name, domain) = value.split_once('@').ok_or(SignerError::InvalidRequest(
                "use a Lightning address such as alice@example.com",
            ))?;
            let valid_name = !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.+".contains(&c));
            let valid_domain = domain.len() <= 253
                && domain.contains('.')
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                });
            if value.len() > 320 || !valid_name || !valid_domain {
                return Err(SignerError::InvalidRequest("use a Lightning address with a lowercase username and a domain, such as alice@example.com"));
            }
        }
        let normalized = address.map(|value| {
            let (name, domain) = value.split_once('@').expect("validated address");
            format!("{name}@{}", domain.to_ascii_lowercase())
        });
        let changed = self.conn().execute(
            "UPDATE accounts SET lightning_address = ?1 WHERE id = ?2",
            params![normalized, id.get()],
        )?;
        if changed == 0 {
            return Err(SignerError::UnknownAccount);
        }
        Ok(())
    }
}

fn row_to_account(row: &Row<'_>) -> rusqlite::Result<Account> {
    let identity: String = row.get(1)?;
    let signer: String = row.get(2)?;
    let created_at: i64 = row.get(4)?;

    let parse = |hex: &str, index: usize| {
        PublicKey::from_hex(hex).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
    };

    Ok(Account {
        id: AccountId::new(row.get(0)?),
        identity_public_key: parse(&identity, 1)?,
        signer_public_key: parse(&signer, 2)?,
        label: row.get(3)?,
        created_at: Timestamp::from_secs(created_at.max(0) as u64),
        is_default: row.get(5)?,
        relays: Vec::new(),
        lightning_address: row.get(6)?,
    })
}
