//! SQLite persistence.
//!
//! This file holds metadata only. Key material lives in the [`KeyStore`] and
//! never reaches this database, which is what keeps a backup or a synced
//! directory from becoming a key leak.
//!
//! [`KeyStore`]: crate::keystore::KeyStore

mod accounts;
mod activity;
mod clients;
mod migrations;
mod pairings;
mod policies;

pub use accounts::NewAccount;
pub use activity::{
    ActivityEntry, ActivityOutcome, ActivitySource, NewActivity, MAX_ACTIVITY_AGE_SECS,
    MAX_ACTIVITY_ROWS,
};
pub use pairings::{NewPairing, Pairing, PairingId};

use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use nostr::nips::nip46::NostrConnectMethod;
use rusqlite::Connection;

use crate::error::{Result, SignerError};
use crate::policy::Decision;

pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    /// Open (creating if needed) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        restrict_permissions(path)?;
        Self::prepare(conn)
    }

    /// An ephemeral database. Tests only.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        migrations::apply(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// A poisoned lock means another thread panicked mid-query. The connection
    /// itself is still sound, and refusing to sign because of it would be a
    /// worse outcome than carrying on.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::fs::{set_permissions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    set_permissions(path, Permissions::from_mode(0o600))
        .map_err(|e| SignerError::Storage(rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn decision_to_sql(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

fn decision_from_sql(value: &str) -> Result<Decision> {
    match value {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        _ => Err(SignerError::InvalidRequest("unknown decision in database")),
    }
}

fn method_from_sql(value: &str) -> Result<NostrConnectMethod> {
    NostrConnectMethod::from_str(value).map_err(SignerError::Nostr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_version(storage: &Storage) -> usize {
        storage
            .conn()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user_version readable")
    }

    #[test]
    fn migrations_are_idempotent() {
        let storage = Storage::in_memory().expect("in-memory database opens");
        let version = user_version(&storage);
        assert!(version > 0, "a fresh database runs its migrations");

        migrations::apply(&storage.conn()).expect("re-applying is a no-op");
        assert_eq!(user_version(&storage), version);
    }
}
