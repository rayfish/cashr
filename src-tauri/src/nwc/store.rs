use anyhow::{ensure, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[derive(Clone, Serialize)]
pub struct Pairing {
    pub id: String,
    pub account: i64,
    pub label: String,
    pub mint: String,
    pub relay: String,
    pub client: String,
    pub wallet: String,
    pub created: u64,
    #[serde(skip)]
    pub info: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Begin {
    New,
    Replay,
    Limited,
}

pub struct Store(Mutex<Connection>);
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY, account INTEGER NOT NULL, label TEXT NOT NULL,
                mint TEXT NOT NULL, relay TEXT NOT NULL, client TEXT NOT NULL,
                wallet TEXT NOT NULL, created INTEGER NOT NULL, info TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY, connection TEXT NOT NULL, created INTEGER NOT NULL,
                response TEXT);
            CREATE TABLE IF NOT EXISTS payments (
                identity TEXT NOT NULL, hash TEXT NOT NULL, request TEXT NOT NULL,
                PRIMARY KEY(identity, hash));",
        )?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS transport_keys (connection TEXT PRIMARY KEY, sealed TEXT NOT NULL);")?;
        Ok(Self(Mutex::new(db)))
    }
    fn db(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn sealed_key(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .db()
            .query_row(
                "SELECT sealed FROM transport_keys WHERE connection=?",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn save_key(&self, id: &str, sealed: &str) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO transport_keys VALUES (?,?)",
            params![id, sealed],
        )?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<Pairing>> {
        let db = self.db();
        let mut query = db.prepare("SELECT id,account,label,mint,relay,client,wallet,created,info FROM connections WHERE revoked=0 ORDER BY created")?;
        let rows = query.query_map([], |r| {
            Ok(Pairing {
                id: r.get(0)?,
                account: r.get(1)?,
                label: r.get(2)?,
                mint: r.get(3)?,
                relay: r.get(4)?,
                client: r.get(5)?,
                wallet: r.get(6)?,
                created: r.get(7)?,
                info: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn add(&self, p: &Pairing) -> Result<()> {
        let db = self.db();
        let count: u64 = db.query_row(
            "SELECT count(*) FROM connections WHERE revoked=0",
            [],
            |r| r.get(0),
        )?;
        ensure!(count < 16, "Revoke an unused connection first.");
        db.execute("INSERT INTO connections (id,account,label,mint,relay,client,wallet,created,info) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![p.id,p.account,p.label,p.mint,p.relay,p.client,p.wallet,p.created,p.info])?;
        Ok(())
    }
    pub fn active(&self, id: &str) -> bool {
        self.db()
            .query_row("SELECT revoked=0 FROM connections WHERE id=?", [id], |r| {
                r.get(0)
            })
            .unwrap_or(false)
    }
    pub fn revoke(&self, id: &str, account: i64) -> Result<()> {
        ensure!(
            self.db().execute(
                "UPDATE connections SET revoked=1 WHERE id=? AND account=? AND revoked=0",
                params![id, account]
            )? == 1,
            "Connection not found."
        );
        Ok(())
    }
    pub fn revoke_account(&self, account: i64) -> Result<()> {
        self.db().execute(
            "UPDATE connections SET revoked=1 WHERE account=?",
            [account],
        )?;
        Ok(())
    }
    // Write before handling. A crash can leave an unanswered request, never a replayed spend.
    pub fn begin(&self, id: &str, connection: &str) -> Result<Begin> {
        let db = self.db();
        let now = super::protocol::now();
        db.execute(
            "DELETE FROM requests WHERE response IS NOT NULL AND created<?",
            [now.saturating_sub(600)],
        )?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM requests WHERE id=?)",
            [id],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(Begin::Replay);
        }
        let count: u64 = db.query_row(
            "SELECT count(*) FROM requests WHERE connection=? AND created>?",
            params![connection, now.saturating_sub(60)],
            |r| r.get(0),
        )?;
        if count >= 60 {
            return Ok(Begin::Limited);
        }
        db.execute(
            "INSERT INTO requests (id,connection,created) VALUES (?1,?2,?3)",
            params![id, connection, now],
        )?;
        Ok(Begin::New)
    }
    pub fn cached(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .db()
            .query_row("SELECT response FROM requests WHERE id=?", [id], |r| {
                r.get(0)
            })
            .optional()?
            .flatten())
    }
    pub fn finish(&self, id: &str, response: &str) -> Result<()> {
        self.db().execute(
            "UPDATE requests SET response=? WHERE id=?",
            params![response, id],
        )?;
        Ok(())
    }
    // Payment hash is claimed immediately before execution, across all connections/mints.
    pub fn claim(&self, identity: &str, hash: &str, request: &str) -> Result<bool> {
        Ok(self.db().execute(
            "INSERT OR IGNORE INTO payments VALUES (?1,?2,?3)",
            params![identity, hash, request],
        )? == 1)
    }
    pub fn recent(&self, connection: &str) -> Result<Vec<String>> {
        let db = self.db();
        let mut query = db.prepare("SELECT response FROM requests WHERE connection=? AND created>? AND response IS NOT NULL AND response<>'' ORDER BY created DESC LIMIT 32")?;
        let rows = query.query_map(
            params![connection, super::protocol::now().saturating_sub(300)],
            |r| r.get(0),
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_and_payment_claims_survive_restart_and_span_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nwc.sqlite");
        let db = Store::open(&path).unwrap();
        assert_eq!(db.begin("request", "jumble").unwrap(), Begin::New);
        assert_eq!(db.begin("request", "jumble").unwrap(), Begin::Replay);
        assert!(db.claim("wallet", "hash", "request").unwrap());
        drop(db);
        let db = Store::open(&path).unwrap();
        assert_eq!(db.begin("request", "jumble").unwrap(), Begin::Replay);
        assert!(!db.claim("wallet", "hash", "new-request").unwrap());
        db.finish("request", "encrypted response").unwrap();
        assert_eq!(
            db.cached("request").unwrap().as_deref(),
            Some("encrypted response")
        );
        assert!(db.claim("other-wallet", "hash", "other-request").unwrap());
    }
    #[test]
    fn limits_new_requests_but_keeps_cached_replies_available() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(&dir.path().join("nwc.sqlite")).unwrap();
        for i in 0..60 {
            assert_eq!(db.begin(&i.to_string(), "client").unwrap(), Begin::New);
        }
        assert_eq!(db.begin("next", "client").unwrap(), Begin::Limited);
        assert_eq!(db.begin("0", "client").unwrap(), Begin::Replay);
        assert_eq!(db.begin("other", "other-client").unwrap(), Begin::New);
    }
    #[test]
    fn revocation_is_scoped_and_does_not_erase_payment_guards() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(&dir.path().join("nwc.sqlite")).unwrap();
        for account in [1, 2] {
            db.add(&Pairing {
                id: account.to_string(),
                account,
                label: "Jumble".into(),
                mint: "mint".into(),
                relay: "relay".into(),
                client: "client".into(),
                wallet: "wallet".into(),
                created: 1,
                info: "info".into(),
            })
            .unwrap();
        }
        assert!(db.claim("identity", "hash", "req").unwrap());
        assert!(db.revoke("1", 2).is_err());
        assert!(db.active("1"));
        db.revoke_account(1).unwrap();
        assert!(!db.active("1"));
        assert!(db.active("2"));
        assert!(!db.claim("identity", "hash", "retry").unwrap());
    }
}
