//! Schema versions, applied in order by stepping `PRAGMA user_version`.
//!
//! Migrations are append-only: an existing entry is never edited, because a
//! database in the field has already run it.

use rusqlite::Connection;

use crate::error::Result;

const MIGRATIONS: &[&str] = &[
    // v1: accounts, clients, policies, pairings, activity.
    r#"
    CREATE TABLE accounts (
        id                  INTEGER PRIMARY KEY,
        identity_public_key TEXT    NOT NULL UNIQUE,
        signer_public_key   TEXT    NOT NULL UNIQUE,
        label               TEXT    NOT NULL,
        created_at          INTEGER NOT NULL,
        is_default          INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE account_relays (
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        url        TEXT    NOT NULL,
        position   INTEGER NOT NULL,
        PRIMARY KEY (account_id, url)
    );

    CREATE TABLE clients (
        id         INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        public_key TEXT    NOT NULL,
        name       TEXT,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        revoked_at INTEGER,
        UNIQUE (account_id, public_key)
    );

    CREATE TABLE policies (
        id         INTEGER PRIMARY KEY,
        client_id  INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        method     TEXT    NOT NULL,
        kind       INTEGER,
        decision   TEXT    NOT NULL,
        created_at INTEGER NOT NULL
    );

    -- NULL kind is the method-wide rule. SQLite does not treat NULLs as equal
    -- in a UNIQUE constraint, so the index normalises it first.
    CREATE UNIQUE INDEX policies_scope
        ON policies (client_id, method, ifnull(kind, -1));

    CREATE TABLE pairings (
        id                INTEGER PRIMARY KEY,
        account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        secret            TEXT    NOT NULL,
        direction         TEXT    NOT NULL,
        client_public_key TEXT,
        created_at        INTEGER NOT NULL,
        expires_at        INTEGER NOT NULL,
        consumed_at       INTEGER
    );

    CREATE INDEX pairings_secret ON pairings (secret);

    CREATE TABLE activity (
        id         INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        client_id  INTEGER REFERENCES clients(id) ON DELETE SET NULL,
        method     TEXT    NOT NULL,
        kind       INTEGER,
        decision   TEXT    NOT NULL,
        source     TEXT    NOT NULL,
        detail     TEXT,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX activity_created ON activity (created_at DESC);
    "#,
    // v2: the app name a `nostrconnect://` URI carried, so the client row and
    // every prompt after it can say who is asking.
    r#"
    ALTER TABLE pairings ADD COLUMN client_name TEXT;
    "#,
    // v3: removing a client takes it off the list without dropping the row.
    // The row is what carries the revocation, and a revocation that a delete
    // could erase would be a revocation the user cannot rely on.
    r#"
    ALTER TABLE clients ADD COLUMN removed_at INTEGER;
    "#,
    // v4: an existing receiving address, saved locally for each identity.
    r#"
    ALTER TABLE accounts ADD COLUMN lightning_address TEXT;
    "#,
];

pub fn apply(conn: &Connection) -> Result<()> {
    let current: usize = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        conn.execute_batch(sql)?;
        // PRAGMA does not accept a bound parameter.
        conn.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
    }

    Ok(())
}
