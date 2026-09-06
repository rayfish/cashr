//! The request log shown in the window.
//!
//! Entries record what was asked and how it was answered. They never record
//! the content of what was signed or decrypted, only its shape.

use nostr::event::Kind;
use nostr::nips::nip46::NostrConnectMethod;
use nostr::types::Timestamp;
use rusqlite::{params, Row};

use super::{method_from_sql, Storage};
use crate::account::AccountId;
use crate::client::ClientId;
use crate::error::Result;

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityOutcome {
    Allowed,
    Denied,
    /// Failed before a decision was reached.
    Failed,
}

impl ActivityOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "allowed" => Some(Self::Allowed),
            "denied" => Some(Self::Denied),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// What produced the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivitySource {
    /// A stored rule answered without asking.
    Policy,
    /// The user answered a prompt.
    User,
    /// Nobody answered in time.
    Timeout,
    Error,
}

impl ActivitySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::User => "user",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "policy" => Some(Self::Policy),
            "user" => Some(Self::User),
            "timeout" => Some(Self::Timeout),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivityEntry {
    pub id: i64,
    pub account: AccountId,
    pub client: Option<ClientId>,
    pub method: NostrConnectMethod,
    pub kind: Option<Kind>,
    pub outcome: ActivityOutcome,
    pub source: ActivitySource,
    pub detail: Option<String>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct NewActivity {
    pub account: AccountId,
    pub client: Option<ClientId>,
    pub method: NostrConnectMethod,
    pub kind: Option<Kind>,
    pub outcome: ActivityOutcome,
    pub source: ActivitySource,
    pub detail: Option<String>,
}

/// Retention. Whichever limit bites first wins.
pub const MAX_ACTIVITY_AGE_SECS: u64 = 90 * 24 * 60 * 60;
pub const MAX_ACTIVITY_ROWS: u64 = 10_000;

impl Storage {
    pub fn record_activity(&self, entry: NewActivity) -> Result<()> {
        self.conn().execute(
            "INSERT INTO activity
                (account_id, client_id, method, kind, decision, source, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.account.get(),
                entry.client.map(|c| c.get()),
                entry.method.to_string(),
                entry.kind.map(|k| k.as_u16() as i64),
                entry.outcome.as_str(),
                entry.source.as_str(),
                entry.detail,
                Timestamp::now().as_secs() as i64,
            ],
        )?;
        Ok(())
    }

    /// Most recent first. `before` pages backwards by row id.
    pub fn activity(
        &self,
        account: AccountId,
        limit: u32,
        before: Option<i64>,
    ) -> Result<Vec<ActivityEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, account_id, client_id, method, kind, decision, source, detail, created_at
             FROM activity
             WHERE account_id = ?1 AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC
             LIMIT ?3",
        )?;
        let entries: Vec<ActivityEntry> = stmt
            .query_map(params![account.get(), before, limit], row_to_activity)?
            .collect::<std::result::Result<_, _>>()?;
        Ok(entries)
    }

    pub fn prune_activity(&self) -> Result<usize> {
        let cutoff = Timestamp::now()
            .as_secs()
            .saturating_sub(MAX_ACTIVITY_AGE_SECS) as i64;
        let conn = self.conn();
        let by_age = conn.execute(
            "DELETE FROM activity WHERE created_at < ?1",
            params![cutoff],
        )?;
        let by_count = conn.execute(
            "DELETE FROM activity WHERE id NOT IN
                (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
            params![MAX_ACTIVITY_ROWS],
        )?;
        Ok(by_age + by_count)
    }
}

fn row_to_activity(row: &Row<'_>) -> rusqlite::Result<ActivityEntry> {
    let method: String = row.get(3)?;
    let kind: Option<i64> = row.get(4)?;
    let outcome: String = row.get(5)?;
    let source: String = row.get(6)?;
    let created_at: i64 = row.get(8)?;

    let text_failure = |index: usize, message: &'static str| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            message.into(),
        )
    };

    Ok(ActivityEntry {
        id: row.get(0)?,
        account: AccountId::new(row.get(1)?),
        client: row.get::<_, Option<i64>>(2)?.map(ClientId::new),
        method: method_from_sql(&method).map_err(|_| text_failure(3, "unknown method"))?,
        kind: kind.map(|k| Kind::from_u16(k as u16)),
        outcome: ActivityOutcome::parse(&outcome)
            .ok_or_else(|| text_failure(5, "unknown outcome"))?,
        source: ActivitySource::parse(&source).ok_or_else(|| text_failure(6, "unknown source"))?,
        detail: row.get(7)?,
        created_at: Timestamp::from_secs(created_at.max(0) as u64),
    })
}
