//! Stored permission rules.

use nostr::event::Kind;
use nostr::types::Timestamp;
use rusqlite::params;

use super::{decision_from_sql, decision_to_sql, method_from_sql, Storage};
use crate::client::ClientId;
use crate::error::Result;
use crate::policy::{Decision, PolicySet, Rule, Scope};

impl Storage {
    /// Every rule stored for one client, ready to evaluate against.
    pub fn policy_set(&self, client: ClientId) -> Result<PolicySet> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT method, kind, decision FROM policies WHERE client_id = ?1")?;

        let rows: Vec<(String, Option<i64>, String)> = stmt
            .query_map(params![client.get()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;

        let mut rules = Vec::with_capacity(rows.len());
        for (method, kind, decision) in rows {
            rules.push(Rule::new(
                Scope {
                    method: method_from_sql(&method)?,
                    kind: kind.map(|k| Kind::from_u16(k as u16)),
                },
                decision_from_sql(&decision)?,
            ));
        }

        Ok(PolicySet::new(rules))
    }

    /// Write a rule, replacing any existing rule with the same scope.
    pub fn set_rule(&self, client: ClientId, scope: Scope, decision: Decision) -> Result<()> {
        self.conn().execute(
            "INSERT INTO policies (client_id, method, kind, decision, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (client_id, method, ifnull(kind, -1)) DO UPDATE SET
                 decision = ?4,
                 created_at = ?5",
            params![
                client.get(),
                scope.method.to_string(),
                scope.kind.map(|k| k.as_u16() as i64),
                decision_to_sql(decision),
                Timestamp::now().as_secs() as i64,
            ],
        )?;
        Ok(())
    }

    pub fn clear_rule(&self, client: ClientId, scope: Scope) -> Result<()> {
        self.conn().execute(
            "DELETE FROM policies
             WHERE client_id = ?1 AND method = ?2 AND ifnull(kind, -1) = ?3",
            params![
                client.get(),
                scope.method.to_string(),
                scope.kind.map(|k| k.as_u16() as i64).unwrap_or(-1),
            ],
        )?;
        Ok(())
    }

    pub fn clear_rules(&self, client: ClientId) -> Result<()> {
        self.conn().execute(
            "DELETE FROM policies WHERE client_id = ?1",
            params![client.get()],
        )?;
        Ok(())
    }
}
