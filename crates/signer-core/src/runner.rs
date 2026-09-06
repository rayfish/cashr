//! Ties a [`Transport`] to a [`Session`]: one listening task per account.
//!
//! Still transport-agnostic, so the loop itself is testable with a fake
//! transport and no relay in sight.

use std::sync::Arc;

use nostr::event::Event;
use tokio::task::JoinHandle;

use crate::account::Account;
use crate::error::Result;
use crate::session::Session;
use crate::transport::{Subscription, Transport};

pub struct Runner {
    session: Arc<Session>,
    transport: Arc<dyn Transport>,
}

impl Runner {
    pub fn new(session: Arc<Session>, transport: Arc<dyn Transport>) -> Self {
        Self { session, transport }
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Listen for this account's requests until the transport closes.
    pub async fn start(&self, account: Account) -> Result<JoinHandle<()>> {
        let mut incoming = self
            .transport
            .listen(Subscription {
                account: account.id,
                signer_public_key: account.signer_public_key,
                relays: account.relays.clone(),
            })
            .await?;

        let session = Arc::clone(&self.session);
        let transport = Arc::clone(&self.transport);
        let relays = account.relays.clone();

        Ok(tokio::spawn(async move {
            while let Some(event) = incoming.recv().await {
                if let Some(response) = session.handle(&account, event).await {
                    publish(transport.as_ref(), response, relays.clone()).await;
                }
            }
        }))
    }

    /// Answer requests that arrived while the signer was locked.
    ///
    /// Called after an unlock. Anything already stale was dropped by the
    /// session, so this only replays what a client could still be waiting on.
    pub async fn replay_deferred(&self, accounts: &[Account]) -> Result<()> {
        for (account_id, event) in self.session.take_deferred().await {
            let Some(account) = accounts.iter().find(|a| a.id == account_id) else {
                continue;
            };
            if let Some(response) = self.session.handle(account, event).await {
                publish(self.transport.as_ref(), response, account.relays.clone()).await;
            }
        }
        Ok(())
    }
}

/// A relay that will not take the response is a relay problem, not a reason to
/// stop the account's loop.
async fn publish(transport: &dyn Transport, response: Event, relays: Vec<nostr::types::RelayUrl>) {
    if let Err(error) = transport.publish(response, relays).await {
        tracing::warn!("could not publish response: {error}");
    }
}
