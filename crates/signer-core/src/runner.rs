//! Ties a [`Transport`] to a [`Session`]: one listening task per account.
//!
//! Still transport-agnostic, so the loop itself is testable with a fake
//! transport and no relay in sight.

use std::collections::HashMap;
use std::sync::Arc;

use nostr::event::Event;
use nostr::types::RelayUrl;
use tokio::task::JoinHandle;

use crate::account::{Account, AccountId};
use crate::error::Result;
use crate::session::Session;
use crate::transport::{Subscription, Transport};
use crate::AsyncMutex;

pub struct Runner {
    session: Arc<Session>,
    transport: Arc<dyn Transport>,
    /// One listening task per account, so a single account can be restarted
    /// without disturbing the others.
    tasks: AsyncMutex<HashMap<AccountId, JoinHandle<()>>>,
}

impl Runner {
    pub fn new(session: Arc<Session>, transport: Arc<dyn Transport>) -> Self {
        Self {
            session,
            transport,
            tasks: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Listen for this account's requests until the transport closes.
    ///
    /// Starting an account that is already running replaces it, which is how a
    /// relay list change takes effect without a restart.
    pub async fn start(&self, account: Account) -> Result<()> {
        let id = account.id;
        self.stop(id).await;
        let handle = self.spawn(account).await?;
        self.tasks.lock().await.insert(id, handle);
        Ok(())
    }

    /// Start an account unless it is already running.
    ///
    /// Used at launch and after an unlock. [`Runner::start`] would drop a
    /// healthy connection and open a new subscription, which loses whatever
    /// arrived in the gap; this leaves a working account alone.
    pub async fn ensure(&self, account: Account) -> Result<()> {
        if self.tasks.lock().await.contains_key(&account.id) {
            return Ok(());
        }
        self.start(account).await
    }

    /// Close an account's connections and stop its task.
    pub async fn stop(&self, account: AccountId) {
        if let Some(task) = self.tasks.lock().await.remove(&account) {
            task.abort();
        }
        self.transport.stop(account).await;
    }

    async fn spawn(&self, account: Account) -> Result<JoinHandle<()>> {
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
                tracing::debug!(account = %account.id, sender = %event.pubkey, "an event arrived");
                if let Some(response) = session.handle(&account, event).await {
                    publish(transport.as_ref(), account.id, response, relays.clone()).await;
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
                publish(
                    self.transport.as_ref(),
                    account.id,
                    response,
                    account.relays.clone(),
                )
                .await;
            }
        }
        Ok(())
    }
}

/// A relay that will not take the response is a relay problem, not a reason to
/// stop the account's loop.
async fn publish(
    transport: &dyn Transport,
    account: AccountId,
    response: Event,
    relays: Vec<RelayUrl>,
) {
    if let Err(error) = transport.publish(account, response, relays).await {
        tracing::warn!("could not publish response: {error}");
    }
}
