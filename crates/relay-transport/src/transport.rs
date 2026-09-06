//! Relay pool behind the signer's [`Transport`] trait.
//!
//! One `nostr-sdk` client serves every account. Accounts are kept apart by
//! subscription id: a single reader task fans notifications out to the right
//! account's channel, rather than one reader per account all seeing
//! everything.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::types::{RelayUrl, Timestamp};
use nostr_sdk::client::Client;
use nostr_sdk::client::ClientNotification;
use nostr_sdk::prelude::{RelayStatus, StreamExt, SubscriptionId};
use signer_core::account::AccountId;
use signer_core::error::{Result, SignerError};
use signer_core::transport::{RelayHealth, Subscription, Transport};
use signer_core::AsyncMutex;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// How many undelivered events a single account may pile up before the reader
/// starts dropping them. A backlog this deep means the session is wedged, and
/// growing it without bound helps nobody.
const ACCOUNT_QUEUE: usize = 64;

struct Route {
    account: AccountId,
    sender: Sender<Event>,
}

pub struct RelayTransport {
    client: Client,
    routes: Arc<AsyncMutex<HashMap<SubscriptionId, Route>>>,
    /// Which relays each account asked for, so health can be reported per
    /// account even though the pool is shared.
    relays: AsyncMutex<HashMap<AccountId, Vec<RelayUrl>>>,
}

impl RelayTransport {
    pub fn new() -> Self {
        let client = Client::new();
        let routes: Arc<AsyncMutex<HashMap<SubscriptionId, Route>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));

        let mut notifications = client.notifications();
        let reader_routes = Arc::clone(&routes);
        tokio::spawn(async move {
            while let Some(notification) = notifications.next().await {
                let ClientNotification::Event {
                    subscription_id,
                    event,
                    ..
                } = notification
                else {
                    continue;
                };

                let sender = {
                    let routes = reader_routes.lock().await;
                    routes.get(&subscription_id).map(|r| r.sender.clone())
                };

                if let Some(sender) = sender {
                    if sender.try_send(*event).is_err() {
                        tracing::warn!(%subscription_id, "dropping event: account queue is full");
                    }
                }
            }
        });

        Self {
            client,
            routes,
            relays: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

impl Default for RelayTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for RelayTransport {
    async fn listen(&self, subscription: Subscription) -> Result<Receiver<Event>> {
        for relay in &subscription.relays {
            self.client
                .add_relay(relay.clone())
                .await
                .map_err(transport_error)?;
        }
        self.client.connect().await;

        // `since` keeps a relay from replaying an old backlog of requests the
        // moment the signer starts: a request from last week is not one the
        // user is waiting on.
        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(subscription.signer_public_key)
            .since(Timestamp::now());

        let id = SubscriptionId::generate();
        self.client
            .subscribe(filter)
            .with_id(id.clone())
            .await
            .map_err(transport_error)?;

        let (sender, receiver) = channel(ACCOUNT_QUEUE);
        self.routes.lock().await.insert(
            id,
            Route {
                account: subscription.account,
                sender,
            },
        );
        self.relays
            .lock()
            .await
            .insert(subscription.account, subscription.relays);

        Ok(receiver)
    }

    async fn publish(&self, event: Event, relays: Vec<RelayUrl>) -> Result<()> {
        self.client
            .send_event(&event)
            .to(relays)
            .await
            .map_err(transport_error)?;
        Ok(())
    }

    async fn health(&self, account: AccountId) -> Vec<RelayHealth> {
        let wanted = self
            .relays
            .lock()
            .await
            .get(&account)
            .cloned()
            .unwrap_or_default();
        let pool = self.client.relays().await;

        wanted
            .into_iter()
            .map(|url| match pool.get(&url) {
                Some(relay) => {
                    let status = relay.status();
                    RelayHealth {
                        relay: url,
                        connected: status == RelayStatus::Connected,
                        last_error: (status != RelayStatus::Connected).then(|| status.to_string()),
                    }
                }
                None => RelayHealth {
                    relay: url,
                    connected: false,
                    last_error: Some("not in the pool".to_string()),
                },
            })
            .collect()
    }
}

fn transport_error<E: std::fmt::Display>(error: E) -> SignerError {
    SignerError::Transport(error.to_string())
}

/// Routes are keyed by subscription id; this keeps the account association
/// readable in logs without exposing it on the public API.
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("account", &self.account)
            .finish()
    }
}
