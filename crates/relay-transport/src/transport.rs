//! Relay pool behind the signer's [`Transport`] trait.
//!
//! One connection per account per relay, each with its own reconnect loop, so
//! a relay being down is a property of that relay rather than something that
//! stops an account.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::message::SubscriptionId;
use nostr::types::{RelayUrl, Timestamp};
use signer_core::account::AccountId;
use signer_core::error::{Result, SignerError};
use signer_core::transport::{RelayHealth, Subscription, Transport};
use signer_core::vault::Vault;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::connection::Connection;

/// How many undelivered events one account may pile up before the reader
/// starts dropping them. A backlog this deep means the session is wedged, and
/// growing it without bound helps nobody.
const ACCOUNT_QUEUE: usize = 64;

/// How many unsent events may queue for a single relay. Small: these are
/// answers to requests that expire in a minute, so a deep queue would only
/// deliver replies nobody is waiting for any more.
const RELAY_QUEUE: usize = 16;

struct Link {
    outgoing: Sender<Event>,
    health: Arc<Mutex<RelayHealth>>,
    task: JoinHandle<()>,
}

struct Pool {
    /// In configured order, which is the order the window shows.
    relays: Vec<RelayUrl>,
    links: HashMap<RelayUrl, Link>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        for link in self.links.values() {
            link.task.abort();
        }
    }
}

#[derive(Default)]
pub struct RelayTransport {
    pools: Mutex<HashMap<AccountId, Pool>>,
    vault: Arc<Vault>,
}

impl RelayTransport {
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            ..Self::default()
        }
    }

    /// The lock only ever guards map bookkeeping, never an await, so a
    /// poisoned lock means a panic elsewhere and the map is still sound.
    fn pools(&self) -> MutexGuard<'_, HashMap<AccountId, Pool>> {
        self.pools.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl Transport for RelayTransport {
    async fn listen(&self, subscription: Subscription) -> Result<Receiver<Event>> {
        // `since` stops a relay replaying an old backlog the moment the signer
        // starts. A request from last week is not one anybody is waiting on.
        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(subscription.signer_public_key)
            .since(Timestamp::now());

        let (incoming, receiver) = channel(ACCOUNT_QUEUE);
        let mut links = HashMap::with_capacity(subscription.relays.len());

        for relay in &subscription.relays {
            let (outgoing, queue) = channel(RELAY_QUEUE);
            let health = Arc::new(Mutex::new(RelayHealth {
                relay: relay.clone(),
                connected: false,
                last_error: None,
            }));

            let connection = Connection {
                account: subscription.account,
                vault: Arc::clone(&self.vault),
                relay: relay.clone(),
                filter: filter.clone(),
                subscription: SubscriptionId::generate(),
                incoming: incoming.clone(),
                health: Arc::clone(&health),
            };

            links.insert(
                relay.clone(),
                Link {
                    outgoing,
                    health,
                    task: tokio::spawn(connection.run(queue)),
                },
            );
        }

        // Replacing a pool drops the old one, whose Drop aborts its tasks, so
        // re-listening after a relay change does not leave orphans behind.
        self.pools().insert(
            subscription.account,
            Pool {
                relays: subscription.relays,
                links,
            },
        );

        Ok(receiver)
    }

    async fn publish(&self, account: AccountId, event: Event, relays: Vec<RelayUrl>) -> Result<()> {
        let senders: Vec<Sender<Event>> = {
            let pools = self.pools();
            let pool = pools
                .get(&account)
                .ok_or_else(|| SignerError::Transport("account is not listening".to_string()))?;

            // An empty list means the account's own relays. A named list is
            // filtered to relays this account actually has a connection to,
            // rather than opening one on a client's say-so.
            let wanted: Vec<&RelayUrl> = if relays.is_empty() {
                pool.relays.iter().collect()
            } else {
                relays
                    .iter()
                    .filter(|r| pool.links.contains_key(r))
                    .collect()
            };

            wanted
                .into_iter()
                .filter_map(|relay| pool.links.get(relay).map(|link| link.outgoing.clone()))
                .collect()
        };

        if senders.is_empty() {
            return Err(SignerError::Transport(
                "no connected relay to answer on".to_string(),
            ));
        }

        // A disconnected relay stops draining its bounded queue. Never wait
        // for that queue: doing so blocks healthy relays and the account's
        // request loop as well. Success means queued, not acknowledged.
        let mut delivered = false;
        for sender in senders {
            if sender.try_send(event.clone()).is_ok() {
                delivered = true;
            }
        }

        if delivered {
            Ok(())
        } else {
            Err(SignerError::Transport(
                "every relay queue refused the response".to_string(),
            ))
        }
    }

    /// Dropping the pool aborts its connection tasks.
    async fn stop(&self, account: AccountId) {
        self.pools().remove(&account);
    }

    async fn health(&self, account: AccountId) -> Vec<RelayHealth> {
        let pools = self.pools();
        let Some(pool) = pools.get(&account) else {
            return Vec::new();
        };

        pool.relays
            .iter()
            .map(|relay| match pool.links.get(relay) {
                Some(link) => link
                    .health
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
                None => RelayHealth {
                    relay: relay.clone(),
                    connected: false,
                    last_error: Some("no connection".to_string()),
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::{EventBuilder, FinalizeEvent};
    use nostr::key::Keys;
    use std::time::Duration;

    #[tokio::test]
    async fn full_relay_queue_does_not_block_healthy_relays_or_later_requests() {
        let transport = RelayTransport::new(Arc::new(Vault::new()));
        let account = AccountId::new(1);
        let dead = RelayUrl::parse("wss://offline.example").unwrap();
        let live = RelayUrl::parse("wss://online.example").unwrap();
        let (dead_sender, _dead_receiver) = channel(RELAY_QUEUE);
        let (live_sender, mut live_receiver) = channel(RELAY_QUEUE);
        let response = EventBuilder::new(Kind::NostrConnect, "test response")
            .finalize(&Keys::generate())
            .unwrap();
        for _ in 0..RELAY_QUEUE {
            dead_sender.try_send(response.clone()).unwrap();
        }
        let link = |relay: &RelayUrl, outgoing| Link {
            outgoing,
            health: Arc::new(Mutex::new(RelayHealth {
                relay: relay.clone(),
                connected: false,
                last_error: None,
            })),
            task: tokio::spawn(std::future::pending()),
        };
        transport.pools().insert(
            account,
            Pool {
                relays: vec![dead.clone(), live.clone()],
                links: HashMap::from([
                    (dead.clone(), link(&dead, dead_sender)),
                    (live.clone(), link(&live, live_sender)),
                ]),
            },
        );
        for _ in 0..2 {
            tokio::time::timeout(
                Duration::from_secs(1),
                transport.publish(account, response.clone(), vec![]),
            )
            .await
            .expect("offline relay must not stall the signer")
            .unwrap();
            assert_eq!(live_receiver.try_recv().unwrap().id, response.id);
        }
        drop(live_receiver);
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            transport.publish(account, response, vec![])
        )
        .await
        .expect("all unavailable queues must fail promptly")
        .is_err());
    }
}
