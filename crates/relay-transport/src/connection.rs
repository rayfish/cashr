//! One relay connection: connect, subscribe, pump messages, reconnect.
//!
//! A connection belongs to exactly one account. Two accounts on the same relay
//! get two sockets, because sharing one would tie them together for that
//! operator, which is what separate transport keys exist to prevent.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::message::{RelayMessage, SubscriptionId};
use nostr::types::RelayUrl;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{timeout, Instant};
use url::Url;
use yawc::frame::{Frame, OpCode};
use yawc::{Options, WebSocket};

use signer_core::account::AccountId;
use signer_core::transport::RelayHealth;
use signer_core::vault::Vault;

use crate::auth::RelaySession;

/// Reconnect backoff. Starts short because most relay drops are brief, and
/// caps low enough that a signer is never unreachable for long.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How long to wait for a relay to accept a connection.
///
/// Without it a relay that takes the socket and never finishes the handshake
/// leaves the connection red with no error against it forever: the reconnect
/// loop cannot come round, because the connect never returns.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a connection has to survive before it counts as healthy enough to
/// reset the backoff. Without this, a relay that accepts and immediately hangs
/// up gets reconnected in a tight loop.
const STABLE_AFTER: Duration = Duration::from_secs(30);

pub(crate) struct Connection {
    pub account: AccountId,
    pub vault: Arc<Vault>,
    pub relay: RelayUrl,
    pub filter: Filter,
    pub subscription: SubscriptionId,
    /// Events for the session to handle.
    pub incoming: Sender<Event>,
    pub health: Arc<Mutex<RelayHealth>>,
}

impl Connection {
    /// Run until the task is dropped. `outgoing` carries events to publish;
    /// anything queued while disconnected waits for the next connection rather
    /// than being thrown away.
    pub(crate) async fn run(self, mut outgoing: Receiver<Event>) {
        let mut backoff = BACKOFF_START;

        loop {
            let started = Instant::now();
            let outcome = self.session(&mut outgoing).await;

            match outcome {
                Ok(()) => {
                    tracing::debug!(relay = %self.relay, "relay closed the connection");
                    self.set_health(false, None);
                }
                Err(error) => {
                    tracing::debug!(relay = %self.relay, "relay connection failed: {error}");
                    self.set_health(false, Some(error));
                }
            }

            if started.elapsed() >= STABLE_AFTER {
                backoff = BACKOFF_START;
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn session(&self, outgoing: &mut Receiver<Event>) -> Result<(), String> {
        let url: Url = self
            .relay
            .as_str()
            .parse()
            .map_err(|e| format!("bad relay url: {e}"))?;

        // permessage-deflate is worth having here: relay traffic is repetitive
        // JSON, and the handshake simply skips it if the relay says no.
        let connect =
            WebSocket::connect(url).with_options(Options::default().with_balanced_compression());
        let socket = timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| "timed out connecting".to_string())?
            .map_err(|e| e.to_string())?;

        let (mut sink, mut stream) = socket.into_streaming().split();
        self.set_health(true, None);
        tracing::debug!(relay = %self.relay, "connected");

        let mut session = RelaySession::new(self.subscription.clone(), self.filter.clone());
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        sink.send(Frame::text(session.subscribe().as_json()))
            .await
            .map_err(|e| e.to_string())?;

        loop {
            let mut messages = Vec::new();
            tokio::select! {
                frame = stream.next() => {
                    // yawc reports a read error as end of stream, so both mean
                    // the same thing here: reconnect.
                    let Some(frame) = frame else { return Ok(()) };
                    match frame.opcode() {
                        OpCode::Text => {
                            if let Ok(message) = RelayMessage::from_json(frame.payload()) {
                                if let RelayMessage::Event { subscription_id, event } = message {
                                    if subscription_id.as_ref() == &self.subscription
                                        && self.incoming.try_send(event.into_owned()).is_err()
                                    {
                                        tracing::warn!(relay = %self.relay, "dropping an event: the queue is full");
                                    }
                                } else {
                                    messages.extend(session.receive(message));
                                }
                            }
                        },
                        OpCode::Close => return Ok(()),
                        // Pings are answered by yawc itself.
                        _ => {}
                    }
                }
                event = outgoing.recv() => {
                    let Some(event) = event else { return Ok(()) };
                    messages.push(session.publish(event));
                }
                _ = ticker.tick() => {}
            }
            messages.extend(session.tick(|challenge| {
                self.vault
                    .sign_relay_auth(self.account, &self.relay, challenge)
            }));
            let error = session.error();
            self.set_health(error.is_none(), error);
            for message in messages {
                sink.send(Frame::text(message.as_json()))
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    fn set_health(&self, connected: bool, error: Option<String>) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health.connected = connected;
        health.last_error = error;
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;
    use nostr::message::ClientMessage;
    use nostr::nips::nip42::is_valid_auth_event;
    use signer_core::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore, KeyStoreError};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::channel;

    use super::*;

    struct MemoryKeys {
        identity: Keys,
        transport: Keys,
    }

    #[async_trait]
    impl KeyStore for MemoryKeys {
        async fn load(&self, handle: KeyHandle) -> Result<Keys, KeyStoreError> {
            Ok(match handle.role {
                KeyRole::Identity => self.identity.clone(),
                KeyRole::Transport => self.transport.clone(),
            })
        }
        async fn store(&self, _: AccountId, _: &AccountKeys) -> Result<(), KeyStoreError> {
            unreachable!("test only loads disposable keys")
        }
        async fn delete(&self, _: AccountId) -> Result<(), KeyStoreError> {
            unreachable!("test only loads disposable keys")
        }
    }

    #[tokio::test]
    async fn local_relay_authenticates_after_unlock_and_retries_blocked_traffic() {
        // Bound the entire exchange so a protocol regression fails, never hangs.
        timeout(Duration::from_secs(8), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay =
                RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
            let keys = MemoryKeys {
                identity: Keys::generate(),
                transport: Keys::generate(),
            };
            let expected_key = keys.transport.public_key();
            let account = AccountId::new(1);
            let vault = Arc::new(Vault::new());
            let (unlock_ready, mut unlock_wait) = channel(1);
            let (finished, mut finish_wait) = channel(1);
            let (outgoing, mut queue) = channel(1);
            let response = EventBuilder::new(Kind::NostrConnect, "encrypted response")
                .finalize(&Keys::generate())
                .unwrap();
            let server_relay = relay.clone();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let service = service_fn(move |mut request| {
                    let (http_response, upgrade) = WebSocket::upgrade(&mut request).unwrap();
                    let relay = server_relay.clone();
                    let unlock_ready = unlock_ready.clone();
                    let finished = finished.clone();
                    let outgoing = outgoing.clone();
                    let response = response.clone();
                    tokio::spawn(async move {
                        let mut socket = upgrade.await.unwrap().into_streaming();
                        let first = socket.next().await.unwrap();
                        let ClientMessage::Req {
                            subscription_id, ..
                        } = ClientMessage::from_json(first.payload()).unwrap()
                        else {
                            panic!("expected initial subscription");
                        };
                        let subscription_id = subscription_id.into_owned();
                        socket
                            .send(Frame::text(
                                RelayMessage::auth("socket-challenge").as_json(),
                            ))
                            .await
                            .unwrap();
                        socket
                            .send(Frame::text(
                                RelayMessage::Closed {
                                    subscription_id: std::borrow::Cow::Owned(
                                        subscription_id.clone(),
                                    ),
                                    message: std::borrow::Cow::Borrowed(
                                        "auth-required: authenticate",
                                    ),
                                }
                                .as_json(),
                            ))
                            .await
                            .unwrap();
                        assert!(
                            timeout(Duration::from_millis(100), socket.next())
                                .await
                                .is_err(),
                            "locked vault must not sign"
                        );
                        unlock_ready.send(()).await.unwrap();
                        let auth = socket.next().await.unwrap();
                        let ClientMessage::Auth(auth) =
                            ClientMessage::from_json(auth.payload()).unwrap()
                        else {
                            panic!("expected AUTH")
                        };
                        assert_eq!(auth.pubkey, expected_key);
                        assert!(is_valid_auth_event(&auth, &relay, "socket-challenge"));
                        socket
                            .send(Frame::text(
                                RelayMessage::Ok {
                                    event_id: auth.id,
                                    status: true,
                                    message: std::borrow::Cow::Borrowed(""),
                                }
                                .as_json(),
                            ))
                            .await
                            .unwrap();
                        let retry = socket.next().await.unwrap();
                        let ClientMessage::Req {
                            subscription_id: retried_id,
                            ..
                        } = ClientMessage::from_json(retry.payload()).unwrap()
                        else {
                            panic!("expected subscription retry")
                        };
                        assert_eq!(retried_id.as_ref(), &subscription_id);
                        outgoing.send(response.clone()).await.unwrap();
                        let sent = socket.next().await.unwrap();
                        assert_eq!(
                            ClientMessage::from_json(sent.payload()).unwrap(),
                            ClientMessage::event(response.clone())
                        );
                        socket
                            .send(Frame::text(
                                RelayMessage::Ok {
                                    event_id: response.id,
                                    status: false,
                                    message: std::borrow::Cow::Borrowed(
                                        "auth-required: retry after auth",
                                    ),
                                }
                                .as_json(),
                            ))
                            .await
                            .unwrap();
                        let retried = socket.next().await.unwrap();
                        assert_eq!(
                            ClientMessage::from_json(retried.payload()).unwrap(),
                            ClientMessage::event(response.clone())
                        );
                        socket
                            .send(Frame::text(
                                RelayMessage::Ok {
                                    event_id: response.id,
                                    status: true,
                                    message: std::borrow::Cow::Borrowed(""),
                                }
                                .as_json(),
                            ))
                            .await
                            .unwrap();
                        finished.send(()).await.unwrap();
                    });
                    async { Ok::<_, hyper::Error>(http_response) }
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .with_upgrades()
                    .await
                    .unwrap();
            });
            let health = Arc::new(Mutex::new(RelayHealth {
                relay: relay.clone(),
                connected: false,
                last_error: None,
            }));
            let (incoming, _receiver) = channel(1);
            let connection = Connection {
                account,
                vault: Arc::clone(&vault),
                relay,
                filter: Filter::new().kind(Kind::NostrConnect),
                subscription: SubscriptionId::new("test"),
                incoming,
                health: Arc::clone(&health),
            };
            let client = tokio::spawn(async move { connection.session(&mut queue).await });
            unlock_wait.recv().await.unwrap();
            assert!(health
                .lock()
                .unwrap()
                .last_error
                .as_ref()
                .unwrap()
                .contains("unlock Byrgi"));
            vault.unlock(&keys, &[account]).await.unwrap();
            finish_wait.recv().await.unwrap();
            assert!(health.lock().unwrap().last_error.is_none());
            client.abort();
            server.abort();
        })
        .await
        .expect("local relay exchange completed");
    }
}
