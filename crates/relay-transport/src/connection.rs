//! One relay connection: connect, subscribe, pump messages, reconnect.
//!
//! A connection belongs to exactly one account. Two accounts on the same relay
//! get two sockets, because sharing one would tie them together for that
//! operator, which is what separate transport keys exist to prevent.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use nostr::types::RelayUrl;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;
use url::Url;
use yawc::frame::{Frame, OpCode};
use yawc::{Options, WebSocket};

use signer_core::transport::RelayHealth;

/// Reconnect backoff. Starts short because most relay drops are brief, and
/// caps low enough that a signer is never unreachable for long.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How long a connection has to survive before it counts as healthy enough to
/// reset the backoff. Without this, a relay that accepts and immediately hangs
/// up gets reconnected in a tight loop.
const STABLE_AFTER: Duration = Duration::from_secs(30);

pub(crate) struct Connection {
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
        let socket = WebSocket::connect(url)
            .with_options(Options::default().with_balanced_compression())
            .await
            .map_err(|e| e.to_string())?;

        let (mut sink, mut stream) = socket.into_streaming().split();
        self.set_health(true, None);
        tracing::debug!(relay = %self.relay, "connected");

        let request = ClientMessage::Req {
            subscription_id: Cow::Borrowed(&self.subscription),
            filters: vec![Cow::Borrowed(&self.filter)],
        };
        sink.send(Frame::text(request.as_json()))
            .await
            .map_err(|e| e.to_string())?;

        loop {
            tokio::select! {
                frame = stream.next() => {
                    // yawc reports a read error as end of stream, so both mean
                    // the same thing here: reconnect.
                    let Some(frame) = frame else { return Ok(()) };
                    match frame.opcode() {
                        OpCode::Text => self.receive(frame.payload()),
                        OpCode::Close => return Ok(()),
                        // Pings are answered by yawc itself.
                        _ => {}
                    }
                }
                event = outgoing.recv() => {
                    let Some(event) = event else { return Ok(()) };
                    let message = ClientMessage::Event(Cow::Owned(event));
                    sink.send(Frame::text(message.as_json()))
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }

    fn receive(&self, payload: &[u8]) {
        let Ok(message) = RelayMessage::from_json(payload) else {
            tracing::debug!(relay = %self.relay, "ignoring a message that is not valid nostr");
            return;
        };

        match message {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                if subscription_id.as_ref() != &self.subscription {
                    return;
                }
                if self.incoming.try_send(event.into_owned()).is_err() {
                    tracing::warn!(relay = %self.relay, "dropping an event: the queue is full");
                }
            }
            RelayMessage::Closed { message, .. } => {
                tracing::debug!(relay = %self.relay, "subscription closed by the relay: {message}");
            }
            RelayMessage::Notice(notice) => {
                tracing::debug!(relay = %self.relay, "notice: {notice}");
            }
            RelayMessage::Ok {
                status: false,
                message,
                ..
            } => {
                tracing::debug!(relay = %self.relay, "relay rejected an event: {message}");
            }
            _ => {}
        }
    }

    fn set_health(&self, connected: bool, error: Option<String>) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health.connected = connected;
        health.last_error = error;
    }
}
