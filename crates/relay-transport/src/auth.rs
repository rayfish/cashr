//! NIP-42 state for one socket. Dropped on reconnect, including its challenge.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::time::Duration;

use nostr::event::{Event, EventId};
use nostr::filter::Filter;
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use signer_core::{Result, SignerError};
use tokio::time::Instant;

const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING: usize = 16;
const MAX_AUTH_ATTEMPTS: usize = 3;
const MAX_CHALLENGE_BYTES: usize = 4096;

type Messages = Vec<ClientMessage<'static>>;

struct PendingEvent {
    event: Event,
    sent_at: Instant,
    waiting_auth: bool,
    retried: bool,
}

pub(crate) struct RelaySession {
    subscription: SubscriptionId,
    filter: Filter,
    challenge: Option<String>,
    attempted: bool,
    attempts: usize,
    pending_auth: Option<(EventId, Instant)>,
    authenticated: bool,
    retry_subscription: bool,
    subscription_retried: bool,
    events: VecDeque<PendingEvent>,
    /// Authentication state, cleared when authentication succeeds.
    auth_error: Option<String>,
    /// Subscription/publication failures must not be erased by an AUTH ack.
    access_error: Option<String>,
}

impl RelaySession {
    pub fn new(subscription: SubscriptionId, filter: Filter) -> Self {
        Self {
            subscription,
            filter,
            challenge: None,
            attempted: false,
            attempts: 0,
            pending_auth: None,
            authenticated: false,
            retry_subscription: false,
            subscription_retried: false,
            events: VecDeque::new(),
            auth_error: None,
            access_error: None,
        }
    }

    pub fn error(&self) -> Option<String> {
        self.access_error
            .clone()
            .or_else(|| self.auth_error.clone())
    }

    pub fn subscribe(&self) -> ClientMessage<'static> {
        ClientMessage::Req {
            subscription_id: Cow::Owned(self.subscription.clone()),
            filters: vec![Cow::Owned(self.filter.clone())],
        }
    }

    pub fn publish(&mut self, event: Event) -> ClientMessage<'static> {
        // Keep only a bounded, short-lived replay window. Relays need not ACK.
        if self.events.len() == MAX_PENDING {
            self.events.pop_front();
        }
        self.events.push_back(PendingEvent {
            event: event.clone(),
            sent_at: Instant::now(),
            waiting_auth: false,
            retried: false,
        });
        ClientMessage::Event(Cow::Owned(event))
    }

    pub fn receive(&mut self, message: RelayMessage<'_>) -> Messages {
        self.expire_events();
        match message {
            RelayMessage::Auth { challenge } => {
                if challenge.len() > MAX_CHALLENGE_BYTES {
                    self.auth_error = Some("relay authentication challenge is too large".into());
                    return Vec::new();
                }
                if self.challenge.as_deref() != Some(challenge.as_ref()) {
                    self.challenge = Some(challenge.into_owned());
                    self.attempted = false;
                    self.pending_auth = None;
                    self.authenticated = false;
                }
            }
            RelayMessage::Ok {
                event_id,
                status,
                message,
            } => {
                if self.pending_auth.as_ref().map(|(id, _)| *id) == Some(event_id) {
                    self.pending_auth = None;
                    if status {
                        self.authenticated = true;
                        self.auth_error = None;
                        return self.retry();
                    }
                    self.auth_error = Some(format!("relay authentication rejected: {message}"));
                } else if let Some(index) = self.events.iter().position(|p| p.event.id == event_id)
                {
                    if !status
                        && message.starts_with("auth-required:")
                        && !self.events[index].retried
                    {
                        self.events[index].waiting_auth = true;
                        if self.authenticated {
                            return self.retry();
                        }
                        self.waiting_for_auth();
                    } else {
                        self.events.remove(index);
                        if !status {
                            self.access_error = Some(format!("relay rejected response: {message}"));
                        }
                    }
                }
            }
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_ref() == &self.subscription => {
                if message.starts_with("auth-required:") && !self.subscription_retried {
                    self.retry_subscription = true;
                    if self.authenticated {
                        return self.retry();
                    }
                    self.waiting_for_auth();
                } else {
                    self.access_error = Some(format!("relay subscription closed: {message}"));
                }
            }
            _ => {}
        }
        Vec::new()
    }

    /// The caller signs with the account's transport key, only while unlocked.
    /// Tick also resumes a challenge received while locked without reconnecting.
    pub fn tick(&mut self, sign: impl FnOnce(&str) -> Result<Event>) -> Messages {
        self.expire_events();
        if self
            .pending_auth
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() >= AUTH_TIMEOUT)
        {
            self.pending_auth = None;
            self.auth_error = Some("relay authentication timed out".into());
        }
        if self.attempted || self.authenticated {
            return Vec::new();
        }
        let Some(challenge) = self.challenge.as_deref() else {
            return Vec::new();
        };
        if self.attempts >= MAX_AUTH_ATTEMPTS {
            self.auth_error =
                Some("relay sent too many authentication challenges; reconnect to retry".into());
            self.attempted = true;
            return Vec::new();
        }
        match sign(challenge) {
            Ok(event) => {
                self.attempts += 1;
                self.attempted = true;
                self.pending_auth = Some((event.id, Instant::now()));
                self.auth_error = Some("authenticating with relay".into());
                vec![ClientMessage::auth(event)]
            }
            Err(SignerError::Locked) => {
                self.auth_error = Some("unlock Byrgi to authenticate with this relay".into());
                Vec::new()
            }
            Err(error) => {
                self.attempted = true;
                self.auth_error = Some(format!("could not authenticate with relay: {error}"));
                Vec::new()
            }
        }
    }

    fn waiting_for_auth(&mut self) {
        if self.auth_error.is_none() {
            self.auth_error = Some("relay requires authentication; waiting for a challenge".into());
        }
    }

    fn expire_events(&mut self) {
        self.events.retain(|p| p.sent_at.elapsed() < EVENT_TTL);
    }

    fn retry(&mut self) -> Messages {
        let mut messages = Vec::new();
        if self.retry_subscription {
            self.retry_subscription = false;
            self.subscription_retried = true;
            messages.push(self.subscribe());
        }
        for pending in &mut self.events {
            if pending.waiting_auth && !pending.retried {
                pending.waiting_auth = false;
                pending.retried = true;
                messages.push(ClientMessage::Event(Cow::Owned(pending.event.clone())));
            }
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;
    use nostr::nips::nip42::{is_valid_auth_event, ClientAuthentication};
    use nostr::types::RelayUrl;

    use super::*;

    fn session() -> RelaySession {
        RelaySession::new(
            SubscriptionId::new("signer"),
            Filter::new().kind(Kind::NostrConnect),
        )
    }

    fn signed(challenge: &str) -> Result<Event> {
        Ok(ClientAuthentication::new(challenge, relay())
            .finalize(&Keys::generate())
            .expect("signed auth"))
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example.com").unwrap()
    }

    fn ack(event_id: EventId, status: bool, message: &str) -> RelayMessage<'_> {
        RelayMessage::Ok {
            event_id,
            status,
            message: Cow::Borrowed(message),
        }
    }

    fn closed(message: &str) -> RelayMessage<'_> {
        RelayMessage::Closed {
            subscription_id: Cow::Owned(SubscriptionId::new("signer")),
            message: Cow::Borrowed(message),
        }
    }

    fn authenticate(session: &mut RelaySession, challenge: &str) -> Event {
        session.receive(RelayMessage::auth(challenge));
        let messages = session.tick(signed);
        assert_eq!(messages.len(), 1);
        let ClientMessage::Auth(event) = &messages[0] else {
            panic!("expected AUTH")
        };
        assert!(is_valid_auth_event(event, &relay(), challenge));
        event.as_ref().clone()
    }

    fn sample_event() -> Event {
        EventBuilder::new(Kind::NostrConnect, "encrypted response")
            .finalize(&Keys::generate())
            .unwrap()
    }

    #[test]
    fn auth_ack_retries_only_blocked_subscription_and_events() {
        let mut session = session();
        let response = sample_event();
        session.publish(response.clone());
        session.receive(closed("auth-required: sign in"));
        session.receive(ack(response.id, false, "auth-required: sign in"));
        let auth = authenticate(&mut session, "challenge");
        assert!(session.receive(ack(sample_event().id, true, "")).is_empty());
        assert!(!session.authenticated);
        let retry = session.receive(ack(auth.id, true, ""));
        assert_eq!(
            retry,
            vec![session.subscribe(), ClientMessage::event(response.clone())]
        );
        assert!(session.error().is_none());
        assert!(session.receive(ack(response.id, true, "")).is_empty());
        assert!(session.events.is_empty());
        assert!(session.receive(ack(auth.id, true, "")).is_empty());
    }

    #[test]
    fn rejection_arriving_after_auth_ack_is_retried_once() {
        let mut session = session();
        let event = sample_event();
        session.publish(event.clone());
        let auth = authenticate(&mut session, "challenge");
        session.receive(ack(auth.id, true, ""));
        assert_eq!(
            session.receive(closed("auth-required: login")),
            vec![session.subscribe()]
        );
        assert_eq!(
            session.receive(ack(event.id, false, "auth-required: login")),
            vec![ClientMessage::event(event.clone())]
        );
        assert!(session
            .receive(ack(event.id, false, "auth-required: still refused"))
            .is_empty());
        assert!(session
            .receive(closed("auth-required: still refused"))
            .is_empty());
        assert!(session.error().unwrap().contains("refused"));
    }

    #[test]
    fn locked_challenge_resumes_on_unlock_without_signing_while_locked() {
        let mut session = session();
        session.receive(RelayMessage::auth("challenge"));
        assert!(session.tick(|_| Err(SignerError::Locked)).is_empty());
        assert_eq!(session.attempts, 0);
        assert!(session.error().unwrap().contains("unlock Byrgi"));
        let auth = authenticate(&mut session, "challenge");
        session.receive(ack(auth.id, true, ""));
        assert!(session.error().is_none());
        assert!(session.tick(|_| panic!("must not sign again")).is_empty());
    }

    #[test]
    fn rejected_auth_does_not_loop_or_retry_blocked_requests() {
        let mut session = session();
        session.receive(closed("auth-required: login"));
        let auth = authenticate(&mut session, "challenge");
        assert!(session
            .receive(ack(auth.id, false, "restricted: not allowed"))
            .is_empty());
        assert!(session.error().unwrap().contains("not allowed"));
        session.receive(RelayMessage::auth("challenge"));
        assert!(session.tick(|_| panic!("no retry storm")).is_empty());
    }

    #[test]
    fn new_challenge_invalidates_pending_auth_and_reconnect_discards_it() {
        let mut first = session();
        let old = authenticate(&mut first, "old");
        let new = authenticate(&mut first, "new");
        first.receive(ack(old.id, true, ""));
        assert!(!first.authenticated);
        first.receive(ack(new.id, true, ""));
        assert!(first.authenticated);
        let mut reconnected = session();
        reconnected.receive(ack(new.id, true, ""));
        assert!(!reconnected.authenticated);
        assert!(reconnected
            .tick(|_| panic!("no stale challenge"))
            .is_empty());
        authenticate(&mut reconnected, "fresh");
    }

    #[test]
    fn auth_timeout_and_challenge_limits_stop_signing() {
        let mut session = session();
        authenticate(&mut session, "one");
        session.pending_auth.as_mut().unwrap().1 -= AUTH_TIMEOUT;
        assert!(session
            .tick(|_| panic!("timed out auth is not retried"))
            .is_empty());
        assert!(session.error().unwrap().contains("timed out"));
        authenticate(&mut session, "two");
        authenticate(&mut session, "three");
        session.receive(RelayMessage::auth("four"));
        assert!(session.tick(|_| panic!("bounded signing")).is_empty());
        assert!(session.error().unwrap().contains("too many"));
        let mut oversized = RelaySession::new(SubscriptionId::new("oversized"), Filter::new());
        oversized.receive(RelayMessage::auth("x".repeat(MAX_CHALLENGE_BYTES + 1)));
        assert!(oversized.tick(|_| panic!("oversized challenge")).is_empty());
    }

    #[test]
    fn replay_window_is_bounded_and_expired_events_are_not_retried() {
        let mut session = session();
        for _ in 0..MAX_PENDING + 3 {
            session.publish(sample_event());
        }
        assert_eq!(session.events.len(), MAX_PENDING);
        let event = session.events[0].event.clone();
        session.receive(ack(event.id, false, "auth-required: login"));
        session.events[0].sent_at -= EVENT_TTL;
        let auth = authenticate(&mut session, "challenge");
        assert!(session.receive(ack(auth.id, true, "")).is_empty());
    }

    #[test]
    fn auth_success_does_not_hide_access_restrictions() {
        let mut session = session();
        let auth = authenticate(&mut session, "challenge");
        session.receive(closed("restricted: transport key is not authorized"));
        session.receive(ack(auth.id, true, ""));
        assert!(session.error().unwrap().contains("not authorized"));
    }

    #[test]
    fn ordinary_relays_do_not_trigger_auth_or_replays() {
        let mut session = session();
        let event = sample_event();
        assert_eq!(
            session.publish(event.clone()),
            ClientMessage::event(event.clone())
        );
        assert!(session.receive(ack(event.id, true, "")).is_empty());
        assert!(session
            .tick(|_| panic!("relay did not ask for auth"))
            .is_empty());
        assert!(session.error().is_none());
    }
}
