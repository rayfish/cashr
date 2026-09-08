//! Read a public Nostr profile without opening a signing session.

use std::borrow::Cow;
use std::time::Duration;

use futures::{future::join_all, SinkExt, StreamExt};
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::key::PublicKey;
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use nostr::types::{RelayUrl, Timestamp};
use yawc::frame::{Frame, OpCode};
use yawc::WebSocket;

fn usable(event: &Event, author: PublicKey) -> bool {
    event.pubkey == author
        && event.kind == Kind::Metadata
        && event.created_at <= Timestamp::now()
        && event.content.len() <= 65_536
        && event.verify().is_ok()
}

async fn from_relay(relay: &RelayUrl, author: PublicKey) -> Result<Option<Event>, ()> {
    let mut socket = WebSocket::connect(relay.as_str().parse().map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    let subscription = SubscriptionId::generate();
    let request = ClientMessage::Req {
        subscription_id: Cow::Borrowed(&subscription),
        filters: vec![Cow::Owned(
            Filter::new().author(author).kind(Kind::Metadata).limit(1),
        )],
    };
    socket
        .send(Frame::text(request.as_json()))
        .await
        .map_err(|_| ())?;
    let mut latest: Option<Event> = None;
    for _ in 0..128 {
        let frame = socket.next().await.ok_or(())?;
        if frame.opcode() != OpCode::Text {
            continue;
        }
        match RelayMessage::from_json(frame.payload()).map_err(|_| ())? {
            RelayMessage::Event {
                subscription_id,
                event,
            } if subscription_id.as_ref() == &subscription && usable(&event, author) => {
                if latest.as_ref().is_none_or(|old| {
                    event.created_at > old.created_at
                        || (event.created_at == old.created_at && event.id < old.id)
                }) {
                    latest = Some(event.into_owned());
                }
            }
            RelayMessage::EndOfStoredEvents(id) if id.as_ref() == &subscription => {
                return Ok(latest)
            }
            RelayMessage::Closed {
                subscription_id, ..
            } if subscription_id.as_ref() == &subscription => return Err(()),
            _ => {}
        }
    }
    Err(())
}

/// Use the newest verified profile, including a newer profile that removed
/// its address. No authentication, seed, or signed message is sent.
pub async fn fetch_profile(
    author: PublicKey,
    relays: &[RelayUrl],
) -> Result<Option<Event>, &'static str> {
    let results = join_all(relays.iter().take(16).map(|relay| async move {
        tokio::time::timeout(Duration::from_secs(6), from_relay(relay, author))
            .await
            .map_err(|_| ())?
    }))
    .await;
    let mut reached = false;
    let mut profiles = Vec::new();
    for profile in results.into_iter().flatten() {
        reached = true;
        if let Some(profile) = profile {
            profiles.push(profile);
        }
    }
    if !reached {
        return Err("Could not reach profile relays. Try again.");
    }
    profiles.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
    Ok(profiles.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::{EventBuilder, FinalizeEvent};
    use nostr::key::Keys;

    #[tokio::test]
    async fn lookup_reads_profiles_and_preserves_a_newer_address_removal() {
        use hyper::{server::conn::http1, service::service_fn};
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;

        let keys = Keys::generate();
        let author = keys.public_key();
        let old = EventBuilder::new(Kind::Metadata, r#"{"lud16":"old@minibits.cash"}"#)
            .custom_created_at(Timestamp::from_secs(1))
            .finalize(&keys)
            .unwrap();
        let new = EventBuilder::new(Kind::Metadata, "{}")
            .custom_created_at(Timestamp::from_secs(2))
            .finalize(&keys)
            .unwrap();
        let expected = new.id;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
        let (done, received) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let done = std::sync::Arc::new(std::sync::Mutex::new(Some(done)));
            let service = service_fn(move |mut request| {
                let (response, upgrade) = WebSocket::upgrade(&mut request).unwrap();
                let old = old.clone();
                let new = new.clone();
                let done = done.clone();
                tokio::spawn(async move {
                    let mut socket = upgrade.await.unwrap();
                    let first = socket.next().await.unwrap();
                    let ClientMessage::Req {
                        subscription_id,
                        filters,
                    } = ClientMessage::from_json(first.payload()).unwrap()
                    else {
                        panic!("profile lookup must only subscribe");
                    };
                    assert_eq!(
                        filters[0].as_ref(),
                        &Filter::new().author(author).kind(Kind::Metadata).limit(1)
                    );
                    let id = subscription_id.into_owned();
                    // Reverse order: a stale address must not override removal.
                    for event in [new, old] {
                        socket
                            .send(Frame::text(
                                RelayMessage::Event {
                                    subscription_id: Cow::Borrowed(&id),
                                    event: Cow::Owned(event),
                                }
                                .as_json(),
                            ))
                            .await
                            .unwrap();
                    }
                    socket
                        .send(Frame::text(
                            RelayMessage::EndOfStoredEvents(Cow::Owned(id)).as_json(),
                        ))
                        .await
                        .unwrap();
                    done.lock().unwrap().take().unwrap().send(()).unwrap();
                });
                async { Ok::<_, hyper::Error>(response) }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
                .unwrap();
        });
        let profile = fetch_profile(author, &[relay]).await.unwrap().unwrap();
        assert_eq!(profile.id, expected);
        tokio::time::timeout(Duration::from_secs(1), received)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn profile_must_be_signed_by_the_requested_identity() {
        let keys = Keys::generate();
        let mut profile = EventBuilder::new(Kind::Metadata, r#"{"lud16":"alice@minibits.cash"}"#)
            .finalize(&keys)
            .unwrap();
        assert!(usable(&profile, keys.public_key()));
        assert!(!usable(&profile, Keys::generate().public_key()));
        profile.content = r#"{"lud16":"attacker@example.com"}"#.into();
        assert!(!usable(&profile, keys.public_key()));
    }
}
