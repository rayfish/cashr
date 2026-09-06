//! The account loop, driven by a fake transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nostr::event::{Event, FinalizeEvent};
use nostr::key::{Keys, SecretKey};
use nostr::nips::nip44::Nip44;
use nostr::nips::nip46::{
    NostrConnectEventBuilder, NostrConnectMessage, NostrConnectRequest, NostrConnectUri,
};
use nostr::types::RelayUrl;
use signer_core::account::Account;
use signer_core::approval::{ApprovalDecision, ApprovalRequest, Approver, NullNotifier};
use signer_core::keystore::{KeyHandle, KeyRole, KeyStore, KeyStoreError};
use signer_core::pairing::mint_bunker_uri;
use signer_core::runner::Runner;
use signer_core::session::{Session, SessionConfig, SessionParts};
use signer_core::storage::{NewAccount, Storage};
use signer_core::transport::{RelayHealth, Subscription, Transport};
use signer_core::vault::Vault;
use signer_core::{account::AccountId, Result};
use tokio::sync::mpsc::{channel, Receiver, Sender};

struct MemoryKeyStore(Mutex<HashMap<String, Keys>>);

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn load(&self, handle: KeyHandle) -> std::result::Result<Keys, KeyStoreError> {
        self.0
            .lock()
            .expect("test lock is uncontended")
            .get(&handle.to_string())
            .cloned()
            .ok_or(KeyStoreError::NotFound(handle))
    }

    async fn store(
        &self,
        handle: KeyHandle,
        secret: SecretKey,
    ) -> std::result::Result<(), KeyStoreError> {
        self.0
            .lock()
            .expect("test lock is uncontended")
            .insert(handle.to_string(), Keys::new(secret));
        Ok(())
    }

    async fn delete(&self, _handle: KeyHandle) -> std::result::Result<(), KeyStoreError> {
        Ok(())
    }
}

struct AlwaysAllow;

#[async_trait]
impl Approver for AlwaysAllow {
    async fn request(&self, _request: ApprovalRequest) -> Result<ApprovalDecision> {
        Ok(ApprovalDecision::allow_once())
    }
}

/// Feeds events in and collects what the runner publishes back.
struct FakeTransport {
    incoming: Mutex<Option<Receiver<Event>>>,
    published: Arc<Mutex<Vec<Event>>>,
}

impl FakeTransport {
    fn new() -> (Arc<Self>, Sender<Event>, Arc<Mutex<Vec<Event>>>) {
        let (sender, receiver) = channel(16);
        let published = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(Self {
            incoming: Mutex::new(Some(receiver)),
            published: Arc::clone(&published),
        });
        (transport, sender, published)
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn listen(&self, _subscription: Subscription) -> Result<Receiver<Event>> {
        Ok(self
            .incoming
            .lock()
            .expect("test lock is uncontended")
            .take()
            .expect("listen is called once per test"))
    }

    async fn publish(&self, event: Event, _relays: Vec<RelayUrl>) -> Result<()> {
        self.published
            .lock()
            .expect("test lock is uncontended")
            .push(event);
        Ok(())
    }

    async fn health(&self, _account: AccountId) -> Vec<RelayHealth> {
        Vec::new()
    }
}

struct Fixture {
    runner: Runner,
    account: Account,
    client: Keys,
    storage: Arc<Storage>,
}

fn build() -> (Fixture, Sender<Event>, Arc<Mutex<Vec<Event>>>) {
    let storage = Arc::new(Storage::in_memory().expect("in-memory database opens"));
    let identity = Keys::generate();
    let transport_keys = Keys::generate();

    let account = storage
        .insert_account(NewAccount {
            identity_public_key: identity.public_key(),
            signer_public_key: transport_keys.public_key(),
            label: "test".to_string(),
            relays: vec![RelayUrl::parse("wss://relay.example").expect("relay url parses")],
            is_default: true,
        })
        .expect("account inserts");

    let keystore = Arc::new(MemoryKeyStore(Mutex::new(HashMap::new())));
    keystore.0.lock().expect("test lock is uncontended").insert(
        KeyHandle::new(account.id, KeyRole::Identity).to_string(),
        identity,
    );
    keystore.0.lock().expect("test lock is uncontended").insert(
        KeyHandle::new(account.id, KeyRole::Transport).to_string(),
        transport_keys,
    );

    let session = Arc::new(Session::new(SessionParts {
        storage: Arc::clone(&storage),
        vault: Arc::new(Vault::new()),
        keystore,
        approver: Arc::new(AlwaysAllow),
        notifier: Arc::new(NullNotifier),
        config: SessionConfig::default(),
    }));

    let (transport, sender, published) = FakeTransport::new();

    (
        Fixture {
            runner: Runner::new(session, transport),
            account,
            client: Keys::generate(),
            storage,
        },
        sender,
        published,
    )
}

impl Fixture {
    fn envelope(&self, id: &str, request: &NostrConnectRequest) -> Event {
        NostrConnectEventBuilder::new(
            self.account.signer_public_key,
            NostrConnectMessage::Request {
                id: id.to_string(),
                method: request.method(),
                params: request.params(),
            },
        )
        .finalize(&self.client)
        .expect("client seals its request")
    }

    fn connect_request(&self) -> NostrConnectRequest {
        let uri = mint_bunker_uri(&self.storage, &self.account, Duration::from_secs(300))
            .expect("bunker uri mints");
        let NostrConnectUri::Bunker { secret, .. } = uri else {
            panic!("minted the wrong uri kind");
        };
        NostrConnectRequest::Connect {
            remote_signer_public_key: self.account.signer_public_key,
            secret: Some(secret.expect("minted uri carries a secret")),
        }
    }

    fn opens(&self, event: &Event) -> NostrConnectMessage {
        let plaintext = self
            .client
            .nip44_decrypt(&self.account.signer_public_key, &event.content)
            .expect("client opens the response");
        serde_json::from_str(&plaintext).expect("response parses")
    }
}

async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn the_account_loop_answers_requests_over_the_transport() {
    let (fixture, incoming, published) = build();
    fixture
        .runner
        .session()
        .unlock(&[fixture.account.id])
        .await
        .expect("vault unlocks");

    let handle = fixture
        .runner
        .start(fixture.account.clone())
        .await
        .expect("loop starts");

    let connect = fixture.connect_request();
    incoming
        .send(fixture.envelope("1", &connect))
        .await
        .expect("event is queued");
    incoming
        .send(fixture.envelope("2", &NostrConnectRequest::GetPublicKey))
        .await
        .expect("event is queued");

    settle().await;
    handle.abort();

    let sent = published.lock().expect("test lock is uncontended").clone();
    assert_eq!(sent.len(), 2);

    let ids: Vec<String> = sent
        .iter()
        .map(|event| match fixture.opens(event) {
            NostrConnectMessage::Response { id, error, .. } => {
                assert!(error.is_none(), "unexpected error: {error:?}");
                id
            }
            NostrConnectMessage::Request { .. } => panic!("signer answered with a request"),
        })
        .collect();
    assert_eq!(ids, vec!["1".to_string(), "2".to_string()]);
}

#[tokio::test]
async fn requests_that_arrive_locked_are_answered_after_unlocking() {
    let (fixture, incoming, published) = build();

    let handle = fixture
        .runner
        .start(fixture.account.clone())
        .await
        .expect("loop starts");

    let connect = fixture.connect_request();
    incoming
        .send(fixture.envelope("1", &connect))
        .await
        .expect("event is queued");

    settle().await;
    assert!(
        published
            .lock()
            .expect("test lock is uncontended")
            .is_empty(),
        "a locked signer answers nothing"
    );

    fixture
        .runner
        .session()
        .unlock(&[fixture.account.id])
        .await
        .expect("vault unlocks");
    fixture
        .runner
        .replay_deferred(std::slice::from_ref(&fixture.account))
        .await
        .expect("deferred requests replay");

    settle().await;
    handle.abort();

    assert_eq!(published.lock().expect("test lock is uncontended").len(), 1);
}
