//! End-to-end NIP-46 behaviour, driven without a relay.
//!
//! Each test plays the client: it builds a real kind 24133 event, hands it to
//! the session, and opens the response the same way a client would.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nostr::event::{Event, FinalizeEvent, Kind, UnsignedEvent};
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::nips::nip44::Nip44;
use nostr::nips::nip46::{
    NostrConnectEventBuilder, NostrConnectMessage, NostrConnectMethod, NostrConnectRequest,
    NostrConnectUri, ResponseResult,
};
use nostr::types::{RelayUrl, Timestamp};
use signer_core::account::Account;
use signer_core::approval::{ApprovalDecision, ApprovalRequest, Approver, NullNotifier};
use signer_core::error::SignerError;
use signer_core::keystore::{KeyHandle, KeyRole, KeyStore, KeyStoreError};
use signer_core::pairing::{accept_client_uri, mint_bunker_uri};
use signer_core::policy::{Decision, Outcome, Scope};
use signer_core::session::{Session, SessionConfig, SessionParts};
use signer_core::storage::{NewAccount, Storage};
use signer_core::vault::Vault;
use signer_core::Result;

// ---------------------------------------------------------------- test doubles

struct MemoryKeyStore {
    keys: Mutex<HashMap<String, Keys>>,
}

impl MemoryKeyStore {
    fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    fn put(&self, handle: KeyHandle, keys: Keys) {
        self.keys
            .lock()
            .expect("test lock is uncontended")
            .insert(handle.to_string(), keys);
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn load(&self, handle: KeyHandle) -> std::result::Result<Keys, KeyStoreError> {
        self.keys
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
        self.put(handle, Keys::new(secret));
        Ok(())
    }

    async fn delete(&self, handle: KeyHandle) -> std::result::Result<(), KeyStoreError> {
        self.keys
            .lock()
            .expect("test lock is uncontended")
            .remove(&handle.to_string());
        Ok(())
    }
}

/// Answers every prompt the same way, and counts how often it was asked.
struct ScriptedApprover {
    answer: Mutex<ApprovalDecision>,
    calls: AtomicUsize,
    /// Simulates the user never answering.
    stall: bool,
}

impl ScriptedApprover {
    fn new(answer: ApprovalDecision) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
            stall: false,
        })
    }

    fn stalling() -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(ApprovalDecision::deny()),
            calls: AtomicUsize::new(0),
            stall: true,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Approver for ScriptedApprover {
    async fn request(&self, _request: ApprovalRequest) -> Result<ApprovalDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stall {
            // Longer than any test's request timeout.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        Ok(*self.answer.lock().expect("test lock is uncontended"))
    }
}

// ------------------------------------------------------------------- fixtures

/// One signer, one account, and the client keys used to talk to it.
struct Harness {
    session: Session,
    storage: Arc<Storage>,
    account: Account,
    approver: Arc<ScriptedApprover>,
    client: Keys,
}

impl Harness {
    async fn new(approver: Arc<ScriptedApprover>) -> Self {
        Self::with_config(approver, SessionConfig::default()).await
    }

    async fn with_config(approver: Arc<ScriptedApprover>, config: SessionConfig) -> Self {
        let storage = Arc::new(Storage::in_memory().expect("in-memory database opens"));
        let identity = Keys::generate();
        let transport = Keys::generate();

        let account = storage
            .insert_account(NewAccount {
                identity_public_key: identity.public_key(),
                signer_public_key: transport.public_key(),
                label: "test".to_string(),
                relays: vec![RelayUrl::parse("wss://relay.example").expect("relay url parses")],
                is_default: true,
            })
            .expect("account inserts");

        let keystore = Arc::new(MemoryKeyStore::new());
        keystore.put(KeyHandle::new(account.id, KeyRole::Identity), identity);
        keystore.put(KeyHandle::new(account.id, KeyRole::Transport), transport);

        let session = Session::new(SessionParts {
            storage: Arc::clone(&storage),
            vault: Arc::new(Vault::new()),
            keystore,
            approver: approver.clone(),
            notifier: Arc::new(NullNotifier),
            config,
        });

        Self {
            session,
            storage,
            account,
            approver,
            client: Keys::generate(),
        }
    }

    async fn unlock(&self) {
        self.session
            .unlock(&[self.account.id])
            .await
            .expect("vault unlocks");
    }

    /// Build the event a client would publish for `request`.
    fn envelope(&self, id: &str, request: &NostrConnectRequest) -> Event {
        let message = NostrConnectMessage::Request {
            id: id.to_string(),
            method: request.method(),
            params: request.params(),
        };
        NostrConnectEventBuilder::new(self.account.signer_public_key, message)
            .finalize(&self.client)
            .expect("client seals its request")
    }

    /// Send a request and read the response the way a client would.
    async fn call(&self, id: &str, request: &NostrConnectRequest) -> Option<ClientResponse> {
        let event = self.envelope(id, request);
        let response = self.session.handle(&self.account, event).await?;
        Some(self.open(&response, request.method()))
    }

    fn open(&self, event: &Event, method: NostrConnectMethod) -> ClientResponse {
        let plaintext = self
            .client
            .nip44_decrypt(&self.account.signer_public_key, &event.content)
            .expect("client opens the response");
        let message: NostrConnectMessage =
            serde_json::from_str(&plaintext).expect("response parses");

        match message {
            NostrConnectMessage::Response { id, result, error } => match error {
                Some(error) => ClientResponse::Error { id, error },
                None => {
                    let raw = result.expect("a response has a result or an error");
                    let parsed = nostr::nips::nip46::ResponseResult::parse(method, raw)
                        .expect("result parses for its method");
                    ClientResponse::Ok { id, result: parsed }
                }
            },
            NostrConnectMessage::Request { .. } => panic!("signer answered with a request"),
        }
    }

    /// Pair the client the way the `bunker://` flow does.
    async fn pair(&self) {
        let uri = mint_bunker_uri(&self.storage, &self.account, Duration::from_secs(300))
            .expect("bunker uri mints");
        let secret = match &uri {
            NostrConnectUri::Bunker { secret, .. } => {
                secret.clone().expect("minted uri carries a secret")
            }
            NostrConnectUri::Client { .. } => panic!("minted the wrong uri kind"),
        };

        let response = self
            .call(
                "connect",
                &NostrConnectRequest::Connect {
                    remote_signer_public_key: self.account.signer_public_key,
                    secret: Some(secret),
                },
            )
            .await
            .expect("connect is answered");
        assert!(matches!(
            response,
            ClientResponse::Ok {
                result: ResponseResult::Ack,
                ..
            }
        ));
    }
}

#[derive(Debug)]
enum ClientResponse {
    Ok { id: String, result: ResponseResult },
    Error { id: String, error: String },
}

impl ClientResponse {
    fn id(&self) -> &str {
        match self {
            Self::Ok { id, .. } | Self::Error { id, .. } => id,
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::Error { error, .. } => Some(error),
            Self::Ok { .. } => None,
        }
    }
}

fn note(author: PublicKey) -> UnsignedEvent {
    UnsignedEvent {
        id: None,
        pubkey: author,
        created_at: Timestamp::now(),
        kind: Kind::TextNote,
        tags: Default::default(),
        content: "hello".to_string(),
    }
}

// ---------------------------------------------------------------------- tests

#[tokio::test]
async fn a_locked_signer_answers_nothing_and_keeps_the_request() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;

    let event = harness.envelope("1", &NostrConnectRequest::GetPublicKey);
    assert!(harness
        .session
        .handle(&harness.account, event)
        .await
        .is_none());

    let deferred = harness.session.take_deferred().await;
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].0, harness.account.id);
}

#[tokio::test]
async fn an_unpaired_client_is_refused_without_a_prompt() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    let response = harness
        .call("1", &NostrConnectRequest::GetPublicKey)
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("unauthorized"));
    assert_eq!(harness.approver.calls(), 0);
}

#[tokio::test]
async fn connect_needs_a_live_pairing_secret() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::Connect {
                remote_signer_public_key: harness.account.signer_public_key,
                secret: Some("not-a-real-secret".to_string()),
            },
        )
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("unauthorized"));
    assert!(harness
        .storage
        .clients(harness.account.id)
        .expect("clients load")
        .is_empty());
}

#[tokio::test]
async fn a_bunker_pairing_registers_the_client() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let clients = harness
        .storage
        .clients(harness.account.id)
        .expect("clients load");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].public_key, harness.client.public_key());
}

#[tokio::test]
async fn a_pairing_secret_cannot_be_reused() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    let uri = mint_bunker_uri(&harness.storage, &harness.account, Duration::from_secs(300))
        .expect("bunker uri mints");
    let NostrConnectUri::Bunker { secret, .. } = &uri else {
        panic!("minted the wrong uri kind");
    };
    let secret = secret.clone().expect("minted uri carries a secret");

    let request = NostrConnectRequest::Connect {
        remote_signer_public_key: harness.account.signer_public_key,
        secret: Some(secret),
    };

    assert!(harness.call("1", &request).await.unwrap().error().is_none());
    assert_eq!(
        harness.call("2", &request).await.unwrap().error(),
        Some("unauthorized")
    );
}

#[tokio::test]
async fn a_nostrconnect_pairing_echoes_the_clients_secret() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    let uri = NostrConnectUri::client(
        harness.client.public_key(),
        [RelayUrl::parse("wss://relay.example").expect("relay url parses")],
        "Test App",
    );
    let NostrConnectUri::Client { secret, .. } = &uri else {
        panic!("built the wrong uri kind");
    };
    let secret = secret.clone();

    accept_client_uri(
        &harness.storage,
        &harness.account,
        &uri,
        Duration::from_secs(300),
    )
    .expect("uri is accepted");

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::Connect {
                remote_signer_public_key: harness.account.signer_public_key,
                secret: Some(secret.clone()),
            },
        )
        .await
        .expect("connect is answered");

    match response {
        ClientResponse::Ok {
            result: ResponseResult::ConnectSecret(echoed),
            ..
        } => assert_eq!(echoed, secret),
        other => panic!("expected the secret echoed back, got {other:?}"),
    }
}

#[tokio::test]
async fn a_nostrconnect_secret_only_works_for_the_app_that_minted_it() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    let someone_else = Keys::generate();
    let uri = NostrConnectUri::client(
        someone_else.public_key(),
        [RelayUrl::parse("wss://relay.example").expect("relay url parses")],
        "Other App",
    );
    let NostrConnectUri::Client { secret, .. } = &uri else {
        panic!("built the wrong uri kind");
    };
    let secret = secret.clone();

    accept_client_uri(
        &harness.storage,
        &harness.account,
        &uri,
        Duration::from_secs(300),
    )
    .expect("uri is accepted");

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::Connect {
                remote_signer_public_key: harness.account.signer_public_key,
                secret: Some(secret),
            },
        )
        .await
        .expect("connect is answered");

    assert_eq!(response.error(), Some("unauthorized"));
}

#[tokio::test]
async fn allow_always_stores_a_rule_and_stops_the_prompting() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_always())).await;
    harness.unlock().await;
    harness.pair().await;

    let request = NostrConnectRequest::SignEvent(note(harness.account.identity_public_key));

    let first = harness
        .call("1", &request)
        .await
        .expect("request is answered");
    assert!(first.error().is_none());
    assert_eq!(harness.approver.calls(), 1);

    let second = harness
        .call("2", &request)
        .await
        .expect("request is answered");
    assert!(second.error().is_none());
    assert_eq!(harness.approver.calls(), 1, "the stored rule answered it");

    let client = harness
        .storage
        .clients(harness.account.id)
        .expect("clients load")[0]
        .clone();
    assert_eq!(
        harness
            .storage
            .policy_set(client.id)
            .expect("policy loads")
            .evaluate(Scope::sign_event(Kind::TextNote)),
        Outcome::Allow
    );
}

#[tokio::test]
async fn allow_once_leaves_no_rule_behind() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let request = NostrConnectRequest::SignEvent(note(harness.account.identity_public_key));
    harness
        .call("1", &request)
        .await
        .expect("request is answered");
    harness
        .call("2", &request)
        .await
        .expect("request is answered");

    assert_eq!(harness.approver.calls(), 2);
}

#[tokio::test]
async fn a_denied_request_says_so_and_signs_nothing() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::deny())).await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("denied"));
}

#[tokio::test]
async fn a_kind_rule_does_not_cover_a_different_kind() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_always())).await;
    harness.unlock().await;
    harness.pair().await;

    let author = harness.account.identity_public_key;
    harness
        .call("1", &NostrConnectRequest::SignEvent(note(author)))
        .await
        .expect("request is answered");
    assert_eq!(harness.approver.calls(), 1);

    let mut dm = note(author);
    dm.kind = Kind::EncryptedDirectMessage;
    harness
        .call("2", &NostrConnectRequest::SignEvent(dm))
        .await
        .expect("request is answered");

    assert_eq!(
        harness.approver.calls(),
        2,
        "approving notes must not approve direct messages"
    );
}

#[tokio::test]
async fn a_redelivered_request_is_answered_from_the_first_answer() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let request = NostrConnectRequest::SignEvent(note(harness.account.identity_public_key));
    let first = harness
        .call("dup", &request)
        .await
        .expect("request is answered");
    let second = harness
        .call("dup", &request)
        .await
        .expect("request is answered");

    assert_eq!(first.id(), second.id());
    assert_eq!(
        harness.approver.calls(),
        1,
        "a redelivery must not re-prompt"
    );
}

#[tokio::test]
async fn ping_is_answered_without_asking_the_user() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::deny())).await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call("1", &NostrConnectRequest::Ping)
        .await
        .expect("request is answered");

    assert!(matches!(
        response,
        ClientResponse::Ok {
            result: ResponseResult::Pong,
            ..
        }
    ));
    assert_eq!(harness.approver.calls(), 0);
}

#[tokio::test]
async fn a_revoked_client_is_refused() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let client = harness
        .storage
        .clients(harness.account.id)
        .expect("clients load")[0]
        .clone();
    harness
        .storage
        .revoke_client(client.id)
        .expect("client revokes");

    let response = harness
        .call("1", &NostrConnectRequest::GetPublicKey)
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("unauthorized"));
    assert_eq!(harness.approver.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_prompt_times_out_instead_of_hanging_the_client() {
    let harness = Harness::with_config(
        ScriptedApprover::stalling(),
        SessionConfig {
            request_timeout: Duration::from_secs(5),
            ..SessionConfig::default()
        },
    )
    .await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("timed out"));
}

#[tokio::test]
async fn get_public_key_returns_the_identity_not_the_transport_key() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call("1", &NostrConnectRequest::GetPublicKey)
        .await
        .expect("request is answered");

    match response {
        ClientResponse::Ok {
            result: ResponseResult::GetPublicKey(public_key),
            ..
        } => {
            assert_eq!(public_key, harness.account.identity_public_key);
            assert_ne!(public_key, harness.account.signer_public_key);
        }
        other => panic!("expected a public key, got {other:?}"),
    }
}

#[tokio::test]
async fn a_signed_event_carries_the_identity_key_and_verifies() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
        .await
        .expect("request is answered");

    match response {
        ClientResponse::Ok {
            result: ResponseResult::SignEvent(event),
            ..
        } => {
            assert_eq!(event.pubkey, harness.account.identity_public_key);
            assert!(event.verify().is_ok());
        }
        other => panic!("expected a signed event, got {other:?}"),
    }
}

#[tokio::test]
async fn locking_stops_the_signer_answering() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    harness.session.lock();

    let event = harness.envelope("1", &NostrConnectRequest::GetPublicKey);
    assert!(harness
        .session
        .handle(&harness.account, event)
        .await
        .is_none());
}

#[tokio::test]
async fn garbage_is_dropped_rather_than_answered() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    // Sealed to a key the signer does not hold, so the envelope will not open.
    let stranger = Keys::generate();
    let event = NostrConnectEventBuilder::new(
        stranger.public_key(),
        NostrConnectMessage::Request {
            id: "1".to_string(),
            method: NostrConnectMethod::GetPublicKey,
            params: vec![],
        },
    )
    .finalize(&harness.client)
    .expect("client seals its request");

    assert!(harness
        .session
        .handle(&harness.account, event)
        .await
        .is_none());
}

#[tokio::test]
async fn a_denial_is_recorded_in_the_activity_log() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::deny())).await;
    harness.unlock().await;
    harness.pair().await;

    harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
        .await
        .expect("request is answered");

    let entries = harness
        .storage
        .activity(harness.account.id, 10, None)
        .expect("activity loads");
    let latest = entries.first().expect("something was recorded");
    assert_eq!(latest.method, NostrConnectMethod::SignEvent);
    assert_eq!(latest.kind, Some(Kind::TextNote));
}

#[tokio::test]
async fn a_stored_deny_rule_refuses_without_asking() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let client = harness
        .storage
        .clients(harness.account.id)
        .expect("clients load")[0]
        .clone();
    harness
        .storage
        .set_rule(client.id, Scope::sign_event(Kind::TextNote), Decision::Deny)
        .expect("rule writes");

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("denied"));
    assert_eq!(harness.approver.calls(), 0);
}

#[tokio::test]
async fn an_error_never_says_which_check_failed() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    // Unknown client and bad pairing secret are different internally. A client
    // must not be able to tell them apart and map out the signer's state.
    let unpaired = harness
        .call("1", &NostrConnectRequest::GetPublicKey)
        .await
        .expect("request is answered");
    let bad_secret = harness
        .call(
            "2",
            &NostrConnectRequest::Connect {
                remote_signer_public_key: harness.account.signer_public_key,
                secret: Some("nope".to_string()),
            },
        )
        .await
        .expect("request is answered");

    assert_eq!(unpaired.error(), bad_secret.error());
}

#[test]
fn client_facing_errors_stay_coarse() {
    assert_eq!(SignerError::UnknownClient.client_message(), "unauthorized");
    assert_eq!(SignerError::ClientRevoked.client_message(), "unauthorized");
    assert_eq!(
        SignerError::BadPairingSecret.client_message(),
        "unauthorized"
    );
    assert_eq!(SignerError::Denied.client_message(), "denied");
    assert_eq!(SignerError::Expired.client_message(), "timed out");
}
