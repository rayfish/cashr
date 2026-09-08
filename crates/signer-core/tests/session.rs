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
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip44::Nip44;
use nostr::nips::nip46::{
    NostrConnectEventBuilder, NostrConnectMessage, NostrConnectMethod, NostrConnectRequest,
    NostrConnectUri, ResponseResult,
};
use nostr::types::{RelayUrl, Timestamp};
use signer_core::account::{Account, AccountId};
use signer_core::approval::{ApprovalDecision, ApprovalRequest, Approver, NullNotifier};
use signer_core::error::SignerError;
use signer_core::keystore::{AccountKeys, KeyHandle, KeyRole, KeyStore, KeyStoreError};
use signer_core::pairing::{accept_client_uri, mint_bunker_uri, parse_client_uri};
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
        account: AccountId,
        keys: &AccountKeys,
    ) -> std::result::Result<(), KeyStoreError> {
        for role in [KeyRole::Identity, KeyRole::Transport] {
            self.put(
                KeyHandle::new(account, role),
                Keys::new(keys.role(role).clone()),
            );
        }
        Ok(())
    }

    async fn delete(&self, account: AccountId) -> std::result::Result<(), KeyStoreError> {
        let mut keys = self.keys.lock().expect("test lock is uncontended");
        for role in [KeyRole::Identity, KeyRole::Transport] {
            keys.remove(&KeyHandle::new(account, role).to_string());
        }
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
        self.envelope_raw(id, request.method(), request.params())
    }

    /// The same, from params a client wrote itself rather than from this
    /// crate's types. Clients in the wild do not use `NostrConnectRequest`.
    fn envelope_raw(&self, id: &str, method: NostrConnectMethod, params: Vec<String>) -> Event {
        let message = NostrConnectMessage::Request {
            id: id.to_string(),
            method,
            params,
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

    /// Send raw params, the way a client that speaks the wire format does.
    async fn call_raw(
        &self,
        id: &str,
        method: NostrConnectMethod,
        params: Vec<String>,
    ) -> Option<ClientResponse> {
        let event = self.envelope_raw(id, method, params);
        let response = self.session.handle(&self.account, event).await?;
        Some(self.open(&response, method))
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

    // The name in the URI is the only thing that makes a prompt readable, so
    // it has to survive from the paste to the client row.
    let client = harness
        .storage
        .client_by_public_key(harness.account.id, &harness.client.public_key())
        .expect("the client row reads back")
        .expect("connect created a client");
    assert_eq!(client.name.as_deref(), Some("Test App"));
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
async fn deny_all_refuses_saved_approvals_and_forget_all_restores_prompts() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;
    let client = harness.storage.clients(harness.account.id).unwrap()[0].clone();
    harness
        .storage
        .set_rule(
            client.id,
            Scope::sign_event(Kind::TextNote),
            Decision::Allow,
        )
        .unwrap();
    harness
        .storage
        .deny_client_actions(harness.account.id, client.id)
        .unwrap();
    let request = NostrConnectRequest::SignEvent(note(harness.account.identity_public_key));
    assert_eq!(
        harness
            .call("blocked-note", &request)
            .await
            .unwrap()
            .error(),
        Some("denied")
    );
    assert_eq!(
        harness
            .call("blocked-identity", &NostrConnectRequest::GetPublicKey)
            .await
            .unwrap()
            .error(),
        Some("denied")
    );
    assert_eq!(harness.approver.calls(), 0);
    harness
        .storage
        .forget_client_rules(harness.account.id, client.id)
        .unwrap();
    assert!(harness
        .call("prompt-again", &request)
        .await
        .unwrap()
        .error()
        .is_none());
    assert_eq!(harness.approver.calls(), 1);
}

#[tokio::test]
async fn allow_all_signs_new_kinds_without_prompts_and_respects_deny_lock_and_revoke() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::deny())).await;
    harness.unlock().await;
    harness.pair().await;
    let client = harness.storage.clients(harness.account.id).unwrap()[0].clone();
    harness
        .storage
        .set_client_allow_all(harness.account.id, client.id, true)
        .unwrap();
    for (index, kind) in [Kind::Metadata, Kind::TextNote, Kind::from_u16(27235)]
        .into_iter()
        .enumerate()
    {
        let mut event = note(harness.account.identity_public_key);
        event.kind = kind;
        assert!(harness
            .call(
                &format!("allow-{index}"),
                &NostrConnectRequest::SignEvent(event)
            )
            .await
            .unwrap()
            .error()
            .is_none());
    }
    assert!(harness
        .call("identity", &NostrConnectRequest::GetPublicKey)
        .await
        .unwrap()
        .error()
        .is_none());
    assert_eq!(harness.approver.calls(), 0);
    let request = NostrConnectRequest::SignEvent(note(harness.account.identity_public_key));
    harness
        .storage
        .set_rule(client.id, Scope::sign_event(Kind::TextNote), Decision::Deny)
        .unwrap();
    assert_eq!(
        harness.call("deny", &request).await.unwrap().error(),
        Some("denied")
    );
    assert_eq!(harness.approver.calls(), 0);
    harness
        .storage
        .clear_rule(client.id, Scope::sign_event(Kind::TextNote))
        .unwrap();
    harness
        .storage
        .set_client_allow_all(harness.account.id, client.id, false)
        .unwrap();
    assert_eq!(
        harness.call("ask-again", &request).await.unwrap().error(),
        Some("denied")
    );
    assert_eq!(harness.approver.calls(), 1);
    harness
        .storage
        .set_client_allow_all(harness.account.id, client.id, true)
        .unwrap();
    harness.session.lock();
    assert!(harness.call("locked", &request).await.is_none());
    harness.unlock().await;
    harness.storage.revoke_client(client.id).unwrap();
    assert_eq!(
        harness.call("revoked", &request).await.unwrap().error(),
        Some("unauthorized")
    );
    assert_eq!(harness.approver.calls(), 1);
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

#[tokio::test]
async fn a_removed_client_is_refused_the_same_way_a_revoked_one_is() {
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
        .remove_client(client.id)
        .expect("client is removed");

    let response = harness
        .call(
            "1",
            &NostrConnectRequest::SignEvent(note(harness.account.identity_public_key)),
        )
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

#[tokio::test]
async fn accepting_a_nostrconnect_uri_sends_the_ack_unprompted() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;

    // The shape a browser client actually produces: flat parameters, and no
    // request of its own. It is sitting on its relays waiting to be answered.
    let uri = format!(
        "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example%2F&secret=s3cret&name=example.app",
        harness.client.public_key().to_hex()
    );
    let parsed = parse_client_uri(&uri).expect("a current client URI parses");
    let pairing = accept_client_uri(
        &harness.storage,
        &harness.account,
        &parsed,
        Duration::from_secs(300),
    )
    .expect("uri is accepted");

    let ack = harness
        .session
        .accept_pairing(
            &harness.account,
            &pairing.client_public_key,
            &pairing.secret,
        )
        .await
        .expect("the ack is minted");

    assert_eq!(ack.kind, Kind::NostrConnect);
    assert_eq!(ack.pubkey, harness.account.signer_public_key);

    match harness.open(&ack, NostrConnectMethod::Connect) {
        ClientResponse::Ok {
            result: ResponseResult::ConnectSecret(echoed),
            ..
        } => assert_eq!(echoed, "s3cret"),
        other => panic!("expected the secret echoed back, got {other:?}"),
    }

    // And the pairing is spent, so the same URI cannot be replayed.
    assert!(harness
        .session
        .accept_pairing(
            &harness.account,
            &pairing.client_public_key,
            &pairing.secret
        )
        .await
        .is_err());
}

#[tokio::test]
async fn a_sign_event_template_without_a_pubkey_is_signed() {
    // What clients actually send: NIP-46 names `{kind, content, tags,
    // created_at}` and nothing else, because only the signer knows the pubkey.
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let template = serde_json::json!({
        "kind": 1,
        "content": "hello",
        "tags": [],
        "created_at": 1_700_000_000u64,
    })
    .to_string();

    let response = harness
        .call_raw("1", NostrConnectMethod::SignEvent, vec![template])
        .await
        .expect("request is answered");

    let ClientResponse::Ok {
        result: ResponseResult::SignEvent(event),
        ..
    } = response
    else {
        panic!("sign_event was refused: {response:?}");
    };
    assert_eq!(event.pubkey, harness.account.identity_public_key);
    assert_eq!(event.kind, Kind::TextNote);
    assert_eq!(event.content, "hello");
    event.verify().expect("the signed event verifies");
}

#[tokio::test]
async fn the_signer_signs_its_own_id_not_the_client_s() {
    // The id is the only thing the signature covers. Taking the client's would
    // sign bytes nobody looked at, whatever the prompt said the request was.
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let stranger = Keys::generate().public_key();
    let template = serde_json::json!({
        "id": "00".repeat(32),
        "pubkey": stranger.to_hex(),
        "kind": 1,
        "content": "hello",
        "tags": [],
        "created_at": 1_700_000_000u64,
    })
    .to_string();

    let response = harness
        .call_raw("1", NostrConnectMethod::SignEvent, vec![template])
        .await
        .expect("request is answered");

    let ClientResponse::Ok {
        result: ResponseResult::SignEvent(event),
        ..
    } = response
    else {
        panic!("sign_event was refused: {response:?}");
    };
    assert_eq!(event.pubkey, harness.account.identity_public_key);
    event.verify().expect("the signed event verifies");
}

#[tokio::test]
async fn a_request_that_will_not_parse_is_recorded() {
    let harness = Harness::new(ScriptedApprover::new(ApprovalDecision::allow_once())).await;
    harness.unlock().await;
    harness.pair().await;

    let response = harness
        .call_raw(
            "1",
            NostrConnectMethod::SignEvent,
            vec!["not an event".to_string()],
        )
        .await
        .expect("request is answered");

    assert_eq!(response.error(), Some("invalid request"));

    let entries = harness
        .storage
        .activity(harness.account.id, 10, None)
        .expect("activity loads");
    let latest = entries.first().expect("something was recorded");
    assert_eq!(latest.method, NostrConnectMethod::SignEvent);
    assert!(latest.client.is_some());
}
