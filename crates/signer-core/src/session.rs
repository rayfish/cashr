//! The NIP-46 request loop: decrypt, authorize, execute, answer.
//!
//! This module is transport-free. It is handed one event at a time and returns
//! the event to publish back, which is what lets it be tested without a relay.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nostr::event::{Event, Kind};
use nostr::key::PublicKey;
use nostr::nips::nip46::{
    NostrConnectMessage, NostrConnectMethod, NostrConnectRequest, NostrConnectResponse,
    ResponseResult,
};
use nostr::types::Timestamp;
use tokio::time::{timeout, Instant};

use crate::account::{Account, AccountId};
use crate::approval::{describe, ApprovalRequest, Approver, Notifier, SignerEvent};
use crate::client::{Client, PairingDirection};
use crate::error::{Result, SignerError};
use crate::keystore::KeyStore;
use crate::pairing::random_hex;
use crate::policy::{Decision, Outcome, Scope};
use crate::storage::{ActivityOutcome, ActivitySource, NewActivity, Storage};
use crate::vault::Vault;
use crate::AsyncMutex;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// How long a prompt waits before the request is refused.
    pub request_timeout: Duration,
    /// How long an unused pairing secret stays valid.
    pub pairing_ttl: Duration,
    /// How long an answer is remembered so a redelivered request is not
    /// prompted for twice.
    pub replay_window: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            pairing_ttl: Duration::from_secs(300),
            replay_window: Duration::from_secs(60),
        }
    }
}

/// Everything the session needs, named rather than passed positionally.
pub struct SessionParts {
    pub storage: Arc<Storage>,
    pub vault: Arc<Vault>,
    pub keystore: Arc<dyn KeyStore>,
    pub approver: Arc<dyn Approver>,
    pub notifier: Arc<dyn Notifier>,
    pub config: SessionConfig,
}

/// Bytes of entropy in an invented NIP-46 request id.
const REQUEST_ID_BYTES: usize = 8;

/// An event that arrived while the signer was locked.
struct Deferred {
    account: AccountId,
    event: Event,
    received_at: Instant,
}

struct Answered {
    response: Event,
    answered_at: Instant,
}

pub struct Session {
    storage: Arc<Storage>,
    vault: Arc<Vault>,
    keystore: Arc<dyn KeyStore>,
    approver: Arc<dyn Approver>,
    notifier: Arc<dyn Notifier>,
    config: SessionConfig,
    /// One prompt at a time. Ten simultaneous requests should not produce ten
    /// notifications competing for the same answer.
    prompt_gate: AsyncMutex<()>,
    answered: AsyncMutex<HashMap<(PublicKey, String), Answered>>,
    deferred: AsyncMutex<Vec<Deferred>>,
}

impl Session {
    pub fn new(parts: SessionParts) -> Self {
        Self {
            storage: parts.storage,
            vault: parts.vault,
            keystore: parts.keystore,
            approver: parts.approver,
            notifier: parts.notifier,
            config: parts.config,
            prompt_gate: AsyncMutex::new(()),
            answered: AsyncMutex::new(HashMap::new()),
            deferred: AsyncMutex::new(Vec::new()),
        }
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Load key material for every account. One call, one Touch ID prompt.
    pub async fn unlock(&self, accounts: &[AccountId]) -> Result<()> {
        self.vault.unlock(self.keystore.as_ref(), accounts).await?;
        self.notifier.notify(SignerEvent::Unlocked);
        Ok(())
    }

    pub fn lock(&self) {
        self.vault.lock();
        self.notifier.notify(SignerEvent::Locked);
    }

    /// Events that arrived while locked and are still worth answering.
    ///
    /// The caller feeds these back through [`Session::handle`] after an
    /// unlock. Anything older than the request timeout is dropped, so a client
    /// gets silence rather than a signature it stopped expecting.
    pub async fn take_deferred(&self) -> Vec<(AccountId, Event)> {
        let mut deferred = self.deferred.lock().await;
        let timeout = self.config.request_timeout;
        deferred
            .drain(..)
            .filter(|entry| entry.received_at.elapsed() < timeout)
            .map(|entry| (entry.account, entry.event))
            .collect()
    }

    /// Handle one incoming event.
    ///
    /// `None` means the event is not answerable and should leave no trace: a
    /// wrong kind, an envelope that will not open, or a body that is not a
    /// request. Answering those would tell a stranger which pubkeys this
    /// signer holds.
    pub async fn handle(&self, account: &Account, event: Event) -> Option<Event> {
        if event.kind != Kind::NostrConnect {
            return None;
        }

        if !self.vault.holds(account.id) {
            self.defer(account.id, event).await;
            self.notifier.notify(SignerEvent::UnlockNeeded {
                account: account.id,
            });
            return None;
        }

        let sender = event.pubkey;
        let plaintext = self
            .vault
            .open_envelope(account.id, &sender, &event.content)
            .ok()?;

        let message: NostrConnectMessage = serde_json::from_str(&plaintext).ok()?;
        let (id, method, params) = match message {
            NostrConnectMessage::Request { id, method, params } => (id, method, params),
            NostrConnectMessage::Response { .. } => return None,
        };

        if let Some(cached) = self.cached_answer(&sender, &id).await {
            return Some(cached);
        }

        let response = match self.dispatch(account, &sender, method, params).await {
            Ok(result) => NostrConnectResponse::with_result(result),
            Err(error) => {
                tracing::debug!(%method, "request refused: {error}");
                NostrConnectResponse::with_error(error.client_message())
            }
        };

        let sealed = self
            .vault
            .seal_envelope(
                account.id,
                sender,
                NostrConnectMessage::response(id.clone(), response),
            )
            .ok()?;

        self.remember_answer(sender, id, sealed.clone()).await;
        Some(sealed)
    }

    /// Answer a `nostrconnect://` pairing without waiting to be asked.
    ///
    /// This direction has the signer speak first. The client that minted the
    /// URI is already listening for a response carrying its own secret back,
    /// and it never sends a `connect` request of its own, so nothing happens
    /// until this event goes out.
    ///
    /// Returns the event to publish on the relays the client named.
    pub async fn accept_pairing(
        &self,
        account: &Account,
        client_public_key: &PublicKey,
        secret: &str,
    ) -> Result<Event> {
        if !self.vault.holds(account.id) {
            return Err(SignerError::Locked);
        }

        let result = self
            .connect(
                account,
                client_public_key,
                &account.signer_public_key,
                Some(secret),
            )
            .await?;

        // No request means no request id, so this one is ours to pick. Clients
        // match the ack by the secret in its result, not by the id.
        let id = random_hex(REQUEST_ID_BYTES)?;
        self.vault.seal_envelope(
            account.id,
            *client_public_key,
            NostrConnectMessage::response(id, NostrConnectResponse::with_result(result)),
        )
    }

    async fn dispatch(
        &self,
        account: &Account,
        sender: &PublicKey,
        method: NostrConnectMethod,
        params: Vec<String>,
    ) -> Result<ResponseResult> {
        let request = NostrConnectRequest::from_message(method, params)?;

        if let NostrConnectRequest::Connect {
            remote_signer_public_key,
            secret,
        } = &request
        {
            return self
                .connect(account, sender, remote_signer_public_key, secret.as_deref())
                .await;
        }

        let client = self
            .storage
            .client_by_public_key(account.id, sender)?
            .ok_or(SignerError::UnknownClient)?;
        if client.is_revoked() {
            return Err(SignerError::ClientRevoked);
        }
        self.storage.touch_client(client.id)?;

        // Ping is liveness, not access. Answering it costs nothing and never
        // touches key material, so it does not deserve a prompt.
        if matches!(request, NostrConnectRequest::Ping) {
            return Ok(ResponseResult::Pong);
        }

        let scope = scope_for(&request);
        let decision = self.authorize(account, &client, scope).await?;
        if decision == Decision::Deny {
            return Err(SignerError::Denied);
        }

        self.execute(account, request)
    }

    /// Turn a `connect` into a trusted client, or refuse it.
    ///
    /// A pairing secret is mandatory in both directions. Without one, anyone
    /// who learns the signer's transport pubkey could pair themselves.
    async fn connect(
        &self,
        account: &Account,
        sender: &PublicKey,
        remote_signer_public_key: &PublicKey,
        secret: Option<&str>,
    ) -> Result<ResponseResult> {
        if remote_signer_public_key != &account.signer_public_key {
            return Err(SignerError::UnknownClient);
        }

        let secret = secret.ok_or(SignerError::BadPairingSecret)?;
        let pairing = self
            .storage
            .usable_pairing(secret)?
            .ok_or(SignerError::BadPairingSecret)?;

        if pairing.account != account.id {
            return Err(SignerError::BadPairingSecret);
        }

        // A `nostrconnect://` URI names its client up front. Anyone else
        // presenting that secret is not the app the user pasted.
        if let Some(expected) = pairing.client_public_key {
            if &expected != sender {
                return Err(SignerError::BadPairingSecret);
            }
        }

        self.storage.consume_pairing(pairing.id, sender)?;
        let client =
            self.storage
                .upsert_client(account.id, sender, pairing.client_name.as_deref())?;

        self.notifier.notify(SignerEvent::ClientConnected {
            account: account.id,
            client: client.id,
        });
        self.storage.record_activity(NewActivity {
            account: account.id,
            client: Some(client.id),
            method: NostrConnectMethod::Connect,
            kind: None,
            outcome: ActivityOutcome::Allowed,
            source: ActivitySource::User,
            detail: Some(format!("paired via {}", pairing.direction.as_str())),
        })?;

        Ok(match pairing.direction {
            // NIP-46 requires the client-initiated flow to get its own secret
            // echoed back, so the client can tell a real signer from a spoof.
            PairingDirection::NostrConnect => ResponseResult::ConnectSecret(secret.to_string()),
            PairingDirection::Bunker => ResponseResult::Ack,
        })
    }

    /// Consult stored rules, and ask the user when they do not cover this.
    async fn authorize(
        &self,
        account: &Account,
        client: &Client,
        scope: Scope,
    ) -> Result<Decision> {
        match self.storage.policy_set(client.id)?.evaluate(scope) {
            Outcome::Allow => {
                self.record(
                    account,
                    client,
                    scope,
                    ActivityOutcome::Allowed,
                    ActivitySource::Policy,
                )?;
                Ok(Decision::Allow)
            }
            Outcome::Deny => {
                self.record(
                    account,
                    client,
                    scope,
                    ActivityOutcome::Denied,
                    ActivitySource::Policy,
                )?;
                Ok(Decision::Deny)
            }
            Outcome::Prompt => self.prompt(account, client, scope).await,
        }
    }

    async fn prompt(&self, account: &Account, client: &Client, scope: Scope) -> Result<Decision> {
        let request = ApprovalRequest {
            account: account.id,
            account_label: account.label.clone(),
            client: client.id,
            client_public_key: client.public_key,
            client_name: client.name.clone(),
            scope,
            detail: describe(scope, scope.kind),
            requested_at: Timestamp::now(),
        };

        let _gate = self.prompt_gate.lock().await;
        let answer = timeout(self.config.request_timeout, self.approver.request(request)).await;

        let decision = match answer {
            Ok(Ok(approval)) => {
                if approval.remember {
                    self.storage.set_rule(client.id, scope, approval.decision)?;
                }
                self.record(
                    account,
                    client,
                    scope,
                    outcome_of(approval.decision),
                    ActivitySource::User,
                )?;
                approval.decision
            }
            Ok(Err(error)) => {
                self.record(
                    account,
                    client,
                    scope,
                    ActivityOutcome::Failed,
                    ActivitySource::Error,
                )?;
                return Err(error);
            }
            Err(_elapsed) => {
                self.record(
                    account,
                    client,
                    scope,
                    ActivityOutcome::Denied,
                    ActivitySource::Timeout,
                )?;
                return Err(SignerError::Expired);
            }
        };

        self.notifier.notify(SignerEvent::RequestHandled {
            account: account.id,
            client: client.id,
            scope,
            decision,
        });

        Ok(decision)
    }

    fn execute(&self, account: &Account, request: NostrConnectRequest) -> Result<ResponseResult> {
        let id = account.id;
        Ok(match request {
            NostrConnectRequest::GetPublicKey => {
                ResponseResult::GetPublicKey(self.vault.identity_public_key(id)?)
            }
            NostrConnectRequest::SignEvent(unsigned) => {
                ResponseResult::SignEvent(Box::new(self.vault.sign_event(id, unsigned)?))
            }
            NostrConnectRequest::Nip04Encrypt { public_key, text } => {
                ResponseResult::Nip04Encrypt {
                    ciphertext: self.vault.nip04_encrypt(id, &public_key, &text)?,
                }
            }
            NostrConnectRequest::Nip04Decrypt {
                public_key,
                ciphertext,
            } => ResponseResult::Nip04Decrypt {
                plaintext: self.vault.nip04_decrypt(id, &public_key, &ciphertext)?,
            },
            NostrConnectRequest::Nip44Encrypt { public_key, text } => {
                ResponseResult::Nip44Encrypt {
                    ciphertext: self.vault.nip44_encrypt(id, &public_key, &text)?,
                }
            }
            NostrConnectRequest::Nip44Decrypt {
                public_key,
                ciphertext,
            } => ResponseResult::Nip44Decrypt {
                plaintext: self.vault.nip44_decrypt(id, &public_key, &ciphertext)?,
            },
            NostrConnectRequest::Ping => ResponseResult::Pong,
            // Handled before authorization; a connect never reaches here.
            NostrConnectRequest::Connect { .. } => {
                return Err(SignerError::InvalidRequest("connect out of order"))
            }
        })
    }

    fn record(
        &self,
        account: &Account,
        client: &Client,
        scope: Scope,
        outcome: ActivityOutcome,
        source: ActivitySource,
    ) -> Result<()> {
        self.storage.record_activity(NewActivity {
            account: account.id,
            client: Some(client.id),
            method: scope.method,
            kind: scope.kind,
            outcome,
            source,
            detail: None,
        })
    }

    async fn defer(&self, account: AccountId, event: Event) {
        let mut deferred = self.deferred.lock().await;
        let timeout = self.config.request_timeout;
        deferred.retain(|entry| entry.received_at.elapsed() < timeout);
        deferred.push(Deferred {
            account,
            event,
            received_at: Instant::now(),
        });
    }

    /// Relays redeliver. A repeat of a request already answered gets the same
    /// answer rather than a second prompt.
    async fn cached_answer(&self, sender: &PublicKey, id: &str) -> Option<Event> {
        let mut answered = self.answered.lock().await;
        answered.retain(|_, entry| entry.answered_at.elapsed() < self.config.replay_window);
        answered
            .get(&(*sender, id.to_string()))
            .map(|entry| entry.response.clone())
    }

    async fn remember_answer(&self, sender: PublicKey, id: String, response: Event) {
        self.answered.lock().await.insert(
            (sender, id),
            Answered {
                response,
                answered_at: Instant::now(),
            },
        );
    }
}

fn scope_for(request: &NostrConnectRequest) -> Scope {
    match request {
        NostrConnectRequest::SignEvent(unsigned) => Scope::sign_event(unsigned.kind),
        other => Scope::method(other.method()),
    }
}

fn outcome_of(decision: Decision) -> ActivityOutcome {
    match decision {
        Decision::Allow => ActivityOutcome::Allowed,
        Decision::Deny => ActivityOutcome::Denied,
    }
}
