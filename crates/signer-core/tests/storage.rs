//! Storage round trips. These are the tests that run away from a Mac.

use nostr::event::Kind;
use nostr::key::Keys;
use nostr::nips::nip46::NostrConnectMethod;
use nostr::types::{RelayUrl, Timestamp};
use signer_core::client::PairingDirection;
use signer_core::policy::{Decision, Outcome, Scope};
use signer_core::storage::{
    ActivityOutcome, ActivitySource, NewAccount, NewActivity, NewPairing, Storage,
};

fn relay(url: &str) -> RelayUrl {
    RelayUrl::parse(url).expect("test relay url parses")
}

fn storage_with_account() -> (Storage, signer_core::account::Account) {
    let storage = Storage::in_memory().expect("in-memory database opens");
    let identity = Keys::generate();
    let transport = Keys::generate();

    let account = storage
        .insert_account(NewAccount {
            identity_public_key: identity.public_key(),
            signer_public_key: transport.public_key(),
            label: "test".to_string(),
            relays: vec![relay("wss://relay.example"), relay("wss://relay2.example")],
            is_default: true,
        })
        .expect("account inserts");

    (storage, account)
}

#[test]
fn account_round_trips_with_its_relays() {
    let (storage, account) = storage_with_account();

    let loaded = storage.account(account.id).expect("account loads");
    assert_eq!(loaded.identity_public_key, account.identity_public_key);
    assert_eq!(loaded.label, "test");
    assert!(loaded.is_default);
    assert_eq!(
        loaded.relays,
        vec![relay("wss://relay.example"), relay("wss://relay2.example")]
    );
}

#[test]
fn accounts_are_found_by_signer_key_not_identity_key() {
    let (storage, account) = storage_with_account();

    let found = storage
        .account_by_signer_key(&account.signer_public_key)
        .expect("lookup runs");
    assert_eq!(found.map(|a| a.id), Some(account.id));

    let by_identity = storage
        .account_by_signer_key(&account.identity_public_key)
        .expect("lookup runs");
    assert!(by_identity.is_none());
}

#[test]
fn only_one_account_is_default() {
    let (storage, first) = storage_with_account();
    let second = storage
        .insert_account(NewAccount {
            identity_public_key: Keys::generate().public_key(),
            signer_public_key: Keys::generate().public_key(),
            label: "second".to_string(),
            relays: vec![],
            is_default: true,
        })
        .expect("second account inserts");

    let accounts = storage.accounts().expect("accounts load");
    let defaults: Vec<_> = accounts
        .iter()
        .filter(|a| a.is_default)
        .map(|a| a.id)
        .collect();
    assert_eq!(defaults, vec![second.id]);

    storage
        .set_default_account(first.id)
        .expect("default moves");
    let accounts = storage.accounts().expect("accounts load");
    let defaults: Vec<_> = accounts
        .iter()
        .filter(|a| a.is_default)
        .map(|a| a.id)
        .collect();
    assert_eq!(defaults, vec![first.id]);
}

#[test]
fn relays_are_replaced_wholesale() {
    let (storage, account) = storage_with_account();
    storage
        .set_account_relays(account.id, &[relay("wss://only.example")])
        .expect("relays replace");

    assert_eq!(
        storage.account_relays(account.id).expect("relays load"),
        vec![relay("wss://only.example")]
    );
}

#[test]
fn upserting_a_client_keeps_first_seen_and_an_earlier_name() {
    let (storage, account) = storage_with_account();
    let client_key = Keys::generate().public_key();

    let first = storage
        .upsert_client(account.id, &client_key, Some("Some App"))
        .expect("client inserts");
    let again = storage
        .upsert_client(account.id, &client_key, None)
        .expect("client upserts");

    assert_eq!(first.id, again.id);
    assert_eq!(first.first_seen, again.first_seen);
    assert_eq!(again.name.as_deref(), Some("Some App"));
}

#[test]
fn stored_rules_drive_evaluation() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), None)
        .expect("client inserts");

    assert_eq!(
        storage
            .policy_set(client.id)
            .expect("policy loads")
            .evaluate(Scope::sign_event(Kind::TextNote)),
        Outcome::Prompt
    );

    storage
        .set_rule(
            client.id,
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )
        .expect("rule writes");
    storage
        .set_rule(
            client.id,
            Scope::sign_event(Kind::EncryptedDirectMessage),
            Decision::Deny,
        )
        .expect("rule writes");

    let policy = storage.policy_set(client.id).expect("policy loads");
    assert_eq!(
        policy.evaluate(Scope::sign_event(Kind::TextNote)),
        Outcome::Allow
    );
    assert_eq!(
        policy.evaluate(Scope::sign_event(Kind::EncryptedDirectMessage)),
        Outcome::Deny
    );
}

#[test]
fn writing_the_same_scope_twice_updates_rather_than_duplicates() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), None)
        .expect("client inserts");
    let scope = Scope::method(NostrConnectMethod::Nip44Decrypt);

    storage
        .set_rule(client.id, scope, Decision::Allow)
        .expect("rule writes");
    storage
        .set_rule(client.id, scope, Decision::Deny)
        .expect("rule updates");

    let policy = storage.policy_set(client.id).expect("policy loads");
    assert_eq!(policy.rules().len(), 1);
    assert_eq!(policy.evaluate(scope), Outcome::Deny);
}

#[test]
fn revoking_a_client_drops_its_rules() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), None)
        .expect("client inserts");
    storage
        .set_rule(
            client.id,
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )
        .expect("rule writes");

    storage.revoke_client(client.id).expect("client revokes");

    assert!(storage
        .policy_set(client.id)
        .expect("policy loads")
        .rules()
        .is_empty());
    let clients = storage.clients(account.id).expect("clients load");
    assert!(clients[0].is_revoked());
}

#[test]
fn a_pairing_secret_works_once() {
    let (storage, account) = storage_with_account();
    let client_key = Keys::generate().public_key();

    let pairing = storage
        .insert_pairing(NewPairing {
            account: account.id,
            secret: "s3cret".to_string(),
            direction: PairingDirection::Bunker,
            client_public_key: None,
            expires_at: Timestamp::now() + 300u64,
        })
        .expect("pairing inserts");

    let found = storage.usable_pairing("s3cret").expect("lookup runs");
    assert_eq!(found.map(|p| p.id), Some(pairing.id));

    storage
        .consume_pairing(pairing.id, &client_key)
        .expect("pairing consumes");

    assert!(storage
        .usable_pairing("s3cret")
        .expect("lookup runs")
        .is_none());
    assert!(storage.consume_pairing(pairing.id, &client_key).is_err());
}

#[test]
fn an_expired_pairing_is_not_usable() {
    let (storage, account) = storage_with_account();
    storage
        .insert_pairing(NewPairing {
            account: account.id,
            secret: "stale".to_string(),
            direction: PairingDirection::NostrConnect,
            client_public_key: None,
            expires_at: Timestamp::from_secs(1),
        })
        .expect("pairing inserts");

    assert!(storage
        .usable_pairing("stale")
        .expect("lookup runs")
        .is_none());
    assert_eq!(storage.prune_pairings().expect("prune runs"), 1);
}

#[test]
fn activity_reads_back_newest_first() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), None)
        .expect("client inserts");

    for kind in [Kind::TextNote, Kind::EncryptedDirectMessage] {
        storage
            .record_activity(NewActivity {
                account: account.id,
                client: Some(client.id),
                method: NostrConnectMethod::SignEvent,
                kind: Some(kind),
                outcome: ActivityOutcome::Allowed,
                source: ActivitySource::Policy,
                detail: None,
            })
            .expect("activity records");
    }

    let entries = storage
        .activity(account.id, 10, None)
        .expect("activity loads");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].kind, Some(Kind::EncryptedDirectMessage));
    assert_eq!(entries[1].kind, Some(Kind::TextNote));

    let page = storage
        .activity(account.id, 10, Some(entries[0].id))
        .expect("activity pages");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, entries[1].id);
}

#[test]
fn deleting_an_account_takes_its_children() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), None)
        .expect("client inserts");
    storage
        .set_rule(
            client.id,
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )
        .expect("rule writes");

    storage.delete_account(account.id).expect("account deletes");

    assert!(storage.accounts().expect("accounts load").is_empty());
    assert!(storage
        .policy_set(client.id)
        .expect("policy loads")
        .rules()
        .is_empty());
}
