//! Storage round trips. These are the tests that run away from a Mac.

use nostr::event::Kind;
use nostr::key::Keys;
use nostr::nips::nip46::NostrConnectMethod;
use nostr::types::{RelayUrl, Timestamp};
use signer_core::client::{ClientId, PairingDirection};
use signer_core::policy::{Decision, Outcome, Scope};
use signer_core::storage::{
    ActivityOutcome, ActivitySource, NewAccount, NewActivity, NewPairing, Storage,
};

fn relay(url: &str) -> RelayUrl {
    RelayUrl::parse(url).expect("test relay url parses")
}

#[test]
fn deny_all_overrides_allow_rules_and_forget_all_clears_only_the_selected_app() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), Some("Nostrich"))
        .unwrap();
    let other = storage
        .upsert_client(account.id, &Keys::generate().public_key(), Some("Other"))
        .unwrap();
    let scope = Scope::sign_event(Kind::TextNote);
    storage.set_rule(client.id, scope, Decision::Allow).unwrap();
    storage.set_rule(other.id, scope, Decision::Allow).unwrap();
    storage
        .set_client_allow_all(account.id, client.id, true)
        .unwrap();
    storage.deny_client_actions(account.id, client.id).unwrap();
    let saved = storage
        .client_by_public_key(account.id, &client.public_key)
        .unwrap()
        .unwrap();
    assert!(saved.deny_all);
    assert!(!saved.allow_all);
    let policy = storage.policy_set(client.id).unwrap();
    assert_eq!(policy.evaluate(scope), Outcome::Deny);
    assert_eq!(
        policy.evaluate(Scope::method(NostrConnectMethod::Nip44Decrypt)),
        Outcome::Deny
    );
    let wrong_account = signer_core::account::AccountId::new(account.id.get() + 1);
    assert!(storage
        .deny_client_actions(wrong_account, client.id)
        .is_err());
    assert!(storage
        .forget_client_rules(wrong_account, client.id)
        .is_err());
    assert_eq!(storage.policy_set(client.id).unwrap().rules().len(), 1);
    storage
        .set_client_allow_all(account.id, client.id, true)
        .unwrap();
    assert_eq!(
        storage.policy_set(client.id).unwrap().evaluate(scope),
        Outcome::Allow
    );
    storage.deny_client_actions(account.id, client.id).unwrap();
    storage.forget_client_rules(account.id, client.id).unwrap();
    let saved = storage
        .client_by_public_key(account.id, &client.public_key)
        .unwrap()
        .unwrap();
    assert!(!saved.allow_all && !saved.deny_all);
    assert!(!saved.is_revoked());
    let policy = storage.policy_set(client.id).unwrap();
    assert!(policy.rules().is_empty());
    assert_eq!(policy.evaluate(scope), Outcome::Prompt);
    assert_eq!(
        storage.policy_set(other.id).unwrap().evaluate(scope),
        Outcome::Allow
    );
    storage
        .set_client_allow_all(account.id, client.id, true)
        .unwrap();
    storage.forget_client_rules(account.id, client.id).unwrap();
    assert_eq!(
        storage.policy_set(client.id).unwrap().evaluate(scope),
        Outcome::Prompt
    );
    storage.deny_client_actions(account.id, client.id).unwrap();
    storage.revoke_client(client.id).unwrap();
    assert!(
        !storage
            .client_by_public_key(account.id, &client.public_key)
            .unwrap()
            .unwrap()
            .deny_all
    );
    assert!(storage.deny_client_actions(account.id, client.id).is_err());
    assert!(storage.forget_client_rules(account.id, client.id).is_err());
}

#[test]
fn app_wide_approval_is_scoped_reversible_and_cleared_on_revocation() {
    let (storage, account) = storage_with_account();
    let client = storage
        .upsert_client(account.id, &Keys::generate().public_key(), Some("Nostrich"))
        .unwrap();
    let other = storage
        .upsert_client(account.id, &Keys::generate().public_key(), Some("Other"))
        .unwrap();
    let second = storage
        .insert_account(NewAccount {
            identity_public_key: Keys::generate().public_key(),
            signer_public_key: Keys::generate().public_key(),
            label: "second".into(),
            relays: vec![],
            is_default: false,
        })
        .unwrap();
    let same_app = storage
        .upsert_client(second.id, &client.public_key, Some("Nostrich"))
        .unwrap();
    assert!(!client.allow_all);
    assert!(storage
        .set_client_allow_all(second.id, client.id, true)
        .is_err());
    assert!(storage
        .set_client_allow_all(account.id, ClientId::new(999), true)
        .is_err());
    storage
        .set_rule(client.id, Scope::sign_event(Kind::TextNote), Decision::Deny)
        .unwrap();
    storage
        .set_client_allow_all(account.id, client.id, true)
        .unwrap();
    assert!(
        storage
            .client_by_public_key(account.id, &client.public_key)
            .unwrap()
            .unwrap()
            .allow_all
    );
    let new_kind = Scope::sign_event(Kind::from_u16(27235));
    let policy = storage.policy_set(client.id).unwrap();
    assert_eq!(policy.evaluate(new_kind), Outcome::Allow);
    assert_eq!(
        policy.evaluate(Scope::method(NostrConnectMethod::Nip44Encrypt)),
        Outcome::Allow
    );
    assert_eq!(
        policy.evaluate(Scope::sign_event(Kind::TextNote)),
        Outcome::Deny
    );
    for app in [other.id, same_app.id] {
        assert_eq!(
            storage.policy_set(app).unwrap().evaluate(new_kind),
            Outcome::Prompt
        );
    }
    storage
        .set_client_allow_all(account.id, client.id, false)
        .unwrap();
    assert_eq!(
        storage.policy_set(client.id).unwrap().evaluate(new_kind),
        Outcome::Prompt
    );
    assert_eq!(
        storage
            .policy_set(client.id)
            .unwrap()
            .evaluate(Scope::sign_event(Kind::TextNote)),
        Outcome::Deny
    );
    storage
        .set_client_allow_all(account.id, client.id, true)
        .unwrap();
    storage.revoke_client(client.id).unwrap();
    assert!(
        !storage
            .client_by_public_key(account.id, &client.public_key)
            .unwrap()
            .unwrap()
            .allow_all
    );
    assert!(storage
        .set_client_allow_all(account.id, client.id, true)
        .is_err());
    storage
        .set_client_allow_all(account.id, other.id, true)
        .unwrap();
    storage.remove_client(other.id).unwrap();
    let repaired = storage
        .upsert_client(account.id, &other.public_key, Some("Other"))
        .unwrap();
    assert!(repaired.is_revoked());
    assert!(!repaired.allow_all);
    assert!(storage
        .set_client_allow_all(account.id, other.id, true)
        .is_err());
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
fn lightning_addresses_are_validated_and_scoped_to_an_account() {
    let (storage, first) = storage_with_account();
    let second = storage
        .insert_account(NewAccount {
            identity_public_key: Keys::generate().public_key(),
            signer_public_key: Keys::generate().public_key(),
            label: "second".into(),
            relays: vec![],
            is_default: false,
        })
        .unwrap();
    storage
        .set_lightning_address(first.id, Some(" alice+tips@Example.COM "))
        .unwrap();
    assert_eq!(
        storage
            .account(first.id)
            .unwrap()
            .lightning_address
            .as_deref(),
        Some("alice+tips@example.com")
    );
    assert_eq!(storage.account(second.id).unwrap().lightning_address, None);
    assert_eq!(
        storage
            .account_by_signer_key(&first.signer_public_key)
            .unwrap()
            .unwrap()
            .lightning_address
            .as_deref(),
        Some("alice+tips@example.com")
    );
    for invalid in [
        "Alice@example.com",
        "alice",
        "alice@@example.com",
        "alice@example.com/path",
        "alice@-example.com",
        "alice@foo..com",
        "alice@example.com:443",
        "alice@example.com\nsecret",
        "@example.com",
    ] {
        assert!(
            storage
                .set_lightning_address(first.id, Some(invalid))
                .is_err(),
            "accepted {invalid}"
        );
    }
    assert_eq!(
        storage
            .account(first.id)
            .unwrap()
            .lightning_address
            .as_deref(),
        Some("alice+tips@example.com")
    );
    storage.set_lightning_address(first.id, None).unwrap();
    assert!(storage
        .accounts()
        .unwrap()
        .iter()
        .all(|account| account.lightning_address.is_none()));
    storage.delete_account(first.id).unwrap();
    assert!(storage
        .set_lightning_address(first.id, Some("alice@example.com"))
        .is_err());
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
fn removing_a_client_revokes_it_and_takes_it_off_the_list() {
    let (storage, account) = storage_with_account();
    let key = Keys::generate().public_key();
    let client = storage
        .upsert_client(account.id, &key, None)
        .expect("client inserts");
    storage
        .set_rule(
            client.id,
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )
        .expect("rule writes");

    storage.remove_client(client.id).expect("client removes");

    assert!(storage
        .clients(account.id)
        .expect("clients load")
        .is_empty());
    assert!(storage
        .policy_set(client.id)
        .expect("policy loads")
        .rules()
        .is_empty());

    // Gone from the list, but the row still answers, and it answers revoked.
    // That is what stops Remove being the softer of the two.
    let found = storage
        .client_by_public_key(account.id, &key)
        .expect("lookup runs")
        .expect("the row is still there");
    assert!(found.is_revoked());
    assert!(found.is_removed());
}

#[test]
fn a_removed_client_that_pairs_again_is_listed_and_still_revoked() {
    let (storage, account) = storage_with_account();
    let key = Keys::generate().public_key();
    let client = storage
        .upsert_client(account.id, &key, None)
        .expect("client inserts");
    storage.remove_client(client.id).expect("client removes");

    let again = storage
        .upsert_client(account.id, &key, Some("jumble.social"))
        .expect("client pairs again");

    // Back on the list, so the refusals have something to explain them.
    assert!(!again.is_removed());
    assert!(again.is_revoked());
    assert_eq!(storage.clients(account.id).expect("clients load").len(), 1);
}

#[test]
fn removing_a_client_that_is_not_there_is_an_error() {
    let (storage, _account) = storage_with_account();
    assert!(storage.remove_client(ClientId::new(9999)).is_err());
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
            client_name: None,
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
            client_name: None,
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
