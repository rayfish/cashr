//! The pending-request registry. Platform-independent, so it runs anywhere.

use std::time::Duration;

use macos_native::notifications::{NotificationApprover, RequestId};
use nostr::event::Kind;
use nostr::key::Keys;
use nostr::nips::nip46::NostrConnectMethod;
use nostr::types::Timestamp;
use signer_core::account::AccountId;
use signer_core::approval::{ApprovalDecision, ApprovalRequest, Approver};
use signer_core::client::ClientId;
use signer_core::policy::{Decision, Scope};

fn request() -> ApprovalRequest {
    ApprovalRequest {
        account: AccountId::new(1),
        account_label: "test".to_string(),
        client: ClientId::new(1),
        client_public_key: Keys::generate().public_key(),
        client_name: Some("Some App".to_string()),
        scope: Scope::sign_event(Kind::TextNote),
        detail: "sign a kind 1 event".to_string(),
        requested_at: Timestamp::now(),
    }
}

#[tokio::test]
async fn a_prompt_is_listed_while_it_waits_and_gone_once_answered() {
    let approver = NotificationApprover::new();
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.request(request()).await }
    });

    let pending = loop {
        let pending = approver.pending();
        if !pending.is_empty() {
            break pending;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request.client_name.as_deref(), Some("Some App"));

    assert!(approver.resolve(pending[0].id, ApprovalDecision::allow_always()));

    let decision = asking.await.expect("task joins").expect("prompt answered");
    assert_eq!(decision.decision, Decision::Allow);
    assert!(decision.remember);
    assert_eq!(approver.pending_count(), 0);
}

#[tokio::test]
async fn resolving_something_unknown_is_harmless() {
    let approver = NotificationApprover::new();
    assert!(!approver.resolve(
        RequestId::parse("42").expect("id parses"),
        ApprovalDecision::deny()
    ));
}

#[tokio::test]
async fn abandoning_a_prompt_clears_it_from_the_list() {
    let approver = NotificationApprover::new();

    // The session drops the future when a request times out. The prompt must
    // not stay in the window offering a decision nobody can receive.
    let answer = tokio::time::timeout(Duration::from_millis(20), approver.request(request())).await;
    assert!(answer.is_err(), "the prompt should have timed out");

    assert_eq!(approver.pending_count(), 0);
}

#[tokio::test]
async fn prompts_are_listed_in_arrival_order() {
    let approver = NotificationApprover::new();
    for _ in 0..3 {
        let approver = approver.clone();
        tokio::spawn(async move { approver.request(request()).await });
    }

    let pending = loop {
        let pending = approver.pending();
        if pending.len() == 3 {
            break pending;
        }
        tokio::task::yield_now().await;
    };

    let ids: Vec<u64> = pending.iter().map(|p| p.id.get()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

#[test]
fn method_scopes_render_without_a_kind() {
    let scope = Scope::method(NostrConnectMethod::Nip44Decrypt);
    assert_eq!(scope.kind, None);
}
