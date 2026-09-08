//! Approval prompts delivered as notifications with Approve, Always allow and
//! Reject buttons.
//!
//! The pending-request registry is plain Rust and platform-independent, which
//! matters: a notification can be suppressed by a Focus mode, so the window
//! and the tray badge read the same registry and a suppressed notification
//! degrades to "the icon has a dot on it" rather than a lost request.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use signer_core::approval::{ApprovalDecision, ApprovalRequest, Approver};
use signer_core::error::{Result, SignerError};
use tokio::sync::oneshot;

/// Identifies one waiting prompt. Also the notification's identifier, so an
/// action tapped in Notification Center finds its way back here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    pub fn get(&self) -> u64 {
        self.0
    }

    pub fn parse(value: &str) -> Option<Self> {
        value.parse().ok().map(Self)
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A prompt the user has not answered yet, as the window renders it.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub id: RequestId,
    pub request: ApprovalRequest,
}

struct Waiting {
    request: ApprovalRequest,
    answer: oneshot::Sender<ApprovalDecision>,
}

#[derive(Default)]
pub struct NotificationApprover {
    waiting: Mutex<HashMap<RequestId, Waiting>>,
    next_id: AtomicU64,
}

impl NotificationApprover {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Everything still waiting, oldest first. Drives the window list and the
    /// tray badge.
    pub fn pending(&self) -> Vec<PendingRequest> {
        let waiting = self.lock();
        let mut pending: Vec<PendingRequest> = waiting
            .iter()
            .map(|(id, entry)| PendingRequest {
                id: *id,
                request: entry.request.clone(),
            })
            .collect();
        pending.sort_by_key(|p| p.id);
        pending
    }

    pub fn pending_count(&self) -> usize {
        self.lock().len()
    }

    /// Answer a prompt, from a notification button or from the window.
    ///
    /// Returns false when the request is already gone, which is the normal
    /// outcome of tapping a notification for something that timed out.
    pub fn resolve(&self, id: RequestId, decision: ApprovalDecision) -> bool {
        let Some(entry) = self.lock().remove(&id) else {
            return false;
        };
        platform::withdraw(id);
        entry.answer.send(decision).is_ok()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<RequestId, Waiting>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Removes the registry entry if the caller gives up first.
///
/// The session drops this future when a request times out. Without this the
/// prompt would linger in the window forever, offering the user a decision
/// that can no longer be delivered anywhere.
struct Cleanup<'a> {
    approver: &'a NotificationApprover,
    id: RequestId,
    done: bool,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.approver.lock().remove(&self.id);
            platform::withdraw(self.id);
        }
    }
}

#[async_trait]
impl Approver for NotificationApprover {
    async fn request(&self, request: ApprovalRequest) -> Result<ApprovalDecision> {
        let id = RequestId(self.next_id.fetch_add(1, Ordering::SeqCst));
        let (sender, receiver) = oneshot::channel();

        self.lock().insert(
            id,
            Waiting {
                request: request.clone(),
                answer: sender,
            },
        );

        let mut cleanup = Cleanup {
            approver: self,
            id,
            done: false,
        };

        // A notification that will not post is not a failure: the request is
        // in the registry, so the window and the tray badge still show it.
        if let Err(error) = platform::post(id, &request) {
            tracing::warn!("could not post notification: {error}");
        }

        let decision = receiver
            .await
            .map_err(|_| SignerError::InvalidRequest("approval channel closed"))?;
        cleanup.done = true;
        Ok(decision)
    }
}

/// Identifiers shared with the delegate. Changing one means changing it in
/// both the category registration and the response handler.
pub const CATEGORY: &str = "SIGN_REQUEST";
pub const ACTION_APPROVE: &str = "APPROVE";
pub const ACTION_ALWAYS: &str = "ALWAYS_ALLOW";
pub const ACTION_REJECT: &str = "REJECT";
#[cfg(target_os = "macos")]
const PAYMENT_CATEGORY: &str = "PAYMENT_REQUEST";
#[cfg(any(target_os = "macos", test))]
const ACTION_PAY: &str = "APPROVE_PAYMENT";
#[cfg(any(target_os = "macos", test))]
const ACTION_DECLINE: &str = "DECLINE_PAYMENT";

/// Payment actions never create a saved permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentAction {
    Approve,
    Decline,
    Open,
}

#[cfg(any(target_os = "macos", test))]
fn payment_action(action: &str) -> Option<PaymentAction> {
    match action {
        ACTION_PAY => Some(PaymentAction::Approve),
        ACTION_DECLINE => Some(PaymentAction::Decline),
        "com.apple.UNNotificationDefaultActionIdentifier" => Some(PaymentAction::Open),
        _ => None,
    }
}

pub struct PaymentPrompt<'a> {
    pub id: &'a str,
    pub app: &'a str,
    pub account: &'a str,
    pub amount: u64,
    pub max_fee: u64,
    pub maximum: u64,
}

/// Owned by the pending payment so answering, revoking or cancelling it also
/// removes its notification.
pub struct PaymentNotification(String);

impl Drop for PaymentNotification {
    fn drop(&mut self) {
        platform::withdraw_payment(&self.0);
    }
}

pub fn notify_payment(prompt: PaymentPrompt<'_>) -> PaymentNotification {
    platform::post_payment(&prompt);
    PaymentNotification(format!("payment:{}", prompt.id))
}

/// Identifier of the "the signer is locked" notice.
///
/// Fixed rather than one per request: several requests arriving while locked
/// are one piece of news, and posting under the same identifier replaces the
/// notice instead of stacking copies of it.
const LOCKED: &str = "UNLOCK_NEEDED";

/// Say that a request arrived and the keys are not loaded.
///
/// No Approve or Reject on this one. Nothing can be decided while the vault is
/// locked, and offering a button that cannot be honoured is worse than saying
/// plainly what has to happen first. The request itself is held by the session
/// and answered after the unlock.
pub fn notify_locked(account_label: &str) {
    platform::post_locked(account_label);
}

/// Take the notice back, once it has stopped being true.
pub fn clear_locked() {
    platform::clear_locked();
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::OnceLock;

    use block2::{DynBlock, RcBlock};
    use objc2::rc::Retained;
    use objc2::runtime::{Bool, ProtocolObject};
    use objc2::{define_class, msg_send, AllocAnyThread};
    use objc2_foundation::{NSArray, NSError, NSObject, NSObjectProtocol, NSSet, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotification, UNNotificationAction,
        UNNotificationActionOptions, UNNotificationCategory, UNNotificationCategoryOptions,
        UNNotificationPresentationOptions, UNNotificationRequest, UNNotificationResponse,
        UNUserNotificationCenter, UNUserNotificationCenterDelegate,
    };
    use signer_core::approval::{ApprovalDecision, ApprovalRequest};
    use std::sync::Arc;

    use super::{
        NotificationApprover, RequestId, ACTION_ALWAYS, ACTION_APPROVE, ACTION_REJECT, CATEGORY,
        LOCKED,
    };
    use super::{PaymentAction, PaymentPrompt, ACTION_DECLINE, ACTION_PAY, PAYMENT_CATEGORY};

    static APPROVER: OnceLock<Arc<NotificationApprover>> = OnceLock::new();
    static DELEGATE: OnceLock<Retained<ResponseHandler>> = OnceLock::new();
    type PaymentHandler = dyn Fn(&str, PaymentAction) + Send + Sync;
    static PAYMENT_HANDLER: OnceLock<Box<PaymentHandler>> = OnceLock::new();

    pub fn install_payment_handler(handler: impl Fn(&str, PaymentAction) + Send + Sync + 'static) {
        let _ = PAYMENT_HANDLER.set(Box::new(handler));
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "CashrNotificationDelegate"]
        struct ResponseHandler;

        unsafe impl NSObjectProtocol for ResponseHandler {}

        unsafe impl UNUserNotificationCenterDelegate for ResponseHandler {
            #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
            fn will_present(
                &self,
                _center: &UNUserNotificationCenter,
                _notification: &UNNotification,
                completion: &DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
            ) {
                completion.call((UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List,));
            }

            #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
            fn did_receive_response(
                &self,
                _center: &UNUserNotificationCenter,
                response: &UNNotificationResponse,
                completion: &DynBlock<dyn Fn()>,
            ) {
                handle_response(response);
                completion.call(());
            }
        }
    );

    fn handle_response(response: &UNNotificationResponse) {
        let Some(approver) = APPROVER.get() else {
            return;
        };

        let action = response.actionIdentifier().to_string();
        let identifier = response.notification().request().identifier().to_string();
        if let Some(id) = identifier.strip_prefix("payment:") {
            if let (Some(handler), Some(action)) =
                (PAYMENT_HANDLER.get(), super::payment_action(&action))
            {
                handler(id, action);
            }
            return;
        }
        let Some(id) = RequestId::parse(&identifier) else {
            return;
        };

        // Reject is once, not always: a client that asked for something odd
        // one time should not lose the ability to ask again because the answer
        // was given from a banner. Saying no forever is in the window.
        let decision = match action.as_str() {
            ACTION_APPROVE => ApprovalDecision::allow_once(),
            ACTION_ALWAYS => ApprovalDecision::allow_always(),
            ACTION_REJECT => ApprovalDecision::deny(),
            // The default action is a tap on the body, which opens the window
            // rather than deciding anything.
            _ => return,
        };

        approver.resolve(id, decision);
    }

    /// Ask for permission, register the Approve/Reject category, and route
    /// responses back into `approver`.
    ///
    /// Only works from a signed, bundled app with a real bundle identifier.
    /// From a bare binary the center is unavailable and nothing posts.
    pub fn install(approver: Arc<NotificationApprover>) {
        let _ = APPROVER.set(approver);

        let center = UNUserNotificationCenter::currentNotificationCenter();

        let approve = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(ACTION_APPROVE),
            &NSString::from_str("Approve"),
            UNNotificationActionOptions::empty(),
        );
        let always = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(ACTION_ALWAYS),
            &NSString::from_str("Always allow"),
            UNNotificationActionOptions::empty(),
        );
        let reject = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(ACTION_REJECT),
            &NSString::from_str("Reject"),
            UNNotificationActionOptions::Destructive,
        );

        // Order matters. A banner shows the first action as its button and
        // folds the rest into the Options menu, so Approve is first: it is the
        // answer most requests get, and it is the one that should not need a
        // second click. An alert shows all three.
        let actions = NSArray::from_retained_slice(&[approve, always, reject]);
        let category =
            UNNotificationCategory::categoryWithIdentifier_actions_intentIdentifiers_options(
                &NSString::from_str(CATEGORY),
                &actions,
                &NSArray::new(),
                UNNotificationCategoryOptions::empty(),
            );
        let pay = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(ACTION_PAY),
            &NSString::from_str("Approve & pay"),
            UNNotificationActionOptions::AuthenticationRequired,
        );
        let decline = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(ACTION_DECLINE),
            &NSString::from_str("Decline"),
            UNNotificationActionOptions::Destructive,
        );
        let payment_category =
            UNNotificationCategory::categoryWithIdentifier_actions_intentIdentifiers_options(
                &NSString::from_str(PAYMENT_CATEGORY),
                &NSArray::from_retained_slice(&[pay, decline]),
                &NSArray::new(),
                UNNotificationCategoryOptions::empty(),
            );
        center
            .setNotificationCategories(&NSSet::from_retained_slice(&[category, payment_category]));

        // The delegate is kept in a `OnceLock` for the life of the process,
        // which is what `setDelegate` needs: the center does not retain it.
        let delegate = DELEGATE.get_or_init(new_response_handler);
        center.setDelegate(Some(ProtocolObject::from_ref(&**delegate)));

        let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
        let handler = RcBlock::new(|granted: Bool, _error: *mut NSError| {
            if !granted.as_bool() {
                tracing::warn!(
                    "notification permission refused; prompts will only appear in the window"
                );
            }
        });
        center.requestAuthorizationWithOptions_completionHandler(options, &handler);
    }

    pub(super) fn post(id: RequestId, request: &ApprovalRequest) -> Result<(), String> {
        if APPROVER.get().is_none() {
            return Err("notification delegate is not installed".to_string());
        }

        let name = request
            .client_name
            .clone()
            .unwrap_or_else(|| short_key(&request.client_public_key.to_hex()));

        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&format!(
            "{name} wants to {}",
            request.detail
        )));
        content.setBody(&NSString::from_str(&format!(
            "Account: {}",
            request.account_label
        )));
        content.setCategoryIdentifier(&NSString::from_str(CATEGORY));

        let notification = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(&id.to_string()),
            &content,
            None,
        );

        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&notification, None);

        Ok(())
    }

    pub(super) fn post_locked(account_label: &str) {
        if APPROVER.get().is_none() {
            return;
        }

        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str("Cashr is locked"));
        content.setBody(&NSString::from_str(&format!(
            "A request for {account_label} is waiting. Unlock to answer it."
        )));

        let notification = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(LOCKED),
            &content,
            None,
        );

        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&notification, None);
    }

    pub(super) fn post_payment(prompt: &PaymentPrompt<'_>) {
        if APPROVER.get().is_none() || PAYMENT_HANDLER.get().is_none() {
            tracing::warn!("payment notification handler is not installed");
            return;
        }
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&format!(
            "{} requests {} sats",
            prompt.app, prompt.amount
        )));
        content.setBody(&NSString::from_str(&format!(
            "Account: {} · Max fee {} sats · Total up to {} sats",
            prompt.account, prompt.max_fee, prompt.maximum
        )));
        content.setCategoryIdentifier(&NSString::from_str(PAYMENT_CATEGORY));
        let notification = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(&format!("payment:{}", prompt.id)),
            &content,
            None,
        );
        let handler = RcBlock::new(|error: *mut NSError| {
            if !error.is_null() {
                tracing::warn!("could not post payment notification; review it in Cashr");
            }
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&notification, Some(&handler));
    }

    pub(super) fn withdraw_payment(identifier: &str) {
        if APPROVER.get().is_none() {
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let identifiers = NSArray::from_retained_slice(&[NSString::from_str(identifier)]);
        center.removeDeliveredNotificationsWithIdentifiers(&identifiers);
        center.removePendingNotificationRequestsWithIdentifiers(&identifiers);
    }

    pub(super) fn clear_locked() {
        if APPROVER.get().is_none() {
            return;
        }

        let center = UNUserNotificationCenter::currentNotificationCenter();
        let identifiers = NSArray::from_retained_slice(&[NSString::from_str(LOCKED)]);
        center.removeDeliveredNotificationsWithIdentifiers(&identifiers);
        center.removePendingNotificationRequestsWithIdentifiers(&identifiers);
    }

    /// Pull a notification back once its request is answered or expired, so
    /// Notification Center does not keep offering a decision that goes
    /// nowhere.
    pub(super) fn withdraw(id: RequestId) {
        if APPROVER.get().is_none() {
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let identifiers = NSArray::from_retained_slice(&[NSString::from_str(&id.to_string())]);
        center.removeDeliveredNotificationsWithIdentifiers(&identifiers);
        center.removePendingNotificationRequestsWithIdentifiers(&identifiers);
    }

    /// Allocate and initialise the delegate.
    ///
    /// This is the only unsafe call outside the class definition itself.
    /// Objective-C has no safe way to send `init`: `define_class!` builds the
    /// class, and something has to make the first instance of it.
    fn new_response_handler() -> Retained<ResponseHandler> {
        let this = ResponseHandler::alloc().set_ivars(());
        // SAFETY: `init` on a freshly allocated instance of a class that
        // declares NSObject as its superclass, so NSObject's implementation
        // applies and the object is fully initialised on return.
        unsafe { msg_send![super(this), init] }
    }

    fn short_key(hex: &str) -> String {
        format!(
            "{}…{}",
            &hex[..8.min(hex.len())],
            &hex[hex.len().saturating_sub(4)..]
        )
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::sync::Arc;

    use signer_core::approval::ApprovalRequest;

    use super::{NotificationApprover, RequestId};

    /// Off a Mac the registry still works, so prompts surface wherever the UI
    /// reads `pending()`. Nothing is posted.
    pub fn install(_approver: Arc<NotificationApprover>) {}

    pub fn install_payment_handler(
        _handler: impl Fn(&str, super::PaymentAction) + Send + Sync + 'static,
    ) {
    }

    pub(super) fn post_payment(_prompt: &super::PaymentPrompt<'_>) {}

    pub(super) fn withdraw_payment(_identifier: &str) {}

    pub(super) fn post(_id: RequestId, _request: &ApprovalRequest) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn post_locked(_account_label: &str) {}

    pub(super) fn clear_locked() {}

    pub(super) fn withdraw(_id: RequestId) {}
}

pub use platform::{install, install_payment_handler};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_actions_require_explicit_payment_approval() {
        assert_eq!(payment_action(ACTION_PAY), Some(PaymentAction::Approve));
        assert_eq!(payment_action(ACTION_DECLINE), Some(PaymentAction::Decline));
        assert_eq!(
            payment_action("com.apple.UNNotificationDefaultActionIdentifier"),
            Some(PaymentAction::Open)
        );
        for action in [
            ACTION_APPROVE,
            ACTION_ALWAYS,
            ACTION_REJECT,
            "",
            "unknown",
            "com.apple.UNNotificationDismissActionIdentifier",
        ] {
            assert_eq!(payment_action(action), None);
        }
    }
}
