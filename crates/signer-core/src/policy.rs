//! Permission rules and how a request is matched against them.
//!
//! A rule is scoped to a client, a method, and (for `sign_event` only) an event
//! kind. Matching is most-specific-first: an exact kind rule beats a
//! method-wide rule, and no match at all means the user is asked.

use nostr::event::Kind;
use nostr::nips::nip46::NostrConnectMethod;

/// A stored answer to "may this client do this".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// The result of consulting the stored rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
    /// No rule covers this. Ask the user.
    Prompt,
}

/// What a rule covers, and what a request needs covered.
///
/// `kind` is only meaningful for [`NostrConnectMethod::SignEvent`]. `None` on a
/// rule means "any kind"; `None` on a request means the method does not carry
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope {
    pub method: NostrConnectMethod,
    pub kind: Option<Kind>,
}

impl Scope {
    pub fn method(method: NostrConnectMethod) -> Self {
        Self { method, kind: None }
    }

    pub fn sign_event(kind: Kind) -> Self {
        Self {
            method: NostrConnectMethod::SignEvent,
            kind: Some(kind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub scope: Scope,
    pub decision: Decision,
}

impl Rule {
    pub fn new(scope: Scope, decision: Decision) -> Self {
        Self { scope, decision }
    }
}

/// Every rule stored for one client on one account.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    rules: Vec<Rule>,
}

impl PolicySet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Match `request` against the rules, most specific first.
    pub fn evaluate(&self, request: Scope) -> Outcome {
        if request.kind.is_some() {
            if let Some(rule) = self.find(request.method, request.kind) {
                return rule.decision.into();
            }
        }

        match self.find(request.method, None) {
            Some(rule) => rule.decision.into(),
            None => Outcome::Prompt,
        }
    }

    fn find(&self, method: NostrConnectMethod, kind: Option<Kind>) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| rule.scope.method == method && rule.scope.kind == kind)
    }
}

impl From<Decision> for Outcome {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow => Outcome::Allow,
            Decision::Deny => Outcome::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rules: &[(Scope, Decision)]) -> PolicySet {
        PolicySet::new(rules.iter().map(|(s, d)| Rule::new(*s, *d)).collect())
    }

    #[test]
    fn no_rules_prompts() {
        let policy = PolicySet::default();
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::TextNote)),
            Outcome::Prompt
        );
    }

    #[test]
    fn method_wide_rule_covers_any_kind() {
        let policy = set(&[(
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )]);
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::TextNote)),
            Outcome::Allow
        );
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::EncryptedDirectMessage)),
            Outcome::Allow
        );
    }

    #[test]
    fn kind_rule_beats_method_wide_rule() {
        let policy = set(&[
            (
                Scope::method(NostrConnectMethod::SignEvent),
                Decision::Allow,
            ),
            (
                Scope::sign_event(Kind::EncryptedDirectMessage),
                Decision::Deny,
            ),
        ]);
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::EncryptedDirectMessage)),
            Outcome::Deny
        );
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::TextNote)),
            Outcome::Allow
        );
    }

    #[test]
    fn kind_rule_alone_does_not_cover_other_kinds() {
        let policy = set(&[(Scope::sign_event(Kind::TextNote), Decision::Allow)]);
        assert_eq!(
            policy.evaluate(Scope::sign_event(Kind::EncryptedDirectMessage)),
            Outcome::Prompt
        );
    }

    #[test]
    fn rules_do_not_leak_across_methods() {
        let policy = set(&[(
            Scope::method(NostrConnectMethod::SignEvent),
            Decision::Allow,
        )]);
        assert_eq!(
            policy.evaluate(Scope::method(NostrConnectMethod::Nip44Decrypt)),
            Outcome::Prompt
        );
    }

    #[test]
    fn non_sign_methods_match_the_method_wide_rule() {
        let policy = set(&[(
            Scope::method(NostrConnectMethod::Nip44Decrypt),
            Decision::Allow,
        )]);
        assert_eq!(
            policy.evaluate(Scope::method(NostrConnectMethod::Nip44Decrypt)),
            Outcome::Allow
        );
    }
}
