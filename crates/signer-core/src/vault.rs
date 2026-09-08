//! Unlocked key material and the operations that use it.
//!
//! Keys are never handed out. Callers ask the vault to sign or decrypt, so a
//! copy of a secret key does not spread through the crate, and locking is a
//! single place that actually takes effect.

use std::collections::HashMap;
use std::fmt;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use nostr::event::{Event, FinalizeEvent, SignEvent, UnsignedEvent};
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip04::Nip04;
use nostr::nips::nip42::ClientAuthentication;
use nostr::nips::nip44::Nip44;
use nostr::nips::nip46::{NostrConnectEventBuilder, NostrConnectMessage};
use nostr::types::RelayUrl;

use crate::account::AccountId;
use crate::error::{Result, SignerError};
use crate::keystore::{KeyHandle, KeyRole, KeyStore};

/// Domain-separated database encryption material; not the Cashu spending seed.
pub fn wallet_storage_seed(keys: &Keys) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hash = Sha512::new();
    hash.update(b"byrgi/cashu/wallet-seed/v1\0");
    hash.update(keys.secret_key().as_secret_bytes());
    hash.finalize().into()
}

/// One account's two unlocked keys.
struct AccountKeys {
    identity: Keys,
    transport: Keys,
}

impl fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: a stray `{:?}` on anything holding this must
        // not be able to print key material.
        f.write_str("AccountKeys(<unlocked>)")
    }
}

/// Which key an operation uses.
///
/// The identity key signs the user's events. The transport key only ever
/// signs NIP-46 envelopes and relay authentication, keeping the identity private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Identity,
    Transport,
}

#[derive(Debug, Default)]
pub struct Vault {
    accounts: RwLock<HashMap<AccountId, AccountKeys>>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every account's keys. One call, so a Keychain backend can ask the
    /// user for Touch ID once rather than twice per account.
    pub async fn unlock<S>(&self, store: &S, accounts: &[AccountId]) -> Result<()>
    where
        S: KeyStore + ?Sized,
    {
        let mut handles = Vec::with_capacity(accounts.len() * 2);
        for account in accounts {
            handles.push(KeyHandle::new(*account, KeyRole::Identity));
            handles.push(KeyHandle::new(*account, KeyRole::Transport));
        }

        let keys = store.load_many(&handles).await?;
        if keys.len() != handles.len() {
            return Err(SignerError::Crypto(
                "keystore returned the wrong number of keys".to_string(),
            ));
        }

        let mut unlocked = self.write();
        for (account, pair) in accounts.iter().zip(keys.chunks_exact(2)) {
            unlocked.insert(
                *account,
                AccountKeys {
                    identity: pair[0].clone(),
                    transport: pair[1].clone(),
                },
            );
        }

        Ok(())
    }

    /// Drop all key material. The `SecretKey` destructor erases the bytes.
    pub fn lock(&self) {
        self.write().clear();
    }

    /// Drop one account's keys without locking the other accounts.
    pub fn forget(&self, account: AccountId) {
        self.write().remove(&account);
    }

    pub fn is_unlocked(&self) -> bool {
        !self.read().is_empty()
    }

    pub fn holds(&self, account: AccountId) -> bool {
        self.read().contains_key(&account)
    }

    /// Derive the database encryption material without exposing the Nostr key.
    pub fn wallet_storage_seed(&self, account: AccountId) -> Result<[u8; 64]> {
        self.with(account, Which::Identity, |keys| {
            Ok(wallet_storage_seed(keys))
        })
    }

    pub fn identity_public_key(&self, account: AccountId) -> Result<PublicKey> {
        self.with(account, Which::Identity, |keys| Ok(keys.public_key()))
    }

    pub fn transport_public_key(&self, account: AccountId) -> Result<PublicKey> {
        self.with(account, Which::Transport, |keys| Ok(keys.public_key()))
    }

    pub fn sign_event(&self, account: AccountId, unsigned: UnsignedEvent) -> Result<Event> {
        self.with(account, Which::Identity, |keys| {
            keys.sign_event(unsigned).map_err(crypto)
        })
    }

    /// Authenticate only the transport identity to a configured relay.
    pub fn sign_relay_auth(
        &self,
        account: AccountId,
        relay: &RelayUrl,
        challenge: &str,
    ) -> Result<Event> {
        self.with(account, Which::Transport, |keys| {
            ClientAuthentication::new(challenge, relay.clone())
                .finalize(keys)
                .map_err(crypto)
        })
    }

    pub fn nip04_encrypt(
        &self,
        account: AccountId,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.with(account, Which::Identity, |keys| {
            keys.nip04_encrypt(peer, plaintext).map_err(crypto)
        })
    }

    pub fn nip04_decrypt(
        &self,
        account: AccountId,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.with(account, Which::Identity, |keys| {
            keys.nip04_decrypt(peer, ciphertext).map_err(crypto)
        })
    }

    pub fn nip44_encrypt(
        &self,
        account: AccountId,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.with(account, Which::Identity, |keys| {
            keys.nip44_encrypt(peer, plaintext).map_err(crypto)
        })
    }

    pub fn nip44_decrypt(
        &self,
        account: AccountId,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.with(account, Which::Identity, |keys| {
            keys.nip44_decrypt(peer, ciphertext).map_err(crypto)
        })
    }

    /// Open a NIP-46 envelope addressed to the account's transport key.
    ///
    /// NIP-44 first, NIP-04 second: the spec moved to NIP-44 but clients in
    /// the wild still send the old form, and a signer that refuses them is a
    /// signer that silently does nothing.
    pub fn open_envelope(
        &self,
        account: AccountId,
        sender: &PublicKey,
        payload: &str,
    ) -> Result<String> {
        self.with(account, Which::Transport, |keys| {
            match keys.nip44_decrypt(sender, payload) {
                Ok(plaintext) => Ok(plaintext),
                Err(_) => keys.nip04_decrypt(sender, payload).map_err(crypto),
            }
        })
    }

    /// Build the signed, encrypted kind 24133 event carrying `message`.
    pub fn seal_envelope(
        &self,
        account: AccountId,
        receiver: PublicKey,
        message: NostrConnectMessage,
    ) -> Result<Event> {
        self.with(account, Which::Transport, |keys| {
            NostrConnectEventBuilder::new(receiver, message)
                .finalize(keys)
                .map_err(crypto)
        })
    }

    fn with<T, F>(&self, account: AccountId, which: Which, f: F) -> Result<T>
    where
        F: FnOnce(&Keys) -> Result<T>,
    {
        let unlocked = self.read();
        let entry = unlocked.get(&account).ok_or(SignerError::Locked)?;
        match which {
            Which::Identity => f(&entry.identity),
            Which::Transport => f(&entry.transport),
        }
    }

    /// A poisoned lock means a panic elsewhere. The map is still valid, and
    /// refusing every signature afterwards helps nobody.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<AccountId, AccountKeys>> {
        self.accounts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<AccountId, AccountKeys>> {
        self.accounts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn crypto<E: std::fmt::Display>(error: E) -> SignerError {
    SignerError::Crypto(error.to_string())
}

#[cfg(test)]
mod tests {
    use nostr::nips::nip42::is_valid_auth_event;

    use super::*;

    #[test]
    fn forgetting_an_account_revokes_its_keys_without_locking_others() {
        let vault = Vault::new();
        let deleted = AccountId::new(1);
        let remaining = AccountId::new(2);
        for account in [deleted, remaining] {
            vault.write().insert(
                account,
                AccountKeys {
                    identity: Keys::generate(),
                    transport: Keys::generate(),
                },
            );
        }
        let retained_seed = vault.wallet_storage_seed(remaining).unwrap();
        vault.forget(deleted);
        assert!(!vault.holds(deleted));
        assert!(vault.wallet_storage_seed(deleted).is_err());
        assert!(vault
            .sign_relay_auth(
                deleted,
                &RelayUrl::parse("wss://relay.example").unwrap(),
                "challenge"
            )
            .is_err());
        assert_eq!(vault.wallet_storage_seed(remaining).unwrap(), retained_seed);
        vault.forget(deleted);
    }

    #[test]
    fn wallet_seed_is_stable_separate_from_identity_and_unavailable_when_locked() {
        let vault = Vault::new();
        let account = AccountId::new(1);
        let identity = Keys::generate();
        vault.write().insert(
            account,
            AccountKeys {
                identity: identity.clone(),
                transport: Keys::generate(),
            },
        );
        let seed = vault.wallet_storage_seed(account).unwrap();
        assert_eq!(seed, vault.wallet_storage_seed(account).unwrap());
        assert_ne!(&seed[..32], identity.secret_key().as_secret_bytes());
        assert!(vault.wallet_storage_seed(AccountId::new(2)).is_err());
        vault.lock();
        assert!(vault.wallet_storage_seed(account).is_err());
    }

    #[test]
    fn relay_auth_uses_transport_key_and_binds_relay_and_challenge() {
        let vault = Vault::new();
        let account = AccountId::new(1);
        let identity = Keys::generate();
        let transport = Keys::generate();
        vault.write().insert(
            account,
            AccountKeys {
                identity: identity.clone(),
                transport: transport.clone(),
            },
        );
        let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
        let event = vault.sign_relay_auth(account, &relay, "challenge").unwrap();
        assert_eq!(event.pubkey, transport.public_key());
        assert_ne!(event.pubkey, identity.public_key());
        assert!(is_valid_auth_event(&event, &relay, "challenge"));
        assert!(!is_valid_auth_event(&event, &relay, "other"));
        let other = RelayUrl::parse("wss://other.example.com").unwrap();
        assert!(!is_valid_auth_event(&event, &other, "challenge"));
        vault.lock();
        assert!(matches!(
            vault.sign_relay_auth(account, &relay, "challenge"),
            Err(SignerError::Locked)
        ));
    }
}
