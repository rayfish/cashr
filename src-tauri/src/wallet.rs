//! Cashu wallet operations stay in Rust. The webview sees invoices and balances,
//! never raw seeds or spendable proofs. Recovery words are revealed only by an
//! explicit backup request on an unlocked account. Databases are encrypted.
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Context, Result};
use cdk::nuts::{CurrencyUnit, PaymentMethod, Token};
use cdk::wallet::{ReceiveOptions, SendOptions, Wallet};
use cdk_sqlite::WalletSqliteDatabase;
use lightning_invoice::{Bolt11Invoice, Currency};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::account::AccountId;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::state::AppState;

pub const MINT: &str = "https://mint.minibits.cash/Bitcoin";

#[derive(Debug)]
enum WalletFailure {
    Missing,
    Storage,
    Sync,
    Recovery,
    RecoveryIdentity,
}

impl std::fmt::Display for WalletFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "Create or restore a wallet in Settings.",
            Self::Storage => "Could not read the saved wallet.",
            Self::Sync => "Mint sync failed. Retrying…",
            Self::Recovery => "Fund recovery interrupted. Retrying…",
            Self::RecoveryIdentity => "Recovery words do not match this wallet.",
        })
    }
}

impl std::error::Error for WalletFailure {}

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::cdk_database::WalletDatabase;

    #[test]
    fn wallet_errors_are_concise_and_do_not_expose_sdk_details() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let missing = error(original_material(&path, &[7; 64]).unwrap_err());
        assert_eq!(missing, "Create or restore a wallet in Settings.");
        assert!(!path.exists());
        assert!(
            !error(anyhow!("SDK error with secret-token-fixture")).contains("secret-token-fixture")
        );
    }

    const WORDS: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";

    #[test]
    fn one_phrase_recovers_cashu_and_the_nip06_identity() {
        let identity = identity_from_phrase(WORDS, "").unwrap();
        assert_eq!(
            identity.public_key().to_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );
        assert_eq!(
            identity.secret_key().to_secret_hex(),
            "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"
        );
        let generated = new_mnemonic().unwrap();
        assert_eq!(generated.split_whitespace().count(), 12);
        let original = identity_from_phrase(&generated, "").unwrap();
        let restored = identity_from_phrase(&generated, "").unwrap();
        assert_eq!(original.public_key(), restored.public_key());
        assert_ne!(
            *import_seed(&generated, "").unwrap(),
            signer_core::vault::wallet_storage_seed(&original)
        );
    }

    #[test]
    fn recovery_passphrase_changes_both_keys_and_normalizes_unicode() {
        let plain = identity_from_phrase(WORDS, "").unwrap();
        let composed = identity_from_phrase(WORDS, "caf\u{e9}").unwrap();
        let decomposed = identity_from_phrase(WORDS, "cafe\u{301}").unwrap();
        assert_ne!(plain.public_key(), composed.public_key());
        assert_eq!(composed.public_key(), decomposed.public_key());
        assert_ne!(
            *import_seed(WORDS, "").unwrap(),
            *import_seed(WORDS, "caf\u{e9}").unwrap()
        );
        assert_eq!(
            *import_seed(WORDS, "caf\u{e9}").unwrap(),
            *import_seed(WORDS, "cafe\u{301}").unwrap()
        );
    }

    #[tokio::test]
    async fn restoring_and_switching_mints_preserve_seed_backup_and_wallet_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let seed = import_seed(WORDS, "").unwrap();
        let identity = identity_from_phrase(WORDS, "").unwrap();
        let storage = signer_core::vault::wallet_storage_seed(&identity);
        initialize_wallet(&path, &storage, &seed, WORDS, false, MINT)
            .await
            .unwrap();
        let wallet = open_path(path.clone(), &storage, false).await.unwrap();
        wallet
            .localstore
            .add_mint("https://saved.example".parse().unwrap(), None)
            .await
            .unwrap();
        let keyset = "00916bbf7ef91a36".parse().unwrap();
        assert_eq!(
            wallet
                .localstore
                .increment_keyset_counter(&keyset, 17)
                .await
                .unwrap(),
            17
        );
        drop(wallet);
        initialize_wallet(
            &path,
            &storage,
            &seed,
            WORDS,
            false,
            "https://another.example",
        )
        .await
        .unwrap();
        let wallet = open_path(path.clone(), &storage, false).await.unwrap();
        assert_eq!(
            wallet
                .localstore
                .increment_keyset_counter(&keyset, 0)
                .await
                .unwrap(),
            17
        );
        assert_eq!(wallet.mint_url.to_string(), MINT);
        assert!(wallet
            .localstore
            .get_mints()
            .await
            .unwrap()
            .contains_key(&"https://saved.example".parse().unwrap()));
        drop(wallet);
        let slot = mint_slot(&path, &storage, "https://another.example")
            .await
            .unwrap();
        select_slot(&path, &slot).unwrap();
        let other_path = slot_path(&path, &slot).unwrap();
        assert_eq!(
            *wallet_profile(&other_path, database_password(&storage).as_str())
                .unwrap()
                .0,
            *seed
        );
        let (backup, required) = read_recovery(&other_path, &storage).unwrap();
        assert_eq!(backup.as_str(), WORDS);
        assert!(!required);
        assert_eq!(
            identity_from_phrase(&backup, "").unwrap().public_key(),
            identity.public_key()
        );
        assert_eq!(*import_seed(&backup, "").unwrap(), *seed);
        assert_eq!(mint_slot(&path, &storage, MINT).await.unwrap(), "original");
        assert_eq!(wallet_choices(&path, &storage).unwrap().len(), 2);
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes
            .windows(WORDS.len())
            .any(|window| window == WORDS.as_bytes()));
        assert!(read_recovery(&path, &[9; 64]).is_err());
        assert!(
            initialize_wallet(&path, &storage, &[9; 64], WORDS, false, MINT)
                .await
                .is_err()
        );
        assert_eq!(*original_material(&path, &storage).unwrap().0, *seed);
    }

    #[test]
    fn imported_seed_matches_bip39_and_rejects_invalid_input() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = import_seed(words, "TREZOR").unwrap();
        let encoded: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(encoded, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
        assert_ne!(*seed, *import_seed(words, "").unwrap());
        assert!(import_seed("abandon abandon", "").is_err());
        assert!(import_seed(&"abandon ".repeat(12), "").is_err());
        assert_eq!(
            import_mint(" https://Mint.Example/cashu/ ").unwrap(),
            "https://mint.example/cashu"
        );
        for value in [
            "http://mint.example",
            "https://user:secret@mint.example",
            "https://mint.example/?key=secret",
            "https://mint.example/#fragment",
        ] {
            assert!(import_mint(value).is_err());
        }
        assert!(slot_path(std::path::Path::new("wallet.sqlite"), "../another").is_err());
    }

    #[test]
    fn locking_invalidates_payment_reviews() {
        let service = WalletService::default();
        service.approvals.lock().unwrap().insert(
            "quote".into(),
            Approval {
                account: 1,
                invoice: "invoice".into(),
                maximum: 100,
                expiry: now() + 60,
                epoch: 0,
            },
        );
        service.lock();
        assert!(service.approvals.lock().unwrap().is_empty());
        assert_eq!(service.epoch.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn malformed_invoices_are_rejected_before_network_requests() {
        for value in ["", "lnbc", "https://example.com", "cashuBtest"] {
            assert!(invoice(value).is_err());
        }
        assert!(invoice(&"x".repeat(16_385)).is_err());
    }

    #[test]
    fn zap_invoice_must_match_both_amount_and_signed_request() {
        use lightning_invoice::{InvoiceBuilder, PaymentSecret};
        let request = "signed zap fixture";
        let key = cdk::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let payment = InvoiceBuilder::new(Currency::Bitcoin)
            .description_hash(format!("{:x}", Sha256::digest(request)).parse().unwrap())
            .payment_hash("11".repeat(32).parse().unwrap())
            .payment_secret(PaymentSecret([42; 32]))
            .amount_milli_satoshis(21_000)
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .build_signed(|hash| {
                cdk::secp256k1::Secp256k1::new().sign_ecdsa_recoverable(hash, &key)
            })
            .unwrap()
            .to_string();
        assert!(check_zap_invoice(&payment, request, 21_000).is_ok());
        assert!(check_zap_invoice(&payment, "another signed request", 21_000).is_err());
        assert!(check_zap_invoice(&payment, request, 22_000).is_err());
    }

    #[tokio::test]
    async fn wallet_database_is_encrypted_and_survives_reopening() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let mint = MINT.parse().unwrap();
        {
            let db = WalletSqliteDatabase::new((path.clone(), "test-encryption-key".into()))
                .await
                .unwrap();
            db.add_mint(mint, None).await.unwrap();
            let wallet = Wallet::new(MINT, CurrencyUnit::Sat, Arc::new(db), [7; 64], None).unwrap();
            assert_eq!(view(&wallet).await.unwrap().balance, 0);
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(!bytes
            .windows(MINT.len())
            .any(|window| window == MINT.as_bytes()));
        let db = WalletSqliteDatabase::new((path.clone(), "test-encryption-key".into()))
            .await
            .unwrap();
        assert!(db
            .get_mints()
            .await
            .unwrap()
            .contains_key(&MINT.parse().unwrap()));
        assert!(WalletSqliteDatabase::new((path, "wrong-key".into()))
            .await
            .is_err());
    }
}

#[derive(Default)]
pub struct WalletService {
    // A single gate also serializes imports, recovery, and confirmation so
    // no two commands can reserve or spend the same proofs concurrently.
    pub(crate) gate: tokio::sync::Mutex<()>,
    approvals: Mutex<HashMap<String, Approval>>,
    cashu_approvals: Mutex<HashMap<String, CashuApproval>>,
    epoch: AtomicU64,
}

struct Approval {
    account: i64,
    invoice: String,
    maximum: u64,
    expiry: u64,
    epoch: u64,
}

impl WalletService {
    pub fn lock(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.cashu_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[derive(Serialize)]
pub struct WalletView {
    mint: String,
    balance: u64,
    pending: u64,
    transactions: Vec<TransactionView>,
    funding_invoice: Option<String>,
    pending_tokens: Vec<PendingTokenView>,
}

#[derive(Serialize)]
struct TransactionView {
    amount: u64,
    fee: u64,
    direction: String,
    status: String,
    timestamp: u64,
}

#[derive(Serialize)]
pub struct InvoiceView {
    invoice: String,
    expiry: u64,
}

#[derive(Serialize)]
pub struct PaymentView {
    quote: String,
    amount: u64,
    max_fee: u64,
    maximum: u64,
    expiry: u64,
    destination: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn original_wallet_path(app: &AppHandle, state: &AppState, account: i64) -> Result<PathBuf> {
    let identity = state
        .storage
        .account(AccountId::new(account))?
        .identity_public_key;
    wallet_path_for_identity(app, identity)
}

fn wallet_path_for_identity(app: &AppHandle, identity: nostr::key::PublicKey) -> Result<PathBuf> {
    let dir = app.path().app_data_dir()?.join("wallets");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir.join(format!("{}.sqlite", identity.to_hex())))
}

async fn open(app: &AppHandle, state: &AppState, account: i64) -> Result<Wallet> {
    open_selected(app, state, account, false).await
}

async fn open_selected(
    app: &AppHandle,
    state: &AppState,
    account: i64,
    recover: bool,
) -> Result<Wallet> {
    let seed = Zeroizing::new(
        state
            .session
            .vault()
            .wallet_storage_seed(AccountId::new(account))?,
    );
    let original = original_wallet_path(app, state, account)?;
    let slot = selected_slot(&original)?;
    let path = slot_path(&original, &slot)?;
    let wallet = open_path(path.clone(), &seed, slot != "original").await?;
    if recover {
        recover_on_open(&wallet, &path, &seed).await?;
    }
    Ok(wallet)
}

fn recovery_scan(
    path: &std::path::Path,
    seed: &[u8; 64],
    complete: Option<bool>,
) -> Result<Option<bool>> {
    use rusqlite::OptionalExtension;
    let conn = rusqlite::Connection::open(path)?;
    conn.pragma_update(None, "key", database_password(seed).as_str())?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS cashr_recovery_scan (id INTEGER PRIMARY KEY CHECK(id = 1), complete INTEGER NOT NULL);")?;
    if let Some(complete) = complete {
        conn.execute(
            "INSERT OR REPLACE INTO cashr_recovery_scan VALUES (1, ?1)",
            [complete],
        )?;
    }
    Ok(conn
        .query_row(
            "SELECT complete FROM cashr_recovery_scan WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?)
}

async fn recover_on_open(wallet: &Wallet, path: &std::path::Path, seed: &[u8; 64]) -> Result<()> {
    let complete = recovery_scan(path, seed, None).context(WalletFailure::Storage)?;
    if complete == Some(true) {
        return Ok(());
    }
    // Wallets that already hold proofs have loaded their funds. An empty wallet
    // with no scan record still needs discovery, including earlier imports.
    let has_funds = wallet.total_balance().await? > 0.into()
        || wallet.total_pending_balance().await? > 0.into()
        || wallet.total_reserved_balance().await? > 0.into();
    if complete == Some(false) || !has_funds {
        // Persist before the network request so partial scans resume after a
        // restart instead of mistaking partially recovered proofs for completion.
        recovery_scan(path, seed, Some(false)).context(WalletFailure::Storage)?;
        wallet.restore().await.context(WalletFailure::Recovery)?;
    }
    recovery_scan(path, seed, Some(true)).context(WalletFailure::Storage)?;
    Ok(())
}

fn database_password(seed: &[u8; 64]) -> Zeroizing<String> {
    let mut hash = Sha256::new();
    hash.update(b"byrgi/cashu/database/v1\0");
    hash.update(&seed[..]);
    Zeroizing::new(format!("{:x}", hash.finalize()))
}

fn new_mnemonic() -> Result<Zeroizing<String>> {
    let entropy = nostr::key::Keys::generate();
    let phrase = Zeroizing::new(bip39::Mnemonic::from_entropy(
        &entropy.secret_key().as_secret_bytes()[..16],
    )?);
    Ok(Zeroizing::new(phrase.to_string()))
}

fn write_recovery(
    conn: &rusqlite::Connection,
    phrase: &str,
    passphrase_required: bool,
) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS byrgi_master_recovery (id INTEGER PRIMARY KEY CHECK(id = 1), phrase TEXT NOT NULL, passphrase_required INTEGER NOT NULL);")?;
    conn.execute(
        "INSERT OR REPLACE INTO byrgi_master_recovery VALUES (1, ?1, ?2)",
        rusqlite::params![phrase, passphrase_required],
    )?;
    Ok(())
}

fn read_recovery(
    path: &std::path::Path,
    identity_seed: &[u8; 64],
) -> Result<(Zeroizing<String>, bool)> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "key", database_password(identity_seed).as_str())?;
    Ok(conn.query_row(
        "SELECT phrase, passphrase_required FROM byrgi_master_recovery WHERE id = 1",
        [],
        |row| Ok((Zeroizing::new(row.get::<_, String>(0)?), row.get(1)?)),
    )?)
}

fn save_recovery(
    path: &std::path::Path,
    identity_seed: &[u8; 64],
    phrase: &str,
    passphrase_required: bool,
) -> Result<()> {
    let mut conn = rusqlite::Connection::open(path)?;
    conn.pragma_update(None, "key", database_password(identity_seed).as_str())?;
    let transaction = conn.transaction()?;
    write_recovery(&transaction, phrase, passphrase_required)?;
    transaction.commit()?;
    Ok(())
}

fn original_material(
    path: &std::path::Path,
    storage_seed: &[u8; 64],
) -> Result<(Zeroizing<[u8; 64]>, String)> {
    if !path.try_exists().context(WalletFailure::Storage)? {
        return Err(WalletFailure::Missing.into());
    }
    read_recovery(path, storage_seed).context(WalletFailure::Storage)?;
    wallet_profile(path, database_password(storage_seed).as_str())
}

fn wallet_profile(path: &std::path::Path, password: &str) -> Result<(Zeroizing<[u8; 64]>, String)> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context(WalletFailure::Storage)?;
    conn.pragma_update(None, "key", password)
        .context(WalletFailure::Storage)?;
    let (bytes, mint): (Vec<u8>, String) = conn
        .query_row(
            "SELECT seed, mint FROM byrgi_wallet_profile WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context(WalletFailure::Storage)?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 64 {
        return Err(WalletFailure::Storage.into());
    }
    let mut seed = Zeroizing::new([0; 64]);
    seed.copy_from_slice(&bytes);
    Ok((seed, mint))
}

async fn open_path(path: PathBuf, identity_seed: &[u8; 64], imported: bool) -> Result<Wallet> {
    let password = database_password(identity_seed);
    let (seed, mint) = if imported {
        wallet_profile(&path, password.as_str())?
    } else {
        original_material(&path, identity_seed)?
    };
    let db = WalletSqliteDatabase::new((path, password.to_string()))
        .await
        .context(WalletFailure::Storage)?;
    Ok(Wallet::new(
        &mint,
        CurrencyUnit::Sat,
        Arc::new(db),
        *seed,
        None,
    )?)
}

async fn view(wallet: &Wallet) -> Result<WalletView> {
    let mut transactions = wallet.list_transactions(None).await?;
    transactions.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));
    Ok(WalletView {
        pending_tokens: pending_tokens(wallet).await?,
        funding_invoice: wallet
            .localstore
            .get_unissued_mint_quotes()
            .await?
            .into_iter()
            .filter(|quote| quote.mint_url == wallet.mint_url && quote.expiry > now())
            .max_by_key(|quote| quote.expiry)
            .map(|quote| quote.request),
        mint: wallet.mint_url.to_string(),
        balance: wallet.total_balance().await?.into(),
        pending: (wallet.total_pending_balance().await? + wallet.total_reserved_balance().await?)
            .into(),
        transactions: transactions
            .into_iter()
            .take(30)
            .map(|tx| TransactionView {
                amount: tx.amount.into(),
                fee: tx.fee.into(),
                direction: format!("{:?}", tx.direction),
                status: format!("{:?}", tx.status),
                timestamp: tx.timestamp,
            })
            .collect(),
    })
}

#[tauri::command]
pub fn wallet_cancel(service: State<'_, WalletService>, account: i64) {
    service
        .cashu_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, approval| approval.account != account);
    service
        .approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, approval| approval.account != account);
}

fn error(error: anyhow::Error) -> String {
    // Avoid forwarding arbitrary SDK errors containing invoices or tokens.
    // Commands supply context suitable for the user instead.
    if let Some(failure) = error.downcast_ref::<WalletFailure>() {
        return failure.to_string();
    }
    if matches!(
        error.downcast_ref::<signer_core::error::SignerError>(),
        Some(signer_core::error::SignerError::Locked)
    ) {
        return "Unlock this account to use its wallet.".into();
    }
    "Wallet operation failed. Check your connection and available balance, then Refresh before retrying.".into()
}

#[tauri::command]
pub async fn wallet_open(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<WalletView, String> {
    let _guard = service.gate.lock().await;
    async {
        let wallet = open_selected(&app, &state, account, true).await?;
        // Recovery only resumes previously authorized operations.
        let report = wallet
            .recover_incomplete_sagas()
            .await
            .context(WalletFailure::Sync)?;
        if report.failed != 0 {
            return Err(WalletFailure::Sync.into());
        }
        wallet
            .finalize_pending_melts()
            .await
            .context(WalletFailure::Sync)?;
        wallet
            .mint_unissued_quotes()
            .await
            .context(WalletFailure::Sync)?;
        view(&wallet).await.context(WalletFailure::Storage)
    }
    .await
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_fund(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    amount: u64,
) -> Result<InvoiceView, String> {
    if !(1..=10_000).contains(&amount) {
        return Err("Enter an amount between 1 and 10,000 sats.".into());
    }
    let _guard = service.gate.lock().await;
    async {
        let wallet = open(&app, &state, account).await?;
        let quote = wallet
            .mint_quote(PaymentMethod::BOLT11, Some(amount.into()), None, None)
            .await?;
        Ok(InvoiceView {
            invoice: quote.request,
            expiry: quote.expiry,
        })
    }
    .await
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_receive(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    token: String,
) -> Result<WalletView, String> {
    if token.len() > 100_000 {
        return Err("This Cashu token is too large.".into());
    }
    let token = Zeroizing::new(token);
    let token = token.trim().strip_prefix("cashu:").unwrap_or(token.trim());
    let parsed = parse_token(token).map_err(|_| "Use a valid Cashu token denominated in sats.")?;
    let _guard = service.gate.lock().await;
    async {
        let wallet = open(&app, &state, account).await?;
        ensure!(
            parsed.mint_url()? == wallet.mint_url,
            "token belongs to a different mint"
        );
        wallet.receive(token, ReceiveOptions::default()).await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

fn invoice(value: &str) -> Result<Bolt11Invoice> {
    ensure!(value.len() <= 16_384, "invoice too long");
    let invoice = Bolt11Invoice::from_str(value)?;
    ensure!(
        invoice.currency() == Currency::Bitcoin,
        "use a mainnet invoice"
    );
    ensure!(!invoice.is_expired(), "invoice expired");
    ensure!(
        invoice
            .amount_milli_satoshis()
            .is_some_and(|amount| amount > 0 && amount <= 10_000_000),
        "invoice amount outside mint limits"
    );
    Ok(invoice)
}

async fn review(
    wallet: &Wallet,
    service: &WalletService,
    account: i64,
    request: String,
    destination: String,
    epoch: u64,
) -> Result<PaymentView> {
    invoice(&request)?;
    let quote = wallet
        .melt_quote(PaymentMethod::BOLT11, &request, None, None)
        .await?;
    let prepared = wallet.prepare_melt(&quote.id, HashMap::new()).await?;
    let amount: u64 = prepared.amount().into();
    let max_fee: u64 = (prepared.total_fee() + quote.fee_reserve).into();
    let maximum = amount
        .checked_add(max_fee)
        .ok_or_else(|| anyhow!("amount overflow"))?;
    prepared.cancel().await?;
    ensure!(quote.expiry > now(), "expired quote");
    let mut approvals = service.approvals.lock().unwrap_or_else(|e| e.into_inner());
    approvals.retain(|_, approval| approval.expiry > now() && approval.account != account);
    ensure!(
        epoch == service.epoch.load(Ordering::SeqCst),
        "wallet locked during review"
    );
    approvals.insert(
        quote.id.clone(),
        Approval {
            account,
            invoice: request,
            maximum,
            expiry: quote.expiry,
            epoch,
        },
    );
    Ok(PaymentView {
        quote: quote.id,
        amount,
        max_fee,
        maximum,
        expiry: quote.expiry,
        destination,
    })
}

#[tauri::command]
pub async fn wallet_review(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    request: String,
) -> Result<PaymentView, String> {
    let request = request.trim();
    let request = if request
        .get(..10)
        .is_some_and(|s| s.eq_ignore_ascii_case("lightning:"))
    {
        &request[10..]
    } else {
        request
    };
    invoice(request).map_err(|_| "Use a valid, unexpired mainnet invoice for 1–10,000 sats.")?;
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let wallet = open(&app, &state, account).await?;
        let destination = invoice(request)?.get_payee_pub_key().to_string();
        review(
            &wallet,
            &service,
            account,
            request.to_owned(),
            destination,
            epoch,
        )
        .await
    }
    .await
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_pay(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    quote: String,
) -> Result<WalletView, String> {
    let _guard = service.gate.lock().await;
    let approval = service
        .approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&quote)
        .ok_or("Review this payment again before paying.")?;
    if approval.account != account || approval.expiry <= now() {
        return Err("Payment review expired. Review it again.".into());
    }
    async {
        let wallet = open(&app, &state, account).await?;
        invoice(&approval.invoice)?;
        let prepared = wallet.prepare_melt(&quote, HashMap::new()).await?;
        let total: u64 =
            (prepared.amount() + prepared.total_fee() + prepared.quote().fee_reserve).into();
        if total > approval.maximum
            || prepared.quote().request != approval.invoice
            || !state.session.vault().holds(AccountId::new(account))
            || approval.epoch != service.epoch.load(Ordering::SeqCst)
        {
            prepared.cancel().await?;
            bail!("payment changed or wallet locked");
        }
        // Once confirmed, finish recording the result even if the user locks.
        // Dropping an in-flight Lightning request is not a cancellation.
        prepared.confirm().await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

/// Explicit seed recovery for a re-imported identity. Local SQLCipher data is
/// still the primary backup: seed recovery cannot recover every pending state.
#[tauri::command]
pub async fn wallet_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<WalletView, String> {
    let _guard = service.gate.lock().await;
    async {
        let seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let original = original_wallet_path(&app, &state, account)?;
        let path = slot_path(&original, &selected_slot(&original)?)?;
        recovery_scan(&path, &seed, Some(false)).context(WalletFailure::Storage)?;
        let wallet = open_selected(&app, &state, account, true).await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

/// Bound LNURL requests and pin DNS results to public IPv4 addresses. A
/// callback cannot redirect into services on the user's LAN or localhost.
async fn get_json(url: url::Url) -> Result<serde_json::Value> {
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443),
        "use a public HTTPS endpoint"
    );
    let host = url.host_str().ok_or_else(|| anyhow!("missing host"))?;
    let addresses: Vec<_> = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host, 443)),
    )
    .await??
    .filter(|address| match address.ip() {
        std::net::IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
                && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        _ => false,
    })
    .collect();
    ensure!(!addresses.is_empty(), "no public endpoint");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .resolve_to_addrs(host, &addresses)
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len() + chunk.len() <= 65_536, "response too large");
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[tauri::command]
pub async fn wallet_zap(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    zap: ZapInput,
) -> Result<PaymentView, String> {
    let ZapInput {
        address,
        recipient,
        amount,
        note,
    } = zap;
    use nostr::event::{EventBuilder, FinalizeUnsignedEvent, Kind, Tag};
    use nostr::key::PublicKey;
    if !(1..=10_000).contains(&amount) {
        return Err("Enter 1–10,000 sats.".into());
    }
    let recipient = PublicKey::parse(recipient.trim())
        .map_err(|_| "Enter the recipient’s npub or hex public key.")?;
    let address = address.trim();
    let (name, domain) = address
        .split_once('@')
        .ok_or("Enter a Lightning address.")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.+".contains(&c))
        || domain.is_empty()
        || !domain
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        || address.len() > 320
    {
        return Err("Enter a valid Lightning address.".into());
    }
    let note = note.trim();
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let wallet = open(&app, &state, account).await?;
        let metadata = get_json(url::Url::parse(&format!(
            "https://{domain}/.well-known/lnurlp/{name}"
        ))?)
        .await?;
        ensure!(
            metadata["allowsNostr"].as_bool() == Some(true),
            "provider does not support zaps"
        );
        PublicKey::from_hex(
            metadata["nostrPubkey"]
                .as_str()
                .ok_or_else(|| anyhow!("missing provider key"))?,
        )?;
        let millisats = amount * 1000;
        ensure!(
            metadata["minSendable"]
                .as_u64()
                .is_some_and(|min| min <= millisats)
                && metadata["maxSendable"]
                    .as_u64()
                    .is_some_and(|max| max >= millisats),
            "amount outside provider limits"
        );
        let identity = state.storage.account(AccountId::new(account))?;
        let mut tags = vec![
            Tag::parse(["p", &recipient.to_hex()])?,
            Tag::parse(["amount", &millisats.to_string()])?,
        ];
        let mut relays = vec!["relays".to_owned()];
        relays.extend(identity.relays.iter().map(ToString::to_string));
        ensure!(relays.len() > 1, "configure a relay before zapping");
        tags.push(Tag::parse(relays)?);
        if !note.is_empty() {
            ensure!(
                note.len() == 64 && note.bytes().all(|c| c.is_ascii_hexdigit()),
                "use a hex note event id"
            );
            tags.push(Tag::parse(["e", note])?);
        }
        let unsigned = EventBuilder::new(Kind::from_u16(9734), "")
            .tags(tags)
            .finalize_unsigned(identity.identity_public_key);
        let signed = state
            .session
            .vault()
            .sign_event(AccountId::new(account), unsigned)?;
        let request = serde_json::to_string(&signed)?;
        let mut callback = url::Url::parse(
            metadata["callback"]
                .as_str()
                .ok_or_else(|| anyhow!("missing callback"))?,
        )?;
        // Do not allow duplicate reserved parameters supplied by the provider.
        ensure!(
            !callback
                .query_pairs()
                .any(|(key, _)| key == "amount" || key == "nostr"),
            "invalid callback parameters"
        );
        callback
            .query_pairs_mut()
            .append_pair("amount", &millisats.to_string())
            .append_pair("nostr", &request);
        let response = get_json(callback).await?;
        let payment = response["pr"]
            .as_str()
            .ok_or_else(|| anyhow!("missing invoice"))?;
        check_zap_invoice(payment, &request, millisats)?;
        review(
            &wallet,
            &service,
            account,
            payment.to_owned(),
            format!("{address} · {}", recipient.to_hex()),
            epoch,
        )
        .await
    }
    .await
    .map_err(|_| {
        "Could not prepare the zap. Check the address, recipient, balance, and provider limits."
            .into()
    })
}

#[derive(Deserialize)]
pub struct ZapInput {
    address: String,
    recipient: String,
    amount: u64,
    note: String,
}

fn check_zap_invoice(payment: &str, request: &str, millisats: u64) -> Result<()> {
    let decoded = invoice(payment)?;
    ensure!(
        decoded.amount_milli_satoshis() == Some(millisats),
        "invoice amount differs from zap"
    );
    match decoded.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(hash) => ensure!(
            hash.0.to_string() == format!("{:x}", Sha256::digest(request.as_bytes())),
            "invoice not bound to zap request"
        ),
        _ => bail!("zap invoice must use a description hash"),
    }
    Ok(())
}

fn slot_path(original: &std::path::Path, slot: &str) -> Result<PathBuf> {
    if slot == "original" {
        return Ok(original.to_path_buf());
    }
    ensure!(
        slot.len() == 64 && slot.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid wallet selection"
    );
    Ok(original.with_extension(format!("{slot}.sqlite")))
}

fn selected_slot(original: &std::path::Path) -> Result<String> {
    match std::fs::read_to_string(original.with_extension("active")) {
        Ok(slot) => {
            slot_path(original, &slot)?;
            Ok(slot)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("original".into()),
        Err(error) => Err(error.into()),
    }
}

fn select_slot(original: &std::path::Path, slot: &str) -> Result<()> {
    slot_path(original, slot)?;
    let temporary = original.with_extension("active.tmp");
    std::fs::write(&temporary, slot)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(temporary, original.with_extension("active"))?;
    Ok(())
}

#[derive(Serialize)]
pub struct WalletList {
    active: String,
    wallets: Vec<WalletChoice>,
}

#[derive(Serialize)]
struct WalletChoice {
    id: String,
    label: String,
}

fn wallet_choices(original: &std::path::Path, seed: &[u8; 64]) -> Result<Vec<WalletChoice>> {
    let password = database_password(seed);
    let (account_seed, account_mint) = original_material(original, seed)?;
    let prefix = format!("{}.", original.file_stem().unwrap().to_string_lossy());
    let mut wallets = vec![WalletChoice {
        id: "original".into(),
        label: account_mint,
    }];
    for entry in std::fs::read_dir(original.parent().unwrap())? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(slot) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".sqlite"))
        {
            if slot.len() == 64 && slot.bytes().all(|c| c.is_ascii_hexdigit()) {
                let (wallet_seed, mint) = wallet_profile(&entry.path(), password.as_str())?;
                ensure!(*wallet_seed == *account_seed, "wallet seed mismatch");
                wallets.push(WalletChoice {
                    id: slot.into(),
                    label: mint,
                });
            }
        }
    }
    wallets[1..].sort_by(|a, b| a.id.cmp(&b.id));
    Ok(wallets)
}

#[tauri::command]
pub async fn wallet_list(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<WalletList, String> {
    let _guard = service.gate.lock().await;
    (|| -> Result<WalletList> {
        let seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let original = original_wallet_path(&app, &state, account)?;
        let wallets = wallet_choices(&original, &seed)?;
        Ok(WalletList {
            active: selected_slot(&original)?,
            wallets,
        })
    })()
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_select(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    slot: String,
) -> Result<WalletView, String> {
    let _guard = service.gate.lock().await;
    service.lock();
    async {
        let seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let original = original_wallet_path(&app, &state, account)?;
        let (root_seed, _) = original_material(&original, &seed)?;
        let (selected_seed, _) = wallet_profile(
            &slot_path(&original, &slot)?,
            database_password(&seed).as_str(),
        )?;
        ensure!(*root_seed == *selected_seed, "wallet seed mismatch");
        let path = slot_path(&original, &slot)?;
        let wallet = open_path(path.clone(), &seed, slot != "original").await?;
        select_slot(&original, &slot)?;
        recover_on_open(&wallet, &path, &seed).await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

async fn mint_slot(
    original: &std::path::Path,
    identity_seed: &[u8; 64],
    mint: &str,
) -> Result<String> {
    let password = database_password(identity_seed);
    let active = selected_slot(original)?;
    let (account_seed, account_mint) = original_material(original, identity_seed)?;
    let source_path = slot_path(original, &active)?;
    let seed = if active == "original" {
        Zeroizing::new(*account_seed)
    } else {
        wallet_profile(&slot_path(original, &active)?, password.as_str())?.0
    };
    ensure!(*seed == *account_seed, "wallet seed mismatch");
    if account_mint == mint {
        return Ok("original".into());
    }
    let slot = store_mint(original, identity_seed, &seed, mint).await?;
    let (phrase, required) = read_recovery(&source_path, identity_seed)?;
    save_recovery(
        &slot_path(original, &slot)?,
        identity_seed,
        &phrase,
        required,
    )?;
    Ok(slot)
}

#[tauri::command]
pub async fn wallet_set_mint(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    mint: String,
) -> Result<WalletView, String> {
    let mint = import_mint(&mint)
        .map_err(|_| "Enter the mint’s HTTPS URL without credentials or query parameters.")?;
    let _guard = service.gate.lock().await;
    service.lock();
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let original = original_wallet_path(&app, &state, account)?;
        let slot = mint_slot(&original, &seed, &mint).await?;
        let path = slot_path(&original, &slot)?;
        let wallet = open_path(path.clone(), &seed, slot != "original").await?;
        ensure!(
            epoch == service.epoch.load(Ordering::SeqCst),
            "wallet locked while selecting mint"
        );
        ensure!(
            state.session.vault().holds(AccountId::new(account)),
            "account locked while selecting mint"
        );
        select_slot(&original, &slot)?;
        recover_on_open(&wallet, &path, &seed).await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

fn import_seed(words: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    ensure!(
        words.len() <= 512 && passphrase.len() <= 1024,
        "recovery input too long"
    );
    let phrase = Zeroizing::new(bip39::Mnemonic::parse(words)?);
    Ok(Zeroizing::new(phrase.to_seed(passphrase)))
}

#[derive(Deserialize)]
pub struct WalletRecoveryInput {
    pub account: Option<i64>,
    pub mnemonic: String,
    pub passphrase: String,
    pub mint: String,
}

impl Drop for WalletRecoveryInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.mnemonic.zeroize();
        self.passphrase.zeroize();
    }
}

fn identity_from_phrase(words: &str, passphrase: &str) -> Result<nostr::key::Keys> {
    use nostr::nips::nip06::FromMnemonic;
    let phrase = Zeroizing::new(bip39::Mnemonic::parse(words)?);
    let words = Zeroizing::new(phrase.to_string());
    let mut normalized = std::borrow::Cow::Borrowed(passphrase);
    bip39::Mnemonic::normalize_utf8_cow(&mut normalized);
    let normalized = Zeroizing::new(normalized.into_owned());
    Ok(nostr::key::Keys::from_mnemonic(
        words.as_str(),
        Some(normalized.as_str()),
    )?)
}

async fn initialize_wallet(
    path: &std::path::Path,
    storage_seed: &[u8; 64],
    seed: &[u8; 64],
    words: &str,
    passphrase_required: bool,
    mint: &str,
) -> Result<()> {
    // A repeated restore keeps the original mint, proofs and derivation counters.
    let original_mint = if path.exists() {
        let (stored, mint) = original_material(path, storage_seed)?;
        ensure!(*stored == *seed, "wallet seed mismatch");
        mint
    } else {
        mint.to_owned()
    };
    store_wallet_file(path, storage_seed, seed, &original_mint).await?;
    save_recovery(path, storage_seed, words, passphrase_required)
}

pub async fn create_account(
    app: &AppHandle,
    state: &AppState,
    service: &WalletService,
    label: String,
    recovery: Option<WalletRecoveryInput>,
) -> Result<signer_core::account::Account> {
    let restoring = recovery.is_some();
    let recovery = match recovery {
        Some(recovery) => recovery,
        None => WalletRecoveryInput {
            account: None,
            mnemonic: new_mnemonic()?.to_string(),
            passphrase: String::new(),
            mint: MINT.into(),
        },
    };
    let seed = import_seed(&recovery.mnemonic, &recovery.passphrase)?;
    let mint = import_mint(&recovery.mint)?;
    let phrase = Zeroizing::new(bip39::Mnemonic::parse(&recovery.mnemonic)?);
    let words = Zeroizing::new(phrase.to_string());
    let identity = identity_from_phrase(&words, &recovery.passphrase)?;
    if let Some(account) = recovery.account {
        if state
            .storage
            .account(AccountId::new(account))?
            .identity_public_key
            != identity.public_key()
        {
            return Err(WalletFailure::RecoveryIdentity.into());
        }
    }
    let storage_seed = Zeroizing::new(signer_core::vault::wallet_storage_seed(&identity));
    let _guard = service.gate.lock().await;
    service.lock();
    let epoch = service.epoch.load(Ordering::SeqCst);
    if !state.has_passphrase() {
        state.prepare_touch_id().await?;
    }
    if epoch != service.epoch.load(Ordering::SeqCst) {
        state.lock();
        bail!("Unlock cancelled.");
    }
    let path = wallet_path_for_identity(app, identity.public_key())?;
    initialize_wallet(
        &path,
        &storage_seed,
        &seed,
        &words,
        !recovery.passphrase.is_empty(),
        &mint,
    )
    .await?;
    let slot = prepare_account_mint(&path, &storage_seed, &mint, restoring).await?;
    ensure!(
        epoch == service.epoch.load(Ordering::SeqCst) && state.has_passphrase(),
        "locked while restoring wallet"
    );
    let existing = state
        .accounts()?
        .into_iter()
        .find(|account| account.identity_public_key == identity.public_key());
    let account = match existing {
        Some(account) => {
            state.restore_account_keys(&account, &identity).await?;
            state.storage.account(account.id)?
        }
        None => state.add_account(label, identity).await?,
    };
    state.session.unlock(&[account.id]).await?;
    if epoch != service.epoch.load(Ordering::SeqCst) || !state.has_passphrase() {
        state.lock();
        bail!("locked while restoring wallet");
    }
    select_slot(&path, &slot)?;
    if let Err(error) = state.runner.ensure(account.clone()).await {
        tracing::warn!("could not resume account relays: {error}");
    }
    Ok(account)
}

async fn prepare_account_mint(
    original: &std::path::Path,
    storage_seed: &[u8; 64],
    mint: &str,
    restoring: bool,
) -> Result<String> {
    let slot = mint_slot(original, storage_seed, mint).await?;
    recovery_scan(&slot_path(original, &slot)?, storage_seed, Some(!restoring))
        .context(WalletFailure::Storage)?;
    Ok(slot)
}

pub(crate) fn import_error(error: anyhow::Error) -> String {
    if let Some(message) = touch_id_error(&error) {
        return message.into();
    }
    if let Some(failure) = error.downcast_ref::<WalletFailure>() {
        return failure.to_string();
    }
    "Could not import wallet. Check the words, recovery passphrase and mint URL.".into()
}

fn touch_id_error(error: &anyhow::Error) -> Option<&'static str> {
    use signer_core::keystore::KeyStoreError;
    match error.downcast_ref::<KeyStoreError>()? {
        KeyStoreError::Cancelled => Some("Authentication cancelled."),
        KeyStoreError::AuthInterrupted => Some("Authentication was interrupted. Try again."),
        KeyStoreError::AuthUnavailable => Some("macOS authentication is unavailable. Try again."),
        KeyStoreError::AuthFailed => Some("Authentication failed. Try again."),
        _ => None,
    }
}

pub(crate) fn create_error(error: anyhow::Error) -> String {
    touch_id_error(&error)
        .unwrap_or("Could not create the wallet. Try again.")
        .into()
}

fn import_mint(value: &str) -> Result<String> {
    ensure!(value.len() < 2048, "mint URL too long");
    let url = url::Url::parse(value.trim())?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "use an HTTPS mint URL without credentials or query parameters"
    );
    Ok(url.to_string().trim_end_matches('/').into())
}

async fn store_mint(
    original: &std::path::Path,
    identity_seed: &[u8; 64],
    seed: &[u8; 64],
    mint: &str,
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"byrgi/cashu/import/v1\0");
    hash.update(seed);
    hash.update(mint.as_bytes());
    let slot = format!("{:x}", hash.finalize());
    let path = slot_path(original, &slot)?;
    store_wallet_file(&path, identity_seed, seed, mint).await?;
    Ok(slot)
}

async fn store_wallet_file(
    path: &std::path::Path,
    identity_seed: &[u8; 64],
    seed: &[u8; 64],
    mint: &str,
) -> Result<()> {
    if !path.exists() {
        let temporary = path.with_extension("importing");
        let password = database_password(identity_seed);
        {
            let conn = rusqlite::Connection::open(&temporary)?;
            conn.pragma_update(None, "key", password.as_str())?;
            conn.execute_batch("CREATE TABLE IF NOT EXISTS byrgi_wallet_profile (id INTEGER PRIMARY KEY CHECK(id = 1), seed BLOB NOT NULL, mint TEXT NOT NULL);")?;
            conn.execute(
                "INSERT OR REPLACE INTO byrgi_wallet_profile VALUES (1, ?1, ?2)",
                rusqlite::params![&seed[..], mint],
            )?;
        }
        std::fs::File::open(&temporary)?.sync_all()?;
        // Publish without replacing a wallet another process may have opened.
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::remove_file(&temporary)?;
    }
    let (stored_seed, stored_mint) =
        wallet_profile(path, database_password(identity_seed).as_str())?;
    ensure!(
        *stored_seed == *seed && stored_mint == mint,
        "wallet profile mismatch"
    );
    open_path(path.to_path_buf(), identity_seed, true).await?;
    Ok(())
}

#[derive(Serialize)]
pub struct WalletBackup {
    words: Option<String>,
    mints: Vec<String>,
    passphrase_required: bool,
}

impl Drop for WalletBackup {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(words) = self.words.as_mut() {
            words.zeroize();
        }
    }
}

#[tauri::command]
pub async fn wallet_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<WalletBackup, String> {
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    (|| -> Result<WalletBackup> {
        let identity_seed = Zeroizing::new(
            state
                .session
                .vault()
                .wallet_storage_seed(AccountId::new(account))?,
        );
        let original = original_wallet_path(&app, &state, account)?;
        let mints = wallet_choices(&original, &identity_seed)?
            .into_iter()
            .map(|choice| choice.label)
            .collect();
        let recovery = read_recovery(&original, &identity_seed)?;
        ensure!(
            epoch == service.epoch.load(Ordering::SeqCst)
                && state.session.vault().holds(AccountId::new(account)),
            "account locked during backup"
        );
        Ok(WalletBackup {
            words: Some(recovery.0.to_string()),
            mints,
            passphrase_required: recovery.1,
        })
    })()
    .map_err(error)
}

struct CashuApproval {
    account: i64,
    mint: String,
    amount: u64,
    maximum: u64,
    expiry: u64,
    epoch: u64,
}

#[derive(Serialize)]
struct PendingTokenView {
    id: String,
    amount: u64,
}

#[derive(Serialize)]
pub struct TokenView {
    id: String,
    amount: u64,
    mint: String,
    token: String,
}

impl Drop for TokenView {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}

#[derive(Serialize)]
pub struct SendTokenView {
    wallet: WalletView,
    transfer: TokenView,
}

#[derive(Serialize)]
pub struct TokenInfo {
    amount: u64,
    mint: String,
}

fn parse_token(value: &str) -> Result<Token> {
    ensure!(value.len() <= 100_000, "token too large");
    let value = value.trim();
    let token = Token::from_str(value.strip_prefix("cashu:").unwrap_or(value))?;
    ensure!(
        token.unit().unwrap_or(CurrencyUnit::Sat) == CurrencyUnit::Sat,
        "only sat tokens are supported"
    );
    Ok(token)
}

#[tauri::command]
pub fn wallet_inspect_token(token: String) -> Result<TokenInfo, String> {
    let token = Zeroizing::new(token);
    (|| -> Result<TokenInfo> {
        let parsed = parse_token(&token)?;
        Ok(TokenInfo {
            amount: parsed.value()?.into(),
            mint: parsed.mint_url()?.to_string(),
        })
    })()
    .map_err(|_| "Use a valid Cashu token denominated in sats.".into())
}

fn send_options() -> SendOptions {
    SendOptions {
        include_fee: true,
        max_proofs: Some(16),
        ..Default::default()
    }
}

async fn pending_tokens(wallet: &Wallet) -> Result<Vec<PendingTokenView>> {
    use cdk::wallet::types::OperationData;
    let mut pending = Vec::new();
    for id in wallet.get_pending_sends().await?.into_iter().take(30) {
        if let Some(saga) = wallet.localstore.get_saga(&id).await? {
            if let OperationData::Send(data) = saga.data {
                pending.push(PendingTokenView {
                    id: id.to_string(),
                    amount: data.amount.into(),
                });
            }
        }
    }
    Ok(pending)
}

async fn stored_token(wallet: &Wallet, operation: &str) -> Result<TokenView> {
    use cdk::wallet::types::{OperationData, SendSagaState, WalletSagaState};
    let id = operation.parse()?;
    let saga = wallet
        .localstore
        .get_saga(&id)
        .await?
        .ok_or_else(|| anyhow!("token not pending"))?;
    ensure!(
        saga.mint_url == wallet.mint_url
            && saga.state == WalletSagaState::Send(SendSagaState::TokenCreated),
        "token not pending at this mint"
    );
    let OperationData::Send(data) = saga.data else {
        bail!("not a send");
    };
    Ok(TokenView {
        id: operation.into(),
        amount: data.amount.into(),
        mint: wallet.mint_url.to_string(),
        token: data.token.ok_or_else(|| anyhow!("missing token"))?,
    })
}

#[tauri::command]
pub async fn wallet_review_send(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    amount: u64,
) -> Result<PaymentView, String> {
    if !(1..=10_000).contains(&amount) {
        return Err("Enter an amount between 1 and 10,000 sats.".into());
    }
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let wallet = open(&app, &state, account).await?;
        let prepared = wallet.prepare_send(amount.into(), send_options()).await?;
        let fee: u64 = prepared.fee().into();
        // Reviews release their reservations. Confirmation rechecks fees and funds.
        prepared.cancel().await?;
        ensure!(
            epoch == service.epoch.load(Ordering::SeqCst)
                && state.session.vault().holds(AccountId::new(account)),
            "wallet locked during review"
        );
        let quote = nostr::key::Keys::generate().public_key().to_hex();
        let maximum = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount overflow"))?;
        let expiry = now() + 120;
        let mut approvals = service
            .cashu_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        approvals.retain(|_, approval| approval.account != account && approval.expiry > now());
        approvals.insert(
            quote.clone(),
            CashuApproval {
                account,
                mint: wallet.mint_url.to_string(),
                amount,
                maximum,
                expiry,
                epoch,
            },
        );
        Ok(PaymentView {
            quote,
            amount,
            max_fee: fee,
            maximum,
            expiry,
            destination: format!("Cashu token · {}", wallet.mint_url),
        })
    }
    .await
    .map_err(error)
}

fn validate_cashu_approval(
    approval: &CashuApproval,
    account: i64,
    mint: &str,
    epoch: u64,
) -> Result<()> {
    ensure!(
        approval.account == account
            && approval.mint == mint
            && approval.epoch == epoch
            && approval.expiry > now(),
        "review this token again"
    );
    Ok(())
}

#[tauri::command]
pub async fn wallet_send_token(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    quote: String,
) -> Result<SendTokenView, String> {
    let _guard = service.gate.lock().await;
    let approval = service
        .cashu_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&quote)
        .ok_or("Review this token again before creating it.")?;
    async {
        let wallet = open(&app, &state, account).await?;
        validate_cashu_approval(
            &approval,
            account,
            &wallet.mint_url.to_string(),
            service.epoch.load(Ordering::SeqCst),
        )?;
        let prepared = wallet
            .prepare_send(approval.amount.into(), send_options())
            .await?;
        let maximum: u64 = (prepared.amount() + prepared.fee()).into();
        if maximum > approval.maximum
            || !state.session.vault().holds(AccountId::new(account))
            || validate_cashu_approval(
                &approval,
                account,
                &wallet.mint_url.to_string(),
                service.epoch.load(Ordering::SeqCst),
            )
            .is_err()
        {
            prepared.cancel().await?;
            bail!("fees changed or account locked; review again");
        }
        let operation = prepared.operation_id().to_string();
        // CDK saves the token and pending proofs in SQLCipher before returning.
        // Losing this response never requires creating another token.
        prepared.confirm(None).await?;
        let transfer = stored_token(&wallet, &operation).await?;
        let wallet = view(&wallet).await?;
        ensure!(
            approval.epoch == service.epoch.load(Ordering::SeqCst)
                && state.session.vault().holds(AccountId::new(account)),
            "account locked; reopen the pending token after unlocking"
        );
        Ok(SendTokenView { wallet, transfer })
    }
    .await
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_show_token(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    operation: String,
) -> Result<TokenView, String> {
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let wallet = open(&app, &state, account).await?;
        let token = stored_token(&wallet, &operation).await?;
        ensure!(
            epoch == service.epoch.load(Ordering::SeqCst)
                && state.session.vault().holds(AccountId::new(account)),
            "account locked"
        );
        Ok(token)
    }
    .await
    .map_err(error)
}

#[tauri::command]
pub async fn wallet_reclaim_token(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    operation: String,
) -> Result<WalletView, String> {
    let _guard = service.gate.lock().await;
    service.lock();
    async {
        let wallet = open(&app, &state, account).await?;
        // Verify that the operation belongs to this mint before any mutation.
        stored_token(&wallet, &operation).await?;
        wallet.revoke_send(operation.parse()?).await?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}
