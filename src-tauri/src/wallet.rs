//! Cashu wallet operations stay in Rust. The webview sees invoices and balances,
//! never seeds or spendable proofs. Each operation opens an encrypted database.
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Result};
use cdk::nuts::{CurrencyUnit, PaymentMethod, Token};
use cdk::wallet::{ReceiveOptions, Wallet};
use cdk_sqlite::WalletSqliteDatabase;
use lightning_invoice::{Bolt11Invoice, Currency};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::account::AccountId;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::state::AppState;

pub const MINT: &str = "https://btc.aleafnd.org/cashu";

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::cdk_database::WalletDatabase;

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

    #[tokio::test]
    async fn imports_are_encrypted_separate_and_reimport_preserves_state() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("identity.sqlite");
        let identity_seed = [9; 64];
        let imported_seed = [7; 64];
        let original_wallet = open_path(original.clone(), &identity_seed, false)
            .await
            .unwrap();
        original_wallet
            .localstore
            .add_mint(MINT.parse().unwrap(), None)
            .await
            .unwrap();
        drop(original_wallet);
        let slot = store_import(
            &original,
            &identity_seed,
            &imported_seed,
            "https://mint.example",
        )
        .await
        .unwrap();
        assert_eq!(selected_slot(&original).unwrap(), "original");
        let imported = open_path(slot_path(&original, &slot).unwrap(), &identity_seed, true)
            .await
            .unwrap();
        assert_eq!(imported.mint_url.to_string(), "https://mint.example");
        imported
            .localstore
            .add_mint("https://preserve.example".parse().unwrap(), None)
            .await
            .unwrap();
        drop(imported);
        assert_eq!(
            slot,
            store_import(
                &original,
                &identity_seed,
                &imported_seed,
                "https://mint.example"
            )
            .await
            .unwrap()
        );
        let imported = open_path(slot_path(&original, &slot).unwrap(), &identity_seed, true)
            .await
            .unwrap();
        assert!(imported
            .localstore
            .get_mints()
            .await
            .unwrap()
            .contains_key(&"https://preserve.example".parse().unwrap()));
        let original_wallet = open_path(original.clone(), &identity_seed, false)
            .await
            .unwrap();
        assert!(original_wallet
            .localstore
            .get_mints()
            .await
            .unwrap()
            .contains_key(&MINT.parse().unwrap()));
        let bytes = std::fs::read(slot_path(&original, &slot).unwrap()).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(!bytes.windows(64).any(|bytes| bytes == imported_seed));
        select_slot(&original, &slot).unwrap();
        assert_eq!(selected_slot(&original).unwrap(), slot);
        select_slot(&original, "original").unwrap();
        assert_eq!(selected_slot(&original).unwrap(), "original");
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
    }
}

#[derive(Serialize)]
pub struct WalletView {
    mint: String,
    balance: u64,
    pending: u64,
    transactions: Vec<TransactionView>,
    funding_invoice: Option<String>,
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
    let dir = app.path().app_data_dir()?.join("wallets");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir.join(format!("{}.sqlite", identity.to_hex())))
}

pub fn has_wallet(app: &AppHandle, state: &AppState, account: i64) -> Result<bool> {
    let path = original_wallet_path(app, state, account)?;
    let prefix = format!("{}.", path.file_stem().unwrap().to_string_lossy());
    for entry in std::fs::read_dir(path.parent().unwrap())? {
        if entry?.file_name().to_string_lossy().starts_with(&prefix) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn open(app: &AppHandle, state: &AppState, account: i64) -> Result<Wallet> {
    let seed = Zeroizing::new(state.session.vault().cashu_seed(AccountId::new(account))?);
    let original = original_wallet_path(app, state, account)?;
    let slot = selected_slot(&original)?;
    let path = slot_path(&original, &slot)?;
    open_path(path, &seed, slot != "original").await
}

fn database_password(seed: &[u8; 64]) -> Zeroizing<String> {
    let mut hash = Sha256::new();
    hash.update(b"byrgi/cashu/database/v1\0");
    hash.update(&seed[..]);
    Zeroizing::new(format!("{:x}", hash.finalize()))
}

async fn open_path(path: PathBuf, identity_seed: &[u8; 64], imported: bool) -> Result<Wallet> {
    let password = database_password(identity_seed);
    let (seed, mint) = if imported {
        let conn = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        conn.pragma_update(None, "key", password.as_str())?;
        let (bytes, mint): (Vec<u8>, String) = conn.query_row(
            "SELECT seed, mint FROM byrgi_wallet_profile WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let bytes = Zeroizing::new(bytes);
        ensure!(bytes.len() == 64, "invalid stored wallet seed");
        let mut seed = Zeroizing::new([0; 64]);
        seed.copy_from_slice(&bytes);
        (seed, mint)
    } else {
        (Zeroizing::new(*identity_seed), MINT.to_owned())
    };
    let db = WalletSqliteDatabase::new((path, password.to_string())).await?;
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
        .approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, approval| approval.account != account);
}

fn error(error: anyhow::Error) -> String {
    // Avoid forwarding arbitrary SDK errors containing invoices or tokens.
    // Commands supply context suitable for the user instead.
    let _ = error;
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
        let wallet = open(&app, &state, account).await?;
        // Recovery only resumes previously authorized operations.
        let report = wallet.recover_incomplete_sagas().await?;
        ensure!(report.failed == 0, "wallet recovery incomplete");
        wallet.finalize_pending_melts().await?;
        wallet.mint_unissued_quotes().await?;
        view(&wallet).await
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
    let token = token.trim().strip_prefix("cashu:").unwrap_or(token.trim());
    let parsed = Token::from_str(token).map_err(|_| "Invalid Cashu token.")?;
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
        let wallet = open(&app, &state, account).await?;
        wallet.restore().await?;
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

#[tauri::command]
pub async fn wallet_list(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<WalletList, String> {
    let _guard = service.gate.lock().await;
    (|| -> Result<WalletList> {
        state
            .session
            .vault()
            .identity_public_key(AccountId::new(account))?;
        let original = original_wallet_path(&app, &state, account)?;
        let prefix = format!("{}.", original.file_stem().unwrap().to_string_lossy());
        let mut wallets = vec![WalletChoice {
            id: "original".into(),
            label: "Original wallet".into(),
        }];
        for entry in std::fs::read_dir(original.parent().unwrap())? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(slot) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".sqlite"))
            {
                if slot.len() == 64 && slot.bytes().all(|c| c.is_ascii_hexdigit()) {
                    wallets.push(WalletChoice {
                        id: slot.into(),
                        label: format!("Imported · {}", &slot[..8]),
                    });
                }
            }
        }
        wallets[1..].sort_by(|a, b| a.id.cmp(&b.id));
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
        let seed = Zeroizing::new(state.session.vault().cashu_seed(AccountId::new(account))?);
        let original = original_wallet_path(&app, &state, account)?;
        let wallet = open_path(slot_path(&original, &slot)?, &seed, slot != "original").await?;
        select_slot(&original, &slot)?;
        view(&wallet).await
    }
    .await
    .map_err(error)
}

#[derive(Deserialize)]
pub struct WalletImport {
    mnemonic: String,
    passphrase: String,
    mint: String,
}

fn import_seed(words: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    ensure!(
        words.len() <= 512 && passphrase.len() <= 1024,
        "recovery input too long"
    );
    let phrase = Zeroizing::new(bip39::Mnemonic::parse(words)?);
    Ok(Zeroizing::new(phrase.to_seed(passphrase)))
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

async fn store_import(
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
        match std::fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::remove_file(&temporary)?;
    }
    // Validate existing imports too. Re-importing never resets CDK counters,
    // proofs, transaction history, or pending operations.
    open_path(path, identity_seed, true).await?;
    Ok(slot)
}

#[tauri::command]
pub async fn wallet_import(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    recovery: WalletImport,
) -> Result<WalletView, String> {
    let words = Zeroizing::new(recovery.mnemonic);
    let passphrase = Zeroizing::new(recovery.passphrase);
    let seed = import_seed(&words, &passphrase)
        .map_err(|_| "Enter a valid BIP-39 seed phrase and optional recovery passphrase.")?;
    let mint = import_mint(&recovery.mint).map_err(|_| "Enter the original mint’s HTTPS URL.")?;
    let _guard = service.gate.lock().await;
    service.lock();
    async {
        let identity_seed =
            Zeroizing::new(state.session.vault().cashu_seed(AccountId::new(account))?);
        let original = original_wallet_path(&app, &state, account)?;
        let slot = store_import(&original, &identity_seed, &seed, &mint).await?;
        ensure!(
            state.session.vault().holds(AccountId::new(account)),
            "account locked during import"
        );
        select_slot(&original, &slot)?;
        let wallet = open_path(slot_path(&original, &slot)?, &identity_seed, true).await?;
        // Save first, so a network failure cannot discard the imported seed.
        // Recovery is an explicit next step and can be retried after reopening.
        view(&wallet).await
    }
    .await
    .map_err(error)
}
