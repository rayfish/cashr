//! Durable username purchases: review first, persist one send operation, then
//! submit its token. Retries reuse that operation and never mint another payment.
use super::*;
use crate::npubcash::{self, username as provider};

const NS: &str = "cashr";
const KIND: &str = "username";
const RECORD: &str = "purchase";

pub(super) struct Approval {
    pub(super) account: i64,
    epoch: u64,
    expiry: u64,
    name: String,
    mint: String,
    price: provider::Price,
    maximum: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct Purchase {
    name: String,
    mint: String,
    amount: u64,
    operation: Option<String>,
    submitted: bool,
    confirmed: Option<npubcash::Address>,
}

#[derive(Serialize)]
pub struct NameStatus {
    address: Option<String>,
    pending: Option<String>,
    can_retry: bool,
    can_reclaim: bool,
}

#[derive(Serialize)]
pub struct NameResult {
    name: NameStatus,
    wallet: WalletView,
}

async fn registry(app: &AppHandle, state: &AppState, account: i64) -> Result<Wallet> {
    let seed = Zeroizing::new(
        state
            .session
            .vault()
            .wallet_storage_seed(AccountId::new(account))?,
    );
    open_path(original_wallet_path(app, state, account)?, &seed, false).await
}

async fn mint_wallet(
    app: &AppHandle,
    state: &AppState,
    account: i64,
    mint: &str,
) -> Result<Wallet> {
    let seed = Zeroizing::new(
        state
            .session
            .vault()
            .wallet_storage_seed(AccountId::new(account))?,
    );
    let original = original_wallet_path(app, state, account)?;
    let choice = wallet_choices(&original, &seed)?
        .into_iter()
        .find(|choice| choice.label == mint)
        .ok_or_else(|| anyhow!("Choose the payment mint first."))?;
    open_path(
        slot_path(&original, &choice.id)?,
        &seed,
        choice.id != "original",
    )
    .await
}

async fn read(wallet: &Wallet) -> Result<Option<Purchase>> {
    wallet
        .localstore
        .kv_read(NS, KIND, RECORD)
        .await?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
}
async fn save(wallet: &Wallet, purchase: &Purchase) -> Result<()> {
    wallet
        .localstore
        .kv_write(NS, KIND, RECORD, &serde_json::to_vec(purchase)?)
        .await?;
    Ok(())
}

fn status(purchase: Option<&Purchase>) -> NameStatus {
    NameStatus {
        address: purchase.and_then(|p| p.confirmed.as_ref().map(|a| a.address.clone())),
        pending: purchase
            .filter(|p| p.confirmed.is_none())
            .map(|p| format!("{}@npub.cash", p.name)),
        can_retry: purchase
            .is_some_and(|p| p.confirmed.is_none() && (p.amount == 0 || p.operation.is_some())),
        can_reclaim: purchase.is_some_and(|p| p.confirmed.is_none() && p.operation.is_some()),
    }
}

fn named(address: &npubcash::Address) -> bool {
    address
        .address
        .strip_suffix("@npub.cash")
        .is_some_and(|name| provider::normalize(name).is_ok())
}

async fn refresh(registry: &Wallet, state: &AppState, account: i64) -> Result<Option<Purchase>> {
    let mut purchase = read(registry).await?;
    let address = npubcash::lookup(state, AccountId::new(account)).await?;
    if let Some(p) = purchase.as_mut() {
        if address.address == format!("{}@npub.cash", p.name) {
            p.confirmed = Some(address);
            save(registry, p).await?;
        }
    } else if named(&address) {
        let p = Purchase {
            name: address.address.split('@').next().unwrap().to_owned(),
            mint: address.mint.clone(),
            amount: 0,
            operation: None,
            submitted: false,
            confirmed: Some(address),
        };
        save(registry, &p).await?;
        purchase = Some(p);
    }
    Ok(purchase)
}

fn safe_error(error: anyhow::Error) -> String {
    let message = error.to_string();
    match message.as_str() {
        "Name already taken."
        | "That name is not available."
        | "Name purchases are unavailable"
        | "Use 3–64 letters or numbers; names cannot start with npub1."
        | "Finish the pending name purchase first."
        | "This wallet already has a name."
        | "Choose the payment mint first."
        | "Choose Minibits to pay for this name."
        | "Price changed. Check the name again."
        | "Review the name purchase again."
        | "Not enough sats for this name."
        | "Payment is still being recovered. Check again." => message,
        _ => "Could not complete the name request. Check the purchase before retrying.".into(),
    }
}

#[tauri::command]
pub async fn wallet_name_status(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    refresh_provider: Option<bool>,
) -> Result<NameStatus, String> {
    let _guard = service.gate.lock().await;
    async {
        let registry = registry(&app, &state, account).await?;
        let purchase = if refresh_provider.unwrap_or(false) {
            match refresh(&registry, &state, account).await {
                Ok(purchase) => purchase,
                Err(error) => match read(&registry).await? {
                    Some(purchase) => Some(purchase),
                    None => return Err(error),
                },
            }
        } else {
            read(&registry).await?
        };
        if let Some(purchase) = purchase
            .as_ref()
            .filter(|p| p.confirmed.is_some() && p.submitted)
        {
            if let Some(operation) = &purchase.operation {
                let wallet = mint_wallet(&app, &state, account, &purchase.mint).await?;
                let _ = wallet.check_send_status(operation.parse()?).await;
            }
        }
        ensure!(
            state.session.vault().holds(AccountId::new(account)),
            "Wallet locked"
        );
        Ok(status(purchase.as_ref()))
    }
    .await
    .map_err(safe_error)
}

#[tauri::command]
pub async fn wallet_name_review(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    name: String,
) -> Result<PaymentView, String> {
    let _guard = service.gate.lock().await;
    let epoch = service.epoch.load(Ordering::SeqCst);
    async {
        let name = provider::normalize(&name)?;
        let registry = registry(&app, &state, account).await?;
        if let Some(p) = refresh(&registry, &state, account).await? {
            bail!(if p.confirmed.is_some() {
                "This wallet already has a name."
            } else {
                "Finish the pending name purchase first."
            });
        }
        let price = provider::quote(&state, AccountId::new(account), &name).await?;
        let wallet = open(&app, &state, account).await?;
        let mint = wallet.mint_url.to_string();
        ensure!(
            price.amount == 0 || price.mint == mint,
            if price.mint == MINT {
                "Choose Minibits to pay for this name."
            } else {
                "Choose the payment mint first."
            }
        );
        ensure!(
            u64::from(wallet.total_balance().await?) >= price.amount,
            "Not enough sats for this name."
        );
        let fee = if price.amount == 0 {
            0
        } else {
            let prepared = wallet
                .prepare_send(price.amount.into(), send_options())
                .await?;
            let fee: u64 = prepared.fee().into();
            prepared.cancel().await?;
            fee
        };
        let maximum = price
            .amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount overflow"))?;
        ensure!(
            epoch == service.epoch.load(Ordering::SeqCst)
                && state.session.vault().holds(AccountId::new(account)),
            "Review the name purchase again."
        );
        let quote = nostr::key::Keys::generate().public_key().to_hex();
        let expiry = now() + 120;
        let mut approvals = service
            .name_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        approvals.retain(|_, p| p.account != account && p.expiry > now());
        ensure!(approvals.len() < 32, "Too many reviews");
        approvals.insert(
            quote.clone(),
            Approval {
                account,
                epoch,
                expiry,
                name: name.clone(),
                mint: mint.clone(),
                price: price.clone(),
                maximum,
            },
        );
        Ok(PaymentView {
            quote,
            amount: price.amount,
            max_fee: fee,
            maximum,
            expiry,
            destination: format!("{name}@npub.cash · {mint}"),
        })
    }
    .await
    .map_err(safe_error)
}

fn validate(approval: &Approval, account: i64, mint: &str, epoch: u64) -> Result<()> {
    ensure!(
        approval.account == account
            && approval.mint == mint
            && approval.epoch == epoch
            && approval.expiry > now(),
        "Review the name purchase again."
    );
    Ok(())
}

async fn submit(
    registry: &Wallet,
    wallet: &Wallet,
    state: &AppState,
    account: i64,
    purchase: &mut Purchase,
) -> Result<()> {
    // A failed response can follow a successful claim. Check ownership first.
    let existing = npubcash::lookup(state, AccountId::new(account)).await?;
    if existing.address == format!("{}@npub.cash", purchase.name) {
        // If the name was acquired elsewhere during review, return our unsent
        // token to the wallet instead of leaving it reserved and hidden.
        if !purchase.submitted {
            if let Some(operation) = &purchase.operation {
                wallet.revoke_send(operation.parse()?).await?;
            }
        }
        purchase.confirmed = Some(existing);
        return save(registry, purchase).await;
    }
    let transfer = match purchase.operation.as_ref() {
        Some(operation) => Some(
            stored_token(wallet, operation)
                .await
                .map_err(|_| anyhow!("Payment is still being recovered. Check again."))?,
        ),
        None => {
            ensure!(
                purchase.amount == 0,
                "Payment is still being recovered. Check again."
            );
            None
        }
    };
    // The only token ever sent is the durable operation tied to this purchase.
    if let Some(token) = &transfer {
        ensure!(
            token.mint == purchase.mint && token.amount == purchase.amount,
            "Payment mismatch"
        );
    }
    purchase.submitted = true;
    save(registry, purchase).await?;
    if let Ok(address) = provider::claim(
        state,
        AccountId::new(account),
        &purchase.name,
        transfer.as_ref().map(|t| t.token.as_str()),
    )
    .await
    {
        purchase.confirmed = Some(address);
        save(registry, purchase).await?;
        if let Some(operation) = &purchase.operation {
            let _ = wallet.check_send_status(operation.parse()?).await;
        }
        // Updating local receiving details must not turn a paid claim into an error.
        let _ = npubcash::discover(wallet, state, AccountId::new(account)).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn wallet_name_claim(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
    quote: String,
) -> Result<NameResult, String> {
    let _guard = service.gate.lock().await;
    let approval = service
        .name_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&quote)
        .ok_or("Review the name purchase again.")?;
    async {
        let wallet = open(&app, &state, account).await?;
        validate(
            &approval,
            account,
            &wallet.mint_url.to_string(),
            service.epoch.load(Ordering::SeqCst),
        )?;
        let registry = registry(&app, &state, account).await?;
        ensure!(
            refresh(&registry, &state, account).await?.is_none(),
            "Finish the pending name purchase first."
        );
        let price = provider::quote(&state, AccountId::new(account), &approval.name).await?;
        ensure!(
            price == approval.price,
            "Price changed. Check the name again."
        );
        let mut purchase = Purchase {
            name: approval.name,
            mint: approval.mint,
            amount: price.amount,
            operation: None,
            submitted: false,
            confirmed: None,
        };
        if price.amount > 0 {
            let prepared = wallet
                .prepare_send(price.amount.into(), send_options())
                .await?;
            let maximum: u64 = (prepared.amount() + prepared.fee()).into();
            if maximum > approval.maximum
                || approval.epoch != service.epoch.load(Ordering::SeqCst)
                || approval.expiry <= now()
                || !state.session.vault().holds(AccountId::new(account))
            {
                prepared.cancel().await?;
                bail!("Review the name purchase again.");
            }
            let operation = prepared.operation_id().to_string();
            purchase.operation = Some(operation.clone());
            // Journal before the swap. An interruption can never create a second send.
            if let Err(error) = save(&registry, &purchase).await {
                prepared.cancel().await?;
                return Err(error);
            }
            wallet
                .localstore
                .kv_write(NS, KIND, &operation, b"1")
                .await?;
            prepared.confirm(None).await?;
        } else {
            ensure!(
                approval.epoch == service.epoch.load(Ordering::SeqCst)
                    && approval.expiry > now()
                    && state.session.vault().holds(AccountId::new(account)),
                "Review the name purchase again."
            );
            save(&registry, &purchase).await?;
        }
        submit(&registry, &wallet, &state, account, &mut purchase).await?;
        Ok(NameResult {
            name: status(Some(&purchase)),
            wallet: view(&wallet).await?,
        })
    }
    .await
    .map_err(safe_error)
}

#[tauri::command]
pub async fn wallet_name_retry(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<NameResult, String> {
    let _guard = service.gate.lock().await;
    async {
        let registry = registry(&app, &state, account).await?;
        let mut purchase = refresh(&registry, &state, account)
            .await?
            .ok_or_else(|| anyhow!("No name purchase"))?;
        let wallet = mint_wallet(&app, &state, account, &purchase.mint).await?;
        if purchase.confirmed.is_none() {
            submit(&registry, &wallet, &state, account, &mut purchase).await?;
        }
        Ok(NameResult {
            name: status(Some(&purchase)),
            wallet: view(&open(&app, &state, account).await?).await?,
        })
    }
    .await
    .map_err(safe_error)
}

#[tauri::command]
pub async fn wallet_name_reclaim(
    app: AppHandle,
    state: State<'_, AppState>,
    service: State<'_, WalletService>,
    account: i64,
) -> Result<NameResult, String> {
    let _guard = service.gate.lock().await;
    async {
        let registry = registry(&app, &state, account).await?;
        let purchase = refresh(&registry, &state, account)
            .await?
            .ok_or_else(|| anyhow!("No name purchase"))?;
        ensure!(purchase.confirmed.is_none(), "Name already claimed");
        let wallet = mint_wallet(&app, &state, account, &purchase.mint).await?;
        if let Some(operation) = &purchase.operation {
            let id = operation.parse()?;
            let report = wallet.recover_incomplete_sagas().await?;
            ensure!(
                report.failed == 0,
                "Payment is still being recovered. Check again."
            );
            if wallet.localstore.get_saga(&id).await?.is_some() {
                wallet.revoke_send(id).await?;
            } else {
                // A previous reclaim may have completed before Cashr saved its
                // result. Never interpret a recipient's completed spend as a refund.
                let refunded = wallet.list_transactions(None).await?.iter().any(|tx| {
                    tx.saga_id == Some(id)
                        && tx.direction == cdk::wallet::types::TransactionDirection::Outgoing
                        && tx.status == cdk::wallet::types::TransactionStatus::Failed
                });
                ensure!(
                    refunded || !purchase.submitted,
                    "Payment is still being recovered. Check again."
                );
            }
        }
        registry.localstore.kv_remove(NS, KIND, RECORD).await?;
        Ok(NameResult {
            name: status(None),
            wallet: view(&open(&app, &state, account).await?).await?,
        })
    }
    .await
    .map_err(safe_error)
}

pub(super) async fn is_payment(wallet: &Wallet, operation: &str) -> Result<bool> {
    Ok(wallet
        .localstore
        .kv_read(NS, KIND, operation)
        .await?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_is_bound_to_account_mint_expiry_and_lock_epoch() {
        let mut a = Approval {
            account: 1,
            epoch: 7,
            expiry: now() + 120,
            name: "alice".into(),
            mint: MINT.into(),
            price: provider::Price {
                amount: 5000,
                mint: MINT.into(),
            },
            maximum: 5002,
        };
        assert!(validate(&a, 1, MINT, 7).is_ok());
        assert!(validate(&a, 2, MINT, 7).is_err());
        assert!(validate(&a, 1, "https://other.example", 7).is_err());
        assert!(validate(&a, 1, MINT, 8).is_err());
        a.expiry = now();
        assert!(validate(&a, 1, MINT, 7).is_err());
    }
    #[tokio::test]
    async fn pending_purchase_survives_reopening_without_exposing_a_token() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let db = WalletSqliteDatabase::new((path.clone(), "fixture".into()))
            .await
            .unwrap();
        let wallet = Wallet::new(MINT, CurrencyUnit::Sat, Arc::new(db), [7; 64], None).unwrap();
        let purchase = Purchase {
            name: "alice".into(),
            mint: MINT.into(),
            amount: 5000,
            operation: Some("durable-operation".into()),
            submitted: true,
            confirmed: None,
        };
        save(&wallet, &purchase).await.unwrap();
        drop(wallet);
        let db = WalletSqliteDatabase::new((path, "fixture".into()))
            .await
            .unwrap();
        let wallet = Wallet::new(MINT, CurrencyUnit::Sat, Arc::new(db), [7; 64], None).unwrap();
        let saved = read(&wallet).await.unwrap().unwrap();
        assert_eq!(saved.operation.as_deref(), Some("durable-operation"));
        let public = serde_json::to_value(status(Some(&saved))).unwrap();
        assert_eq!(public["pending"], "alice@npub.cash");
        assert_eq!(public["can_retry"], true);
        assert!(!public.to_string().contains("durable-operation"));
    }
}
