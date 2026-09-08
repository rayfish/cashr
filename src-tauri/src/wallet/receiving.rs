//! One durable retry record per quote. A failed collection is not a new payment.
use anyhow::Result;
use cdk::wallet::{
    types::{Transaction, TransactionDirection, TransactionStatus},
    Wallet,
};
use cdk::{amount::SplitTarget, Error};
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = "cashr";
const RETRIES: &str = "mint-retries";

#[derive(Serialize, Deserialize)]
struct Retry {
    attempts: u32,
    after: u64,
    blocked: bool,
    message: String,
}

impl Retry {
    fn pending(previous: Option<&Self>, now: u64) -> Self {
        let attempts = previous.map_or(1, |r| r.attempts.saturating_add(1));
        Self {
            attempts,
            after: now.saturating_add((60u64 << attempts.saturating_sub(1).min(5)).min(1800)),
            blocked: false,
            message: "Collection pending.".into(),
        }
    }
    fn due(&self, now: u64, manual: bool) -> bool {
        manual || (!self.blocked && now >= self.after)
    }
}

fn failure(error: &Error) -> &'static str {
    match error {
        Error::SignatureMissingOrInvalid => "Mint rejected the collection signature.",
        Error::MaxOutputsExceeded { .. } => "Collection exceeds the mint’s output limit.",
        Error::AmountOutofLimitRange(..) => "Amount exceeds the mint’s limits.",
        Error::UnknownQuote => "Mint could not find this payment.",
        Error::ExpiredQuote(..) => "Mint reports that this payment expired.",
        Error::MintingDisabled => "Mint has paused collection.",
        Error::HttpError(..) | Error::Timeout => "Could not reach the mint. Retrying later.",
        _ if error.is_definitive_failure() => "Mint rejected collection. Refresh to retry.",
        _ => "Collection interrupted. Retrying later.",
    }
}

async fn read(wallet: &Wallet, id: &str) -> Result<Option<Retry>> {
    wallet
        .localstore
        .kv_read(NAMESPACE, RETRIES, id)
        .await?
        .map(|v| serde_json::from_slice(&v).map_err(Into::into))
        .transpose()
}

async fn save(wallet: &Wallet, id: &str, retry: &Retry) -> Result<()> {
    wallet
        .localstore
        .kv_write(NAMESPACE, RETRIES, id, &serde_json::to_vec(retry)?)
        .await?;
    Ok(())
}

pub async fn collect(wallet: &Wallet, manual: bool, unlocked: impl Fn() -> bool) -> Result<u64> {
    let mut received = 0u64;
    for quote in wallet.get_unissued_mint_quotes().await? {
        anyhow::ensure!(unlocked(), "Wallet locked");
        let retry = read(wallet, &quote.id).await?;
        if retry.as_ref().is_some_and(|r| !r.due(super::now(), manual)) {
            continue;
        }
        let mut retry = Retry::pending(retry.as_ref(), super::now());
        // Save before contacting the mint; restarting must not reset the backoff.
        save(wallet, &quote.id, &retry).await?;
        let result = attempt(wallet, &quote.id, &unlocked).await;
        match result {
            Ok(()) => {
                let updated = wallet.localstore.get_mint_quote(&quote.id).await?;
                if let Some(updated) = updated {
                    let delta: u64 = updated
                        .amount_issued
                        .checked_sub(quote.amount_issued)
                        .unwrap_or_default()
                        .into();
                    received = received.saturating_add(delta);
                }
                wallet
                    .localstore
                    .kv_remove(NAMESPACE, RETRIES, &quote.id)
                    .await?;
            }
            Err(error) => {
                retry.blocked = error.is_definitive_failure();
                retry.message = failure(&error).into();
                save(wallet, &quote.id, &retry).await?;
            }
        }
    }
    Ok(received)
}

async fn attempt(wallet: &Wallet, id: &str, unlocked: &impl Fn() -> bool) -> Result<(), Error> {
    // This reconciles an existing saga before we consider starting a new one.
    wallet.check_mint_quote_status(id).await?;
    let quote = wallet
        .localstore
        .get_mint_quote(id)
        .await?
        .ok_or(Error::UnknownQuote)?;
    if quote.amount_mintable() > 0.into() && quote.used_by_operation.is_none() {
        if !unlocked() {
            return Err(Error::Custom("Wallet locked".into()));
        }
        wallet.mint(id, SplitTarget::default(), None).await?;
    }
    Ok(())
}

/// Failed invoice collection attempts are not incoming payments. Keep the
/// underlying records for recovery, but omit them from the payment history.
pub fn history(mut transactions: Vec<Transaction>) -> Vec<Transaction> {
    transactions.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));
    transactions.retain(|tx| {
        !(tx.direction == TransactionDirection::Incoming
            && tx.status == TransactionStatus::Failed
            && tx.quote_id.is_some())
    });
    transactions
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failures_back_off_and_rejections_require_manual_retry() {
        let first = Retry::pending(None, 100);
        assert!(!first.due(159, false));
        assert!(first.due(160, false));
        let mut second = Retry::pending(Some(&first), 160);
        assert_eq!(second.after, 280);
        second.blocked = true;
        let persisted: Retry =
            serde_json::from_slice(&serde_json::to_vec(&second).unwrap()).unwrap();
        assert!(!persisted.due(u64::MAX, false));
        assert!(persisted.due(161, true));
        assert_eq!(
            failure(&Error::SignatureMissingOrInvalid),
            "Mint rejected the collection signature."
        );
        assert!(!failure(&Error::Custom("sensitive SDK content".into())).contains("sensitive"));
    }

    fn transaction(id: Option<&str>, status: TransactionStatus, timestamp: u64) -> Transaction {
        Transaction {
            mint_url: "https://mint.example".parse().unwrap(),
            direction: TransactionDirection::Incoming,
            amount: 100_000.into(),
            fee: 0.into(),
            unit: cdk::nuts::CurrencyUnit::Sat,
            ys: vec![],
            timestamp,
            memo: None,
            metadata: Default::default(),
            quote_id: id.map(str::to_owned),
            payment_request: None,
            payment_proof: None,
            payment_method: None,
            saga_id: None,
            status,
        }
    }

    #[test]
    fn history_omits_collection_attempts_without_hiding_payments_or_bolt12_receipts() {
        use TransactionStatus::{Completed, Failed, Pending};
        let pending = history(vec![
            transaction(Some("a"), Failed, 1),
            transaction(Some("a"), Failed, 2),
            transaction(Some("b"), Failed, 3),
        ]);
        assert!(pending.is_empty());
        let mut outgoing = transaction(Some("a"), Failed, 5);
        outgoing.direction = TransactionDirection::Outgoing;
        let complete = history(vec![
            transaction(Some("a"), Failed, 1),
            transaction(Some("a"), Completed, 2),
            transaction(Some("a"), Completed, 3),
            transaction(None, Failed, 4),
            transaction(Some("b"), Pending, 6),
            outgoing,
        ]);
        assert_eq!(complete.len(), 5);
        assert_eq!(complete[0].status, Pending);
        assert_eq!(complete.iter().filter(|t| t.status == Completed).count(), 2);
    }

    #[tokio::test]
    async fn a_persisted_rejection_blocks_background_network_calls_but_manual_refresh_retries() {
        use cdk::wallet::types::MintQuote;
        use std::sync::Arc;
        let db = cdk_sqlite::wallet::memory::empty().await.unwrap();
        let wallet = Wallet::new(
            "http://127.0.0.1:1",
            cdk::nuts::CurrencyUnit::Sat,
            Arc::new(db),
            [7; 64],
            None,
        )
        .unwrap();
        let quote = MintQuote::new(
            "fixture".into(),
            wallet.mint_url.clone(),
            cdk::nuts::PaymentMethod::BOLT11,
            Some(100_000.into()),
            cdk::nuts::CurrencyUnit::Sat,
            "fixture-invoice".into(),
            0,
            None,
        );
        wallet.localstore.add_mint_quote(quote).await.unwrap();
        let retry = Retry {
            attempts: 1,
            after: 0,
            blocked: true,
            message: failure(&Error::SignatureMissingOrInvalid).into(),
        };
        save(&wallet, "fixture", &retry).await.unwrap();
        // Fresh Wallet instance, same persistent database; no attempt counter bump.
        let reopened = Wallet::new(
            &wallet.mint_url.to_string(),
            cdk::nuts::CurrencyUnit::Sat,
            wallet.localstore.clone(),
            [7; 64],
            None,
        )
        .unwrap();
        assert_eq!(collect(&reopened, false, || true).await.unwrap(), 0);
        assert_eq!(
            read(&reopened, "fixture").await.unwrap().unwrap().attempts,
            1
        );
        assert_eq!(collect(&reopened, true, || true).await.unwrap(), 0);
        let retry = read(&reopened, "fixture").await.unwrap().unwrap();
        assert_eq!(retry.attempts, 2);
        assert!(!retry.blocked);
        assert!(retry.after > super::super::now());
        assert!(collect(&reopened, true, || false).await.is_err());
    }
}
