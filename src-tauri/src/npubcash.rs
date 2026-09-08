//! Provider lookup and quote collection. Authentication stays in the vault;
//! CDK records and claims quotes in the existing encrypted wallet database.
use crate::state::AppState;
use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cdk::wallet::Wallet;
use nostr::{
    event::{Event, EventBuilder, FinalizeUnsignedEvent, Kind, Tag, UnsignedEvent},
    key::PublicKey,
    nips::nip19::ToBech32,
};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signer_core::account::AccountId;
use std::time::Duration;

const ORIGIN: &str = "https://npub.cash";
const LIMIT: usize = 1_048_576;
const NAMESPACE: &str = "cashr";
const PROVIDER: &str = "npubcash";
pub(crate) mod username;

#[derive(Clone, Deserialize, Serialize)]
pub struct Address {
    pub address: String,
    pub mint: String,
}

fn auth_event(
    public: PublicKey,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Result<UnsignedEvent> {
    // npub.cash signs origin + pathname, excluding pagination parameters.
    let mut url = url::Url::parse(url)?;
    url.set_query(None);
    let mut tags = vec![
        Tag::parse(["u", url.as_str()])?,
        Tag::parse(["method", method])?,
    ];
    if let Some(body) = body {
        tags.push(Tag::parse([
            "payload",
            &format!("{:x}", Sha256::digest(body.as_bytes())),
        ])?);
    }
    Ok(EventBuilder::new(Kind::Custom(27235), "")
        .tags(tags)
        .finalize_unsigned(public))
}

async fn send(
    client: &Client,
    url: &str,
    method: Method,
    body: Option<Value>,
    public: PublicKey,
    sign: impl FnOnce(UnsignedEvent) -> Result<Event>,
) -> Result<Value> {
    let body = body.map(|body| body.to_string());
    let event = sign(auth_event(public, method.as_str(), url, body.as_deref())?)?;
    let mut request = client.request(method, url).header(
        "Authorization",
        format!("Nostr {}", STANDARD.encode(serde_json::to_vec(&event)?)),
    );
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(body);
    }
    let mut response = request.send().await?.error_for_status()?;
    ensure!(
        response.status().is_success(),
        "Unexpected provider redirect"
    );
    ensure!(
        response.content_length().unwrap_or(0) <= LIMIT as u64,
        "Provider response too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= LIMIT,
            "Provider response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        value.get("error") == Some(&Value::Bool(false)),
        "Provider request failed"
    );
    Ok(value)
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Cashr/0.1")
        .build()?)
}

async fn request(
    state: &AppState,
    account: AccountId,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let public = state.session.vault().identity_public_key(account)?;
    send(
        &client()?,
        &format!("{ORIGIN}{path}"),
        method,
        body,
        public,
        |event| Ok(state.session.vault().sign_event(account, event)?),
    )
    .await
}

fn user(value: &Value, public: PublicKey) -> Result<(&Value, Address)> {
    let user = &value["data"]["user"];
    ensure!(
        user["pubkey"].as_str() == Some(public.to_hex().as_str()),
        "Provider identity mismatch"
    );
    let name = match user
        .get("name")
        .or_else(|| user.get("username"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(name) => {
            ensure!(
                name.len() <= 64
                    && name.bytes().all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || b"-_.".contains(&c)),
                "Invalid provider username"
            );
            name.to_owned()
        }
        None => public.to_bech32()?,
    };
    let mint = crate::wallet::import_mint(
        user["mintUrl"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing receiving mint"))?,
    )?;
    Ok((
        user,
        Address {
            address: format!("{name}@npub.cash"),
            mint,
        },
    ))
}

pub async fn lookup(state: &AppState, account: AccountId) -> Result<Address> {
    let value = request(state, account, Method::GET, "/api/v2/user/info", None).await?;
    Ok(user(&value, state.session.vault().identity_public_key(account)?)?.1)
}

pub async fn saved(wallet: &Wallet) -> Result<Option<Address>> {
    wallet
        .localstore
        .kv_read(NAMESPACE, PROVIDER, "address")
        .await?
        .map(|value| serde_json::from_slice(&value).map_err(Into::into))
        .transpose()
}

async fn save(wallet: &Wallet, address: &Address) -> Result<()> {
    wallet
        .localstore
        .kv_write(
            NAMESPACE,
            PROVIDER,
            "address",
            &serde_json::to_vec(address)?,
        )
        .await?;
    Ok(())
}

pub async fn failed(wallet: &Wallet, failed: Option<bool>) -> Result<bool> {
    if let Some(failed) = failed {
        wallet
            .localstore
            .kv_write(
                NAMESPACE,
                PROVIDER,
                "failed",
                if failed { b"1" } else { b"0" },
            )
            .await?;
    }
    Ok(wallet
        .localstore
        .kv_read(NAMESPACE, PROVIDER, "failed")
        .await?
        .as_deref()
        == Some(b"1"))
}

fn check_identity(wallet: &Wallet, state: &AppState, account: AccountId) -> Result<PublicKey> {
    let public = state.session.vault().identity_public_key(account)?;
    ensure!(
        wallet.get_npubcash_keys()?.public_key().to_hex() == public.to_hex(),
        "Wallet identity mismatch"
    );
    Ok(public)
}

/// A click opts this mint into receiving. Merely viewing the mint picker never
/// changes the provider's routing. Re-fetch after PATCH to confirm both settings.
pub async fn enable(wallet: &Wallet, state: &AppState, account: AccountId) -> Result<Address> {
    let public = check_identity(wallet, state, account)?;
    ensure!(
        wallet
            .fetch_mint_info()
            .await?
            .is_some_and(|info| info.nuts.nut20.supported),
        "Mint does not support quote locking"
    );
    let mint = wallet.mint_url.to_string();
    request(
        state,
        account,
        Method::PATCH,
        "/api/v2/user/mint",
        Some(json!({"mint_url": mint})),
    )
    .await?;
    request(
        state,
        account,
        Method::PATCH,
        "/api/v2/user/lock",
        Some(json!({"lockQuotes": true})),
    )
    .await?;
    let value = request(state, account, Method::GET, "/api/v2/user/info", None).await?;
    let (user, address) = user(&value, public)?;
    ensure!(
        address.mint == mint && user["lockQuote"] == true,
        "Provider did not confirm receiving settings"
    );
    save(wallet, &address).await?;
    Ok(address)
}

/// Recover provider configuration without changing it. Unavailable providers
/// must not prevent opening a wallet or displaying its existing balance.
pub async fn discover(wallet: &Wallet, state: &AppState, account: AccountId) -> Result<()> {
    let public = check_identity(wallet, state, account)?;
    let value = request(state, account, Method::GET, "/api/v2/user/info", None).await?;
    let (user, address) = user(&value, public)?;
    if address.mint == wallet.mint_url.to_string() && user["lockQuote"] == true {
        save(wallet, &address).await?;
    } else {
        // Old quotes still belong to this mint and remain collectable.
        wallet
            .localstore
            .kv_remove(NAMESPACE, PROVIDER, "address")
            .await?;
    }
    Ok(())
}

fn validate_quote(value: &Value, mint: &str) -> Result<bool> {
    // Never let the SDK's defaults turn a missing mint into another endpoint.
    let remote = value["mintUrl"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing quote mint"))?;
    if crate::wallet::import_mint(remote)? != mint {
        return Ok(false);
    }
    ensure!(
        value["unit"].as_str().unwrap_or("sat") == "sat",
        "Unsupported quote unit"
    );
    ensure!(
        value["quoteId"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 512),
        "Invalid quote id"
    );
    ensure!(
        value["amount"].as_u64().is_some_and(|n| n > 0),
        "Invalid quote amount"
    );
    ensure!(value["locked"].is_boolean(), "Missing quote locking state");
    match value["state"].as_str() {
        Some("ISSUED") => return Ok(false),
        Some("PAID" | "INFLIGHT") => {}
        _ => bail!("Invalid quote state"),
    }
    let invoice: lightning_invoice::Bolt11Invoice = value["request"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing invoice"))?
        .parse()?;
    ensure!(
        invoice.currency() == lightning_invoice::Currency::Bitcoin
            && invoice.amount_milli_satoshis()
                == value["amount"].as_u64().and_then(|n| n.checked_mul(1000)),
        "Quote invoice mismatch"
    );
    Ok(true)
}

/// Fetch every page, persist each quote before minting, and retain CDK's issued
/// state. No destructive provider claim endpoint or incremental cursor is used.
pub async fn sync(wallet: &Wallet, state: &AppState, account: AccountId) -> Result<()> {
    check_identity(wallet, state, account)?;
    sync_quotes(wallet, |offset| async move {
        request(
            state,
            account,
            Method::GET,
            &format!("/api/v2/wallet/quotes?limit=50&offset={offset}"),
            None,
        )
        .await
    })
    .await?;
    Ok(())
}

async fn sync_quotes<F: std::future::Future<Output = Result<Value>>>(
    wallet: &Wallet,
    mut fetch: impl FnMut(u64) -> F,
) -> Result<()> {
    let mut offset = 0;
    let mint = wallet.mint_url.to_string();
    loop {
        let value = fetch(offset).await?;
        let quotes = value["data"]["quotes"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Missing quotes"))?;
        let total = value["metadata"]["total"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing pagination"))?;
        ensure!(
            quotes.len() <= 50 && total <= 100_000,
            "Provider history too large"
        );
        for quote in quotes {
            if validate_quote(quote, &mint)? {
                let mut quote = quote.clone();
                quote["mintUrl"] = json!(mint);
                wallet
                    .add_npubcash_mint_quote(serde_json::from_value(quote)?)
                    .await?;
            }
        }
        offset += quotes.len() as u64;
        if offset >= total {
            break;
        }
        ensure!(!quotes.is_empty(), "Incomplete provider history");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{event::SignEvent, key::Keys};

    #[test]
    fn provider_auth_binds_identity_method_path_and_exact_body() {
        let keys = Keys::generate();
        let body = r#"{"lockQuotes":true}"#;
        let event = keys
            .sign_event(
                auth_event(
                    keys.public_key(),
                    "PATCH",
                    "https://npub.cash/api/v2/user/lock?ignored=1",
                    Some(body),
                )
                .unwrap(),
            )
            .unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::Custom(27235));
        let tags: Vec<_> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(tags.contains(&vec![
            "u".into(),
            "https://npub.cash/api/v2/user/lock".into()
        ]));
        assert!(tags.contains(&vec!["method".into(), "PATCH".into()]));
        assert!(tags.contains(&vec![
            "payload".into(),
            format!("{:x}", Sha256::digest(body))
        ]));
    }

    #[test]
    fn address_comes_from_authenticated_provider_and_rejects_other_identity() {
        let public = Keys::generate().public_key();
        let mut value = json!({"data":{"user":{"pubkey":public.to_hex(),"mintUrl":crate::wallet::MINT,"username":"dario"}}});
        assert_eq!(user(&value, public).unwrap().1.address, "dario@npub.cash");
        value["data"]["user"]["username"] = Value::Null;
        assert_eq!(
            user(&value, public).unwrap().1.address,
            format!("{}@npub.cash", public.to_bech32().unwrap())
        );
        value["data"]["user"]["username"] = json!("someone@other.example");
        assert!(user(&value, public).is_err());
        value["data"]["user"]["username"] = Value::Null;
        assert!(user(&value, Keys::generate().public_key()).is_err());
    }

    #[test]
    fn quotes_cannot_route_to_another_mint_or_use_sdk_defaults() {
        assert!(validate_quote(&json!({}), crate::wallet::MINT).is_err());
        assert!(!validate_quote(
            &json!({"mintUrl":"https://other.example"}),
            crate::wallet::MINT
        )
        .unwrap());
        assert!(validate_quote(
            &json!({"mintUrl":crate::wallet::MINT,"unit":"usd"}),
            crate::wallet::MINT
        )
        .is_err());
    }

    #[tokio::test]
    async fn repeated_provider_quotes_preserve_issued_state_and_derive_the_same_identity() {
        use cdk::nuts::{CurrencyUnit, MintQuoteState};
        use std::sync::Arc;
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = bip39::Mnemonic::parse(phrase).unwrap().to_seed("");
        let db = cdk_sqlite::wallet::memory::empty().await.unwrap();
        let wallet = Wallet::new(
            crate::wallet::MINT,
            CurrencyUnit::Sat,
            Arc::new(db),
            seed,
            None,
        )
        .unwrap();
        let identity = nostr::nips::nip06::FromMnemonic::from_mnemonic(phrase, None);
        let identity: Keys = identity.unwrap();
        assert_eq!(
            wallet.get_npubcash_keys().unwrap().public_key().to_hex(),
            identity.public_key().to_hex()
        );
        let quote = json!({"quoteId":"fixture","mintUrl":crate::wallet::MINT,"amount":1000,"unit":"sat","state":"PAID","locked":true,"createdAt":1});
        let mut stored = wallet
            .add_npubcash_mint_quote(serde_json::from_value(quote.clone()).unwrap())
            .await
            .unwrap()
            .unwrap();
        stored.state = MintQuoteState::Issued;
        stored.amount_issued = 1000.into();
        wallet.localstore.add_mint_quote(stored).await.unwrap();
        wallet
            .add_npubcash_mint_quote(serde_json::from_value(quote).unwrap())
            .await
            .unwrap();
        let saved = wallet
            .localstore
            .get_mint_quote("fixture")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.state, MintQuoteState::Issued);
        assert_eq!(saved.amount_issued, 1000.into());
        assert!(saved.secret_key.is_none());
        assert!(wallet.get_unissued_mint_quotes().await.unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "read-only live API check with an ephemeral synthetic identity"]
    async fn live_provider_lookup_contract() {
        let keys = Keys::generate();
        let response = send(
            &client().unwrap(),
            &format!("{ORIGIN}/api/v2/user/info"),
            Method::GET,
            None,
            keys.public_key(),
            |event| Ok(keys.sign_event(event)?),
        )
        .await
        .unwrap();
        let (_, address) = user(&response, keys.public_key()).unwrap();
        assert_eq!(
            address.address,
            format!("{}@npub.cash", keys.public_key().to_bech32().unwrap())
        );
        let response = send(
            &client().unwrap(),
            &format!("{ORIGIN}/api/v2/wallet/quotes?limit=50&offset=0"),
            Method::GET,
            None,
            keys.public_key(),
            |event| Ok(keys.sign_event(event)?),
        )
        .await
        .unwrap();
        assert_eq!(response["data"]["quotes"], json!([]));
        assert_eq!(response["metadata"]["total"], json!(0));
    }

    #[tokio::test]
    async fn paginated_quotes_are_durable_and_missing_pages_fail() {
        use std::sync::Arc;
        let db = cdk_sqlite::wallet::memory::empty().await.unwrap();
        let wallet = Wallet::new(
            crate::wallet::MINT,
            cdk::nuts::CurrencyUnit::Sat,
            Arc::new(db),
            [7; 64],
            None,
        )
        .unwrap();
        let key = cdk::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Bitcoin)
            .description("Synthetic receiving fixture".into())
            .payment_hash(format!("{:x}", Sha256::digest([1; 32])).parse().unwrap())
            .payment_secret(lightning_invoice::PaymentSecret([42; 32]))
            .amount_milli_satoshis(21000)
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .build_signed(|h| cdk::secp256k1::Secp256k1::new().sign_ecdsa_recoverable(h, &key))
            .unwrap()
            .to_string();
        let quote = json!({"quoteId":"fixture","mintUrl":crate::wallet::MINT,"request":invoice,"amount":21,"unit":"sat","state":"PAID","locked":true,"createdAt":1});
        assert!(validate_quote(&quote, crate::wallet::MINT).unwrap());
        let mut wrong = quote.clone();
        wrong["amount"] = json!(22);
        assert!(validate_quote(&wrong, crate::wallet::MINT).is_err());
        let mut offsets = Vec::new();
        sync_quotes(&wallet, |offset| {
            offsets.push(offset);
            let quotes: Vec<_> = (offset..(offset + 50).min(51))
                .map(|i| {
                    let mut value = quote.clone();
                    value["quoteId"] = json!(format!("fixture-{i}"));
                    value
                })
                .collect();
            std::future::ready(Ok(
                json!({"data":{"quotes":quotes},"metadata":{"total":51}}),
            ))
        })
        .await
        .unwrap();
        assert_eq!(offsets, vec![0, 50]);
        assert_eq!(wallet.get_unissued_mint_quotes().await.unwrap().len(), 51);
        assert!(sync_quotes(&wallet, |_| std::future::ready(Ok(
            json!({"data":{"quotes":[]},"metadata":{"total":51}})
        )))
        .await
        .is_err());
        assert_eq!(wallet.get_unissued_mint_quotes().await.unwrap().len(), 51);
    }
}
