//! Username purchases use NIP-98 and in-band X-Cashu payments to a fixed origin.
use super::*;
use cdk::nuts::{nut18::PaymentRequest, CurrencyUnit};
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Price {
    pub amount: u64,
    pub mint: String,
}

pub fn normalize(name: &str) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    ensure!(
        (3..=64).contains(&name.len())
            && !name.starts_with("npub1")
            && name.bytes().all(|b| b.is_ascii_alphanumeric()),
        "Use 3–64 letters or numbers; names cannot start with npub1."
    );
    Ok(name)
}

async fn json_response(mut response: reqwest::Response) -> Result<Value> {
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
    Ok(serde_json::from_slice(&bytes)?)
}

fn payment_terms(encoded: &str) -> Result<Price> {
    ensure!(encoded.len() < 8192, "Invalid name price");
    let request = PaymentRequest::from_str(encoded)?;
    let amount: u64 = request
        .amount
        .ok_or_else(|| anyhow::anyhow!("Missing name price"))?
        .into();
    ensure!(
        request.unit == Some(CurrencyUnit::Sat)
            && (1..=10_000).contains(&amount)
            && request.mints.len() == 1
            && request.nut10.is_none()
            && request.transports.is_empty()
            && request.supported_methods.is_empty(),
        "Unsupported name payment terms"
    );
    Ok(Price {
        amount,
        mint: crate::wallet::import_mint(&request.mints[0].to_string())?,
    })
}

async fn post_to(
    client: &Client,
    url: &str,
    name: &str,
    token: Option<&str>,
    public: PublicKey,
    sign: impl FnOnce(UnsignedEvent) -> Result<Event>,
) -> Result<reqwest::Response> {
    let body = json!({"username": name}).to_string();
    let event = sign(auth_event(public, "POST", url, Some(&body))?)?;
    let mut request = client
        .post(url)
        .header(
            "Authorization",
            format!("Nostr {}", STANDARD.encode(serde_json::to_vec(&event)?)),
        )
        .header("Content-Type", "application/json")
        .body(body);
    if let Some(token) = token {
        let mut header = reqwest::header::HeaderValue::from_str(token)?;
        header.set_sensitive(true);
        request = request.header("X-Cashu", header);
    }
    Ok(request.send().await?)
}

async fn post(
    state: &AppState,
    account: AccountId,
    name: &str,
    token: Option<&str>,
) -> Result<reqwest::Response> {
    let public = state.session.vault().identity_public_key(account)?;
    post_to(
        &client()?,
        &format!("{ORIGIN}/api/v2/user/username"),
        name,
        token,
        public,
        |event| Ok(state.session.vault().sign_event(account, event)?),
    )
    .await
}

/// The unpaid POST is a provider-side availability check for paid names.
/// Free names are only submitted after the explicit Claim click.
pub async fn quote(state: &AppState, account: AccountId, name: &str) -> Result<Price> {
    let response = client()?
        .get(format!("{ORIGIN}/api/v2/info"))
        .send()
        .await?;
    ensure!(response.status().is_success(), "Name service unavailable");
    let info = json_response(response).await?;
    let feature = &info["data"]["features"]["username"];
    ensure!(
        info["error"] == false && feature["enabled"] == true,
        "Name purchases are unavailable"
    );
    if feature["payment"]["amount"] == 0 {
        return Ok(Price {
            amount: 0,
            mint: String::new(),
        });
    }
    parse_quote(post(state, account, name, None).await?).await
}

async fn parse_quote(response: reqwest::Response) -> Result<Price> {
    match response.status().as_u16() {
        402 => payment_terms(
            response
                .headers()
                .get("X-Cashu")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow::anyhow!("Provider did not return a name price"))?,
        ),
        409 => bail!("Name already taken."),
        400 => bail!("That name is not available."),
        _ => bail!("Could not check the name. Try again."),
    }
}

pub async fn claim(
    state: &AppState,
    account: AccountId,
    name: &str,
    token: Option<&str>,
) -> Result<Address> {
    let response = post(state, account, name, token).await?;
    ensure!(
        response.status().is_success(),
        "Name purchase not confirmed"
    );
    let value = json_response(response).await?;
    ensure!(value["error"] == false, "Name purchase not confirmed");
    let address = user(&value, state.session.vault().identity_public_key(account)?)?.1;
    ensure!(
        address.address == format!("{name}@npub.cash"),
        "Provider name mismatch"
    );
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{event::FinalizeEvent, key::Keys, nips::nip19::ToBech32};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn authenticated_payment_binds_body_and_reuses_the_same_token_without_redirects() {
        let server = MockServer::start().await;
        let keys = Keys::generate();
        let url = format!("{}/username", server.uri());
        Mock::given(method("POST")).and(path("/username"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"error":false,"data":{"user":{"pubkey":keys.public_key().to_hex(),"name":"alice","mintUrl":crate::wallet::MINT}}})))
            .mount(&server).await;
        for _ in 0..2 {
            let response = post_to(
                &client().unwrap(),
                &url,
                "alice",
                Some("cashuB-synthetic-only"),
                keys.public_key(),
                |event| Ok(event.finalize(&keys)?),
            )
            .await
            .unwrap();
            let value = json_response(response).await.unwrap();
            assert_eq!(
                user(&value, keys.public_key()).unwrap().1.address,
                "alice@npub.cash"
            );
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(request.headers["X-Cashu"], "cashuB-synthetic-only");
            let authorization = request.headers["Authorization"]
                .to_str()
                .unwrap()
                .strip_prefix("Nostr ")
                .unwrap();
            let event: Event =
                serde_json::from_slice(&STANDARD.decode(authorization).unwrap()).unwrap();
            event.verify().unwrap();
            assert_eq!(event.pubkey, keys.public_key());
            let tags: Vec<_> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
            assert!(tags.contains(&vec!["u".into(), url.clone()]));
            assert!(tags.contains(&vec!["method".into(), "POST".into()]));
            assert!(tags.contains(&vec![
                "payload".into(),
                format!("{:x}", Sha256::digest(&request.body))
            ]));
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!({"username":"alice"})
            );
        }
        Mock::given(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/leak", server.uri())),
            )
            .mount(&server)
            .await;
        let response = post_to(
            &client().unwrap(),
            &format!("{}/redirect", server.uri()),
            "alice",
            Some("cashuB-synthetic-only"),
            keys.public_key(),
            |event| Ok(event.finalize(&keys)?),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 307);
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path() == "/leak"));
        // A normal npub fallback is not mistaken for a purchased name.
        assert!(normalize(&keys.public_key().to_bech32().unwrap()).is_err());
    }

    #[tokio::test]
    async fn quote_reads_the_payment_header_and_reports_a_taken_name() {
        let server = MockServer::start().await;
        let request: PaymentRequest =
            serde_json::from_value(json!({"a":5000,"u":"sat","m":[crate::wallet::MINT]})).unwrap();
        Mock::given(path("/price"))
            .respond_with(ResponseTemplate::new(402).insert_header("X-Cashu", request.to_string()))
            .mount(&server)
            .await;
        Mock::given(path("/taken"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        let price = parse_quote(
            client()
                .unwrap()
                .get(format!("{}/price", server.uri()))
                .send()
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(price.amount, 5000);
        let error = parse_quote(
            client()
                .unwrap()
                .get(format!("{}/taken", server.uri()))
                .send()
                .await
                .unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "Name already taken.");
    }

    #[test]
    fn usernames_match_provider_rules() {
        assert_eq!(normalize(" Dario ").unwrap(), "dario");
        for invalid in [
            "ab",
            "npub1abc",
            "dario@npub.cash",
            "a/b",
            "a_b",
            "a-b",
            "ábc",
            "a\nb",
        ] {
            assert!(normalize(invalid).is_err());
        }
        assert!(normalize(&"a".repeat(65)).is_err());
    }
    #[test]
    fn payment_requests_require_bounded_sats_at_one_https_mint() {
        let request: PaymentRequest = serde_json::from_value(
            json!({"a":5000,"u":"sat","m":["https://mint.minibits.cash/Bitcoin"]}),
        )
        .unwrap();
        let price = payment_terms(&request.to_string()).unwrap();
        assert_eq!(price.amount, 5000);
        assert_eq!(price.mint, crate::wallet::MINT);
        for value in [
            json!({"a":5000,"u":"usd","m":["https://mint.example"]}),
            json!({"a":10001,"u":"sat","m":["https://mint.example"]}),
            json!({"a":5000,"u":"sat","m":[]}),
            json!({"a":5000,"u":"sat","m":["http://mint.example"]}),
        ] {
            let request: PaymentRequest = serde_json::from_value(value).unwrap();
            assert!(payment_terms(&request.to_string()).is_err());
        }
    }
}
