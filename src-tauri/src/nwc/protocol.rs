use anyhow::{bail, ensure, Result};
use nostr::{
    event::{Event, EventBuilder, FinalizeEvent, Kind, Tag},
    key::{Keys, PublicKey, SecretKey},
    nips::{nip04::Nip04, nip44::Nip44},
    types::Timestamp,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const METHODS: &str = "get_info get_balance pay_invoice";

pub fn balance(sats: u64) -> Result<Value> {
    Ok(success(
        "get_balance",
        json!({"balance": sats.checked_mul(1000).ok_or_else(|| anyhow::anyhow!("balance overflow"))?}),
    ))
}
pub const MAX_AGE: u64 = 300;

pub fn now() -> u64 {
    Timestamp::now().as_secs()
}

pub fn connection_keys(seed: &[u8; 64], client: PublicKey) -> Result<Keys> {
    let mut hash = Sha256::new();
    hash.update(b"cashr/nwc/connection/v1\0");
    hash.update(seed);
    hash.update(client.to_bytes());
    let secret = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    Ok(Keys::new(SecretKey::from_slice(secret.as_ref())?))
}

pub fn info(keys: &Keys) -> Result<Event> {
    Ok(EventBuilder::new(Kind::from_u16(13194), METHODS)
        .tags([Tag::parse(["encryption", "nip44_v2 nip04"])?])
        .finalize(keys)?)
}

fn tag<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|t| {
        let v = t.as_slice();
        (v.first().map(String::as_str) == Some(name))
            .then(|| v.get(1).map(String::as_str))
            .flatten()
    })
}

pub fn valid(event: &Event, client: PublicKey, wallet: PublicKey, created: u64) -> bool {
    let at = now();
    event.kind == Kind::from_u16(23194)
        && event.pubkey == client
        && event.created_at.as_secs() >= created
        && event.created_at.as_secs() <= at + 30
        && event.created_at.as_secs().saturating_add(MAX_AGE) > at
        && event.content.len() <= 32_768
        && event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(String::as_str) == Some("p"))
            .count()
            == 1
        && tag(event, "p") == Some(wallet.to_hex().as_str())
        && tag(event, "expiration").is_none_or(|s| s.parse::<u64>().is_ok_and(|t| t > at))
        && event.verify().is_ok()
}

pub fn deadline(event: &Event) -> u64 {
    let age = event.created_at.as_secs().saturating_add(MAX_AGE);
    tag(event, "expiration")
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(age, |expiry| age.min(expiry))
}

fn encryption(event: &Event) -> Result<&str> {
    match tag(event, "encryption").unwrap_or("nip04") {
        "nip04" => Ok("nip04"),
        "nip44_v2" => Ok("nip44_v2"),
        _ => bail!("unsupported encryption"),
    }
}

#[derive(Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub fn decode(event: &Event, keys: &Keys) -> Result<Request> {
    let plain = Zeroizing::new(match encryption(event)? {
        "nip44_v2" => keys.nip44_decrypt(&event.pubkey, &event.content)?,
        _ => keys.nip04_decrypt(&event.pubkey, &event.content)?,
    });
    let request: Request = serde_json::from_str(&plain)?;
    ensure!(request.method.len() <= 64, "invalid method");
    Ok(request)
}

pub fn response(event: &Event, keys: &Keys, value: Value) -> Result<Event> {
    let mode = encryption(event)?;
    let plain = Zeroizing::new(serde_json::to_string(&value)?);
    let content = match mode {
        "nip44_v2" => keys.nip44_encrypt(&event.pubkey, plain.as_str())?,
        _ => keys.nip04_encrypt(&event.pubkey, plain.as_str())?,
    };
    Ok(EventBuilder::new(Kind::from_u16(23195), content)
        .tags([
            Tag::parse(["p", &event.pubkey.to_hex()])?,
            Tag::parse(["e", &event.id.to_hex()])?,
            Tag::parse(["encryption", mode])?,
        ])
        .finalize(keys)?)
}

pub fn failure(method: &str, code: &str, message: &str) -> Value {
    json!({"result_type":method,"result":null,"error":{"code":code,"message":message}})
}

pub fn success(method: &str, result: Value) -> Value {
    json!({"result_type":method,"error":null,"result":result})
}

pub fn payment(params: &Value) -> Result<(String, String)> {
    let raw = params["invoice"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing invoice"))?;
    ensure!(raw.len() <= 16_384, "Invoice too long");
    let invoice: lightning_invoice::Bolt11Invoice = raw.parse()?;
    ensure!(
        !invoice.is_expired() && invoice.currency() == lightning_invoice::Currency::Bitcoin,
        "Invalid invoice"
    );
    let amount = invoice
        .amount_milli_satoshis()
        .ok_or_else(|| anyhow::anyhow!("Invoice needs an amount"))?;
    ensure!(
        (1000..=10_000_000).contains(&amount),
        "Use an invoice for 1–10,000 sats"
    );
    if let Some(supplied) = params.get("amount") {
        ensure!(supplied.as_u64() == Some(amount), "Invoice amount mismatch");
    }
    Ok((raw.to_owned(), invoice.payment_hash().to_string()))
}

pub fn paid(preimage: &str, hash: &str) -> bool {
    if preimage.len() != 64 {
        return false;
    }
    let bytes: Option<Vec<u8>> = (0..64)
        .step_by(2)
        .map(|i| {
            preimage
                .get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();
    bytes.is_some_and(|b| format!("{:x}", Sha256::digest(b)) == hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn balance_is_advertised_and_uses_millisats() {
        let event = info(&Keys::generate()).unwrap();
        assert!(event
            .content
            .split_whitespace()
            .any(|method| method == "get_balance"));
        assert_eq!(
            balance(21).unwrap(),
            success("get_balance", json!({"balance":21_000}))
        );
        assert_eq!(balance(0).unwrap()["result"]["balance"], 0);
        assert!(balance(u64::MAX).is_err());
    }

    fn request(client: &Keys, server: &Keys, mode: &str) -> Event {
        let text = r#"{"method":"get_info"}"#;
        let content = if mode == "nip04" {
            client.nip04_encrypt(&server.public_key(), text).unwrap()
        } else {
            client.nip44_encrypt(&server.public_key(), text).unwrap()
        };
        EventBuilder::new(Kind::from_u16(23194), content)
            .tags([
                Tag::parse(["p", &server.public_key().to_hex()]).unwrap(),
                Tag::parse(["encryption", mode]).unwrap(),
            ])
            .finalize(client)
            .unwrap()
    }
    #[test]
    fn client_round_trip_for_both_encryptions() {
        let client = Keys::generate();
        let server = Keys::generate();
        for mode in ["nip04", "nip44_v2"] {
            let event = request(&client, &server, mode);
            assert!(valid(&event, client.public_key(), server.public_key(), 0));
            assert_eq!(decode(&event, &server).unwrap().method, "get_info");
            let reply = response(
                &event,
                &server,
                success("get_info", json!({"alias":"Cashr"})),
            )
            .unwrap();
            assert!(reply.verify().is_ok());
            assert_eq!(tag(&reply, "e"), Some(event.id.to_hex().as_str()));
            let plain = if mode == "nip04" {
                client
                    .nip04_decrypt(&server.public_key(), &reply.content)
                    .unwrap()
            } else {
                client
                    .nip44_decrypt(&server.public_key(), &reply.content)
                    .unwrap()
            };
            assert_eq!(
                serde_json::from_str::<Value>(&plain).unwrap()["result"]["alias"],
                "Cashr"
            );
        }
    }
    #[test]
    fn rejects_forged_wrong_recipient_and_stale_events() {
        let client = Keys::generate();
        let server = Keys::generate();
        let mut event = request(&client, &server, "nip04");
        assert!(!valid(
            &event,
            Keys::generate().public_key(),
            server.public_key(),
            0
        ));
        assert!(!valid(
            &event,
            client.public_key(),
            Keys::generate().public_key(),
            0
        ));
        event.content.push('x');
        assert!(!valid(&event, client.public_key(), server.public_key(), 0));
        let stale = EventBuilder::new(Kind::from_u16(23194), "")
            .custom_created_at(Timestamp::from_secs(now() - 301))
            .tags([Tag::parse(["p", &server.public_key().to_hex()]).unwrap()])
            .finalize(&client)
            .unwrap();
        assert!(!valid(&stale, client.public_key(), server.public_key(), 0));
    }
    #[test]
    fn connection_keys_are_separate_and_repeatable() {
        let client = Keys::generate().public_key();
        let a = connection_keys(&[7; 64], client).unwrap();
        assert_eq!(
            a.public_key(),
            connection_keys(&[7; 64], client).unwrap().public_key()
        );
        assert_ne!(
            a.public_key(),
            connection_keys(&[8; 64], client).unwrap().public_key()
        );
        assert_ne!(
            a.public_key(),
            connection_keys(&[7; 64], Keys::generate().public_key())
                .unwrap()
                .public_key()
        );
    }
    #[test]
    fn success_requires_a_real_matching_preimage() {
        let preimage = "01".repeat(32);
        let hash = format!("{:x}", Sha256::digest([1; 32]));
        assert!(paid(&preimage, &hash));
        assert!(!paid(&"02".repeat(32), &hash));
        assert!(!paid("pending", &hash));
        assert!(!paid(&"é".repeat(32), &hash));
    }
}
