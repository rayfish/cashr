use super::*;
use cdk::nuts::{BlindSignature, Id, Keys, PreMintSecrets, SecretKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;

// Local mint with deterministic signatures: one unspent proof and one spent
// proof in an inactive keyset. No real funds or external mint are involved.
struct MintFixture {
    url: String,
    stop: Arc<AtomicBool>,
    fail: Arc<AtomicBool>,
    restores: Arc<AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MintFixture {
    fn new(seed: &[u8; 64]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let fail = Arc::new(AtomicBool::new(false));
        let restores = Arc::new(AtomicU64::new(0));
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let keys = Keys::new(BTreeMap::from([(8.into(), key.public_key())]));
        let id = Id::v1_from_keys(&keys);
        let secrets = PreMintSecrets::restore_batch(id, seed, 0, 2).unwrap();
        let outputs = secrets.blinded_messages();
        let signatures: Vec<_> = outputs
            .iter()
            .map(|output| BlindSignature {
                amount: 8.into(),
                keyset_id: id,
                c: cdk::dhke::sign_message(&key, &output.blinded_secret).unwrap(),
                dleq: None,
            })
            .collect();
        let unspent = cdk::dhke::hash_to_curve(secrets.secrets[0].secret.as_bytes())
            .unwrap()
            .to_string();
        let thread = {
            let stop = stop.clone();
            let fail = fail.clone();
            let restores = restores.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut stream = stream.unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(&stream);
                    let mut first = String::new();
                    reader.read_line(&mut first).unwrap();
                    let path = first.split_whitespace().nth(1).unwrap();
                    let mut length = 0;
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        if header == "\r\n" {
                            break;
                        }
                        if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let request: serde_json::Value =
                        serde_json::from_slice(&body).unwrap_or(json!({}));
                    let response = match path {
                        "/v1/info" => json!({"name":"Recovery fixture", "nuts":{}}),
                        "/v1/keysets" => json!({"keysets":[{"id":id,"unit":"sat","active":false,"input_fee_ppk":0}]}),
                        p if p.starts_with("/v1/keys") => json!({"keysets":[{"id":id,"unit":"sat","keys":keys}]}),
                        "/v1/restore" => {
                            restores.fetch_add(1, Ordering::SeqCst);
                            if fail.load(Ordering::SeqCst) {
                                json!({"code":10000,"error":"private SDK details"})
                            } else {
                                let mut found = vec![];
                                let mut signed = vec![];
                                for (output, signature) in outputs.iter().zip(&signatures) {
                                    if request["outputs"].as_array().unwrap().iter().any(|item| item["B_"] == json!(output.blinded_secret)) {
                                        found.push(output); signed.push(signature);
                                    }
                                }
                                json!({"outputs":found,"signatures":signed})
                            }
                        }
                        "/v1/checkstate" => json!({"states":request["Ys"].as_array().unwrap().iter().map(|y| json!({"Y":y,"state":if y == &json!(unspent) {"UNSPENT"} else {"SPENT"}})).collect::<Vec<_>>()}),
                        other => panic!("Unexpected mint operation: {other}"),
                    }.to_string();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                }
            })
        };
        Self {
            url,
            stop,
            fail,
            restores,
            thread: Some(thread),
        }
    }
}

impl Drop for MintFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        self.thread.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn importing_recovers_unspent_funds_and_persists_them() {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = import_seed(words, "").unwrap();
    let storage = [9; 64];
    let mint = MintFixture::new(&seed);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    initialize_wallet(&path, &storage, &seed, words, false, &mint.url)
        .await
        .unwrap();
    // Creation must remain offline and must not run recovery.
    prepare_account_mint(&path, &storage, &mint.url, false)
        .await
        .unwrap();
    assert_eq!(mint.restores.load(Ordering::SeqCst), 0);
    let fresh = open_path(path.clone(), &storage, false).await.unwrap();
    recover_on_open(&fresh, &path, &storage).await.unwrap();
    assert_eq!(mint.restores.load(Ordering::SeqCst), 0);
    drop(fresh);
    assert_eq!(
        view(&open_path(path.clone(), &storage, false).await.unwrap())
            .await
            .unwrap()
            .balance,
        0
    );

    mint.fail.store(true, Ordering::SeqCst);
    // Import itself works offline; loading owns the retryable network scan.
    prepare_account_mint(&path, &storage, &mint.url, true)
        .await
        .unwrap();
    let wallet = open_path(path.clone(), &storage, false).await.unwrap();
    let failure = recover_on_open(&wallet, &path, &storage).await.unwrap_err();
    assert_eq!(import_error(failure), WalletFailure::Recovery.to_string());
    assert_eq!(recovery_scan(&path, &storage, None).unwrap(), Some(false));
    drop(wallet);
    mint.fail.store(false, Ordering::SeqCst);
    let wallet = open_path(path.clone(), &storage, false).await.unwrap();
    recover_on_open(&wallet, &path, &storage).await.unwrap();
    assert!(mint.restores.load(Ordering::SeqCst) >= 5);
    assert_eq!(view(&wallet).await.unwrap().balance, 8);
    assert_eq!(recovery_scan(&path, &storage, None).unwrap(), Some(true));
    drop(wallet);
    let count = mint.restores.load(Ordering::SeqCst);
    let reopened = open_path(path.clone(), &storage, false).await.unwrap();
    recover_on_open(&reopened, &path, &storage).await.unwrap();
    assert_eq!(mint.restores.load(Ordering::SeqCst), count);
    drop(reopened);
    // Repeated import must not count recovered proofs twice.
    prepare_account_mint(&path, &storage, &mint.url, true)
        .await
        .unwrap();
    let reopened = open_path(path.clone(), &storage, false).await.unwrap();
    recover_on_open(&reopened, &path, &storage).await.unwrap();
    assert_eq!(view(&reopened).await.unwrap().balance, 8);

    // Already-imported empty wallets have no scan record yet.
    let earlier = temp.path().join("earlier.sqlite");
    initialize_wallet(&earlier, &storage, &seed, words, false, &mint.url)
        .await
        .unwrap();
    let wallet = open_path(earlier.clone(), &storage, false).await.unwrap();
    assert_eq!(recovery_scan(&earlier, &storage, None).unwrap(), None);
    recover_on_open(&wallet, &earlier, &storage).await.unwrap();
    assert_eq!(view(&wallet).await.unwrap().balance, 8);

    // Each newly chosen mint needs its own scan, even if the original is done.
    let other_mint = MintFixture::new(&seed);
    let slot = mint_slot(&path, &storage, &other_mint.url).await.unwrap();
    let other_path = slot_path(&path, &slot).unwrap();
    let other = open_path(other_path.clone(), &storage, true).await.unwrap();
    recover_on_open(&other, &other_path, &storage)
        .await
        .unwrap();
    assert_eq!(view(&other).await.unwrap().balance, 8);
    assert!(other_mint.restores.load(Ordering::SeqCst) > 0);
}
