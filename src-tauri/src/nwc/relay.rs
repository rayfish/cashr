use super::{protocol, store::Pairing, NwcService};
use anyhow::{anyhow, Result};
use futures::{SinkExt, StreamExt};
use nostr::{event::Event, key::PublicKey};
use serde_json::{json, Value};
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tokio::sync::broadcast;
use yawc::{
    frame::{Frame, OpCode},
    WebSocket,
};

pub async fn run(app: AppHandle, mut pairing: Pairing) {
    let (outgoing, _) = broadcast::channel(32);
    let mut delay = 1;
    loop {
        if !app.state::<NwcService>().store.active(&pairing.id) {
            return;
        }
        // Responses are persisted before publishing and replayed after reconnect.
        if connected(&app, &mut pairing, &outgoing).await.is_err() {
            tracing::warn!(
                retry_seconds = delay,
                "NWC relay disconnected; reconnecting"
            );
        }
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = (delay * 2).min(30);
    }
}

async fn connected(
    app: &AppHandle,
    pairing: &mut Pairing,
    outgoing: &broadcast::Sender<String>,
) -> Result<()> {
    let mut replies = outgoing.subscribe();
    let mut socket = tokio::time::timeout(
        Duration::from_secs(10),
        WebSocket::connect(pairing.relay.parse()?).with_options(
            yawc::Options::default()
                .with_max_payload_read(65_536)
                .with_max_read_buffer(131_072),
        ),
    )
    .await??;
    tracing::info!("NWC relay connected");
    let messages = [json!(["EVENT",serde_json::from_str::<Value>(&pairing.info)?]).to_string(),
        json!(["REQ","cashr-nwc",{"kinds":[23194],"authors":[pairing.client],"#p":[pairing.wallet],"since":protocol::now().saturating_sub(300),"limit":32}]).to_string()];
    for msg in messages {
        tokio::time::timeout(Duration::from_secs(10), socket.send(Frame::text(msg))).await??;
    }
    for reply in app.state::<NwcService>().store.recent(&pairing.id)? {
        let msg = json!(["EVENT", serde_json::from_str::<Value>(&reply)?]).to_string();
        tokio::time::timeout(Duration::from_secs(10), socket.send(Frame::text(msg))).await??;
    }
    let client = PublicKey::from_hex(&pairing.client)?;
    let wallet = PublicKey::from_hex(&pairing.wallet)?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            reply = replies.recv() => {
                let reply = reply?;
                let msg = json!(["EVENT",serde_json::from_str::<Value>(&reply)?]).to_string();
                tokio::time::timeout(Duration::from_secs(10),socket.send(Frame::text(msg))).await??;
            }
            _ = heartbeat.tick() => {
                // Refresh discovery for existing connections once their keys are unlocked.
                if serde_json::from_str::<Value>(&pairing.info)?["content"] != protocol::METHODS {
                    let state = app.state::<crate::state::AppState>();
                    if state.session.vault().holds(signer_core::account::AccountId::new(pairing.account)) {
                        let info = protocol::info(&super::keys(app, &state, pairing)?)?;
                        let encoded = serde_json::to_string(&info)?;
                        app.state::<NwcService>().store.update_info(&pairing.id, &encoded)?;
                        pairing.info = encoded;
                        tokio::time::timeout(Duration::from_secs(10), socket.send(Frame::text(json!(["EVENT", info]).to_string()))).await??;
                    }
                }
                tokio::time::timeout(Duration::from_secs(10),socket.send(Frame::ping(Vec::new()))).await??;
            }
            frame = socket.next() => {
                let frame = frame.ok_or_else(|| anyhow!("relay closed"))?;
                if frame.opcode() != OpCode::Text || frame.payload().len() > 65_536 { continue; }
                let Ok(message) = serde_json::from_slice::<Value>(frame.payload()) else { continue; };
                if message[0] == "OK" && message[2] == false { tracing::warn!("NWC relay rejected an event"); }
                if message[0] == "CLOSED" { tracing::warn!("NWC relay closed subscription"); return Err(anyhow!("subscription closed")); }
                if message[0] != "EVENT" || message[1] != "cashr-nwc" { continue; }
                let Ok(event) = serde_json::from_value::<Event>(message[2].clone()) else { continue; };
                if !protocol::valid(&event, client, wallet, pairing.created) { continue; }
                let handle = app.clone(); let pairing = pairing.clone(); let outgoing = outgoing.clone();
                // Acquire before spawning so a relay cannot create unbounded tasks.
                let service = app.state::<NwcService>();
                let Ok(permit) = service.limit.clone().try_acquire_owned() else { continue; };
                tauri::async_runtime::spawn(async move {
                    let _permit = permit;
                    if super::handle(&handle, &pairing, event, &outgoing).await.is_err() {
                        tracing::warn!("NWC request handling failed");
                    }
                });
            }
        }
    }
}
