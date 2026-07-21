//! CDP bridge (#3 initiator, Phase 1) — connect to the embedded browser's Chrome
//! DevTools Protocol and learn which script/line initiated each request, so flows
//! can be tagged with their originator (something a proxy alone cannot see).
//!
//! Best-effort and browser-coupled: it attaches to the throwaway browser launched
//! from the dashboard, keys initiators by request URL, and lets the engine match
//! them onto captured flows. Only works while a CDP browser is attached.

use std::time::Duration;

use anyhow::{Context, Result};
use bogbogprox_core::model::InitiatorSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

/// Cap on remembered URL→initiator entries (cleared wholesale when exceeded).
const MAX_ENTRIES: usize = 8000;

/// Attach to the browser exposing CDP on `debug_port` and stream request
/// initiators into `sink` until it closes. Retries briefly while the browser
/// starts, then gives up quietly.
pub async fn attach(debug_port: u16, sink: InitiatorSink) {
    for attempt in 0..40 {
        match run(debug_port, &sink).await {
            Ok(()) => {
                tracing::info!("cdp: browser session ended (port {debug_port})");
                return;
            }
            Err(e) => {
                if attempt == 0 {
                    tracing::debug!("cdp: waiting for browser debug port {debug_port}: {e:#}");
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
    }
    tracing::warn!("cdp: gave up attaching to browser debug port {debug_port}");
}

async fn run(debug_port: u16, sink: &InitiatorSink) -> Result<()> {
    // Discover the browser-level DevTools websocket.
    let body = reqwest::get(format!("http://127.0.0.1:{debug_port}/json/version"))
        .await
        .context("GET /json/version")?
        .text()
        .await
        .context("read /json/version")?;
    let ver: Value = serde_json::from_str(&body).context("parse /json/version")?;
    let ws_url = ver
        .get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .context("no webSocketDebuggerUrl")?;

    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .context("connect CDP websocket")?;

    // Auto-attach to every page target, flattened so events carry a sessionId.
    let mut next_id = 1i64;
    ws.send(Message::Text(
        json!({"id": next_id, "method": "Target.setDiscoverTargets", "params": {"discover": true}})
            .to_string(),
    ))
    .await?;
    next_id += 1;
    ws.send(Message::Text(
        json!({"id": next_id, "method": "Target.setAutoAttach",
               "params": {"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}})
        .to_string(),
    ))
    .await?;
    next_id += 1;

    tracing::info!("cdp: attached (port {debug_port}); capturing request initiators");

    while let Some(msg) = ws.next().await {
        let text = match msg.context("cdp websocket recv")? {
            Message::Text(t) => t,
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.ok();
                continue;
            }
            Message::Close(_) => break,
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
            "Target.attachedToTarget" => {
                if let Some(session) = v.pointer("/params/sessionId").and_then(|s| s.as_str()) {
                    ws.send(Message::Text(
                        json!({"id": next_id, "method": "Network.enable", "sessionId": session})
                            .to_string(),
                    ))
                    .await
                    .ok();
                    next_id += 1;
                }
            }
            "Network.requestWillBeSent" => {
                if let (Some(url), Some(initiator)) = (
                    v.pointer("/params/request/url").and_then(|u| u.as_str()),
                    v.pointer("/params/initiator"),
                ) {
                    let label = describe_initiator(initiator);
                    if let Ok(mut map) = sink.lock() {
                        if map.len() > MAX_ENTRIES {
                            map.clear();
                        }
                        map.insert(url.to_string(), (label, bogbogprox_core::now_millis()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Turn a CDP `Initiator` object into a short human label.
fn describe_initiator(init: &Value) -> String {
    // A script call stack is the most useful — name the top frame.
    if let Some(frame) = init.pointer("/stack/callFrames/0") {
        let url = frame.get("url").and_then(|u| u.as_str()).unwrap_or("");
        let line = frame.get("lineNumber").and_then(|l| l.as_i64()).unwrap_or(0) + 1;
        let func = frame.get("functionName").and_then(|f| f.as_str()).unwrap_or("");
        let short = short_url(url);
        return if func.is_empty() {
            format!("script {short}:{line}")
        } else {
            format!("script {short}:{line} {func}()")
        };
    }
    match init.get("type").and_then(|t| t.as_str()).unwrap_or("other") {
        "parser" => match init.get("url").and_then(|u| u.as_str()) {
            Some(u) if !u.is_empty() => format!("parser {}", short_url(u)),
            _ => "parser".into(),
        },
        "preload" => "preload".into(),
        "SignedExchange" => "signed-exchange".into(),
        other => other.to_string(),
    }
}

/// Compact a URL down to its filename (or host) for a readable label.
fn short_url(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let path = no_scheme.split(['?', '#']).next().unwrap_or(no_scheme);
    let last = path.rsplit('/').find(|s| !s.is_empty());
    match last {
        Some(name) if name.contains('.') || !path.contains('/') => name.to_string(),
        // directory-style (e.g. host/ or /path/): show host + trailing
        _ => no_scheme.split(['?', '#']).next().unwrap_or(no_scheme).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_initiator_labels_top_frame() {
        let init = json!({
            "type": "script",
            "stack": {"callFrames": [
                {"url": "https://ex.com/static/app.js", "lineNumber": 41, "functionName": "render"}
            ]}
        });
        assert_eq!(describe_initiator(&init), "script app.js:42 render()");
    }

    #[test]
    fn parser_initiator() {
        let init = json!({"type": "parser", "url": "https://ex.com/index.html"});
        assert_eq!(describe_initiator(&init), "parser index.html");
    }

    #[test]
    fn other_initiator() {
        assert_eq!(describe_initiator(&json!({"type": "preload"})), "preload");
    }
}
