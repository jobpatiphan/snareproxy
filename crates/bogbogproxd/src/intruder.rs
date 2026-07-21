//! Intruder (§5.1) — fuzz a request template by substituting a marker with each
//! payload, running them bounded-parallel through the repeater engine.

use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use bogbogprox_core::model::{Header, HttpRequest, Source};
use bogbogprox_core::store::FlowStore;
use tokio::sync::{broadcast, Semaphore};

use bogbogprox_core::model::FlowEvent;

use crate::repeater;

fn sub(text: &str, marker: &str, payload: &str) -> String {
    if marker.is_empty() {
        text.to_string()
    } else {
        text.replace(marker, payload)
    }
}

/// Run `payloads` against `base`, substituting `marker` in the URL, header
/// values, and body. Up to `concurrency` requests run at once. Returns one
/// result row per payload (unordered).
pub async fn run(
    store: &Arc<dyn FlowStore>,
    events: &broadcast::Sender<FlowEvent>,
    base: &HttpRequest,
    marker: &str,
    payloads: Vec<String>,
    concurrency: usize,
) -> Vec<Value> {
    let sem = Arc::new(Semaphore::new(concurrency.clamp(1, 64)));
    let base_url = base.url();
    let mut handles = Vec::with_capacity(payloads.len());

    for payload in payloads {
        let permit = sem.clone().acquire_owned().await.expect("semaphore");
        let store = store.clone();
        let events = events.clone();
        let method = base.method.clone();
        let url = sub(&base_url, marker, &payload);
        let headers: Vec<Header> = base
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), sub(v, marker, &payload)))
            .collect();
        let body = sub(&String::from_utf8_lossy(&base.body), marker, &payload).into_bytes();

        handles.push(tokio::spawn(async move {
            let _permit = permit; // released on drop
            let row = match repeater::send(
                &store,
                &events,
                Source::Intruder,
                &method,
                &url,
                &headers,
                body,
            )
            .await
            {
                Ok(flow) => json!({
                    "payload": payload,
                    "flow_id": flow.id,
                    "status": flow.response.as_ref().map(|r| r.status),
                    "length": flow.response.as_ref().map(|r| r.body.len()),
                    "ms": flow.duration_ms,
                }),
                Err(e) => json!({ "payload": payload, "error": e.to_string() }),
            };
            row
        }));
    }

    let mut rows = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(row) = h.await {
            rows.push(row);
        }
    }
    rows
}

/// Convenience: build a base request from a stored flow.
pub fn base_from_flow(store: &Arc<dyn FlowStore>, id: i64) -> Result<HttpRequest> {
    let flow = store
        .get_flow(id)?
        .ok_or_else(|| anyhow::anyhow!("flow {id} not found"))?;
    if flow.request.body_truncated {
        anyhow::bail!("flow {id} has a truncated request body and cannot be replayed safely");
    }
    Ok(flow.request)
}

/// Build a base request from explicit parts (a URL the operator has marked),
/// so the Web UI can send a request template with `§` markers inserted.
pub fn base_from_request(
    method: String,
    url: &str,
    headers: Vec<Header>,
    body: Vec<u8>,
) -> Result<HttpRequest> {
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("bad url: {e}"))?;
    let scheme = parsed.scheme().to_string();
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Ok(HttpRequest {
        method,
        scheme,
        host: parsed.host_str().unwrap_or("").to_string(),
        port,
        path: parsed.path().to_string(),
        query: parsed.query().map(|s| s.to_string()),
        http_version: "HTTP/1.1".into(),
        headers,
        body,
        body_truncated: false,
    })
}
