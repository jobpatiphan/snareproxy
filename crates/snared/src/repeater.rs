//! Repeater (§5.1 `r`) — resend an arbitrary request and capture the result as
//! a first-class flow, streamed live like any proxied traffic.
//!
//! Unlike the proxy data-plane (hudsucker, inbound), the repeater is an
//! *outbound* client, so it carries its own `reqwest` client with rustls.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use snare_core::model::{
    Flow, FlowEvent, FlowSummary, Header, HttpRequest, HttpResponse, Source,
};
use snare_core::store::FlowStore;
use tokio::sync::broadcast;

/// Hop-by-hop / client-managed headers we must not forward verbatim — reqwest
/// sets its own, and forwarding a stale `accept-encoding` risks a body we can't
/// decode.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
];

fn summary_of_request(id: i64, ts: i64, req: &HttpRequest, source: Source) -> FlowSummary {
    FlowSummary {
        id,
        ts,
        source,
        method: req.method.clone(),
        scheme: req.scheme.clone(),
        host: req.host.clone(),
        port: req.port,
        path: req.path.clone(),
        status: None,
        mime: None,
        resp_size: None,
        duration_ms: None,
    }
}

/// Send `method url` with `headers`/`body`, persist the flow (tagged `source`),
/// and emit live events. Returns the stored flow (with response attached).
pub async fn send(
    store: &Arc<dyn FlowStore>,
    events: &broadcast::Sender<FlowEvent>,
    source: Source,
    method: &str,
    url: &str,
    headers: &[Header],
    body: Vec<u8>,
) -> Result<Flow> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("bad url: {url}"))?;
    let scheme = parsed.scheme().to_string();
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let req_model = HttpRequest {
        method: method.to_string(),
        scheme,
        host,
        port,
        path: parsed.path().to_string(),
        query: parsed.query().map(|s| s.to_string()),
        http_version: "HTTP/1.1".into(),
        headers: headers.to_vec(),
        body: body.clone(),
    };

    // Record the request immediately so it appears in the UI even while in flight.
    let ts = snare_core::now_millis();
    let id = store.insert_request(ts, source, &req_model)?;
    let _ = events.send(FlowEvent::FlowNew {
        summary: summary_of_request(id, ts, &req_model, source),
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // it's a security tool; test broken TLS too
        .build()
        .context("build repeater client")?;
    let rmethod = reqwest::Method::from_bytes(method.as_bytes()).context("bad method")?;
    let mut rb = client.request(rmethod, parsed);
    for (k, v) in headers {
        if SKIP_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
            continue;
        }
        rb = rb.header(k, v);
    }
    if !body.is_empty() {
        rb = rb.body(body);
    }

    let start = Instant::now();
    let resp = rb.send().await.context("repeater request failed")?;
    let status = resp.status().as_u16();
    let http_version = format!("{:?}", resp.version());
    let resp_headers: Vec<Header> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let resp_body = resp.bytes().await.context("read repeater body")?.to_vec();
    let dur = start.elapsed().as_millis() as u64;

    let resp_model = HttpResponse {
        status,
        http_version,
        headers: resp_headers,
        body: resp_body,
    };
    store.attach_response(id, &resp_model, dur)?;

    let mut summary = summary_of_request(id, ts, &req_model, source);
    summary.status = Some(status);
    summary.mime = resp_model.mime().map(|s| s.to_string());
    summary.resp_size = Some(resp_model.body.len() as u64);
    summary.duration_ms = Some(dur);
    let _ = events.send(FlowEvent::FlowUpdate { summary });

    store.get_flow(id)?.context("flow vanished after store")
}
