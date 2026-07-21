//! `bogbogprox-engine` — the TLS-intercepting proxy data-plane (§6).
//!
//! Built on [hudsucker] (hyper + rustls + rcgen). It captures every
//! request/response pair, writes it through the [`FlowStore`] port, and emits
//! [`FlowEvent`]s for realtime frontends.
//!
//! Request→response correlation is per-connection FIFO. This is correct because
//! we build hudsucker without its `http2` feature, so both the client-facing and
//! upstream connections are HTTP/1.1 — requests are serialized per connection and
//! never multiplexed.

pub mod ca;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use futures::StreamExt;
use http_body_util::{BodyExt, BodyStream, Full, StreamBody};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{
        header::{HeaderName, HeaderValue},
        Request, Response, StatusCode, Uri,
    },
    rcgen::{CertificateParams, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use bogbogprox_core::intercept::{Decision, Intercept, RespDecision};
use bogbogprox_core::model::{
    base64_encode, FlowEvent, FlowSummary, Header, HttpRequest, HttpResponse, Source,
};
use bogbogprox_core::rules::Rules;
use bogbogprox_core::scanner::Scanner;
use bogbogprox_core::session::Vars;
use bogbogprox_core::store::FlowStore;
use bogbogprox_core::ws::WsLog;
use tokio::sync::broadcast;

pub use ca::{generate_ca, GeneratedCa};

/// Maximum request/response prefix retained in memory and persisted. Bodies
/// larger than this are streamed through in full and marked as truncated in
/// the capture model.
pub const MAX_CAPTURE_BODY_BYTES: usize = 16 * 1024 * 1024;

struct CapturedBody {
    wire: Body,
    captured: Vec<u8>,
    truncated: bool,
}

/// Retain at most `limit` bytes while preserving the complete body (including
/// trailers) for forwarding. Once the limit is crossed, the unread remainder
/// stays streaming instead of being accumulated in memory.
async fn capture_body(mut body: Body, limit: usize) -> Result<CapturedBody> {
    let mut frames = Vec::new();
    let mut captured = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;

    while let Some(frame) = body.frame().await {
        let frame = frame.context("read HTTP body frame")?;
        if let Some(data) = frame.data_ref() {
            let remaining = limit.saturating_sub(captured.len());
            if remaining > 0 {
                captured.extend_from_slice(&data[..data.len().min(remaining)]);
            }
            truncated |= data.len() > remaining;
        }
        frames.push(frame);

        if truncated {
            let prefix = futures::stream::iter(frames.into_iter().map(Ok::<_, hudsucker::Error>));
            let rest = BodyStream::new(body);
            return Ok(CapturedBody {
                wire: Body::from(StreamBody::new(prefix.chain(rest))),
                captured,
                truncated: true,
            });
        }
    }

    let frames = futures::stream::iter(frames.into_iter().map(Ok::<_, hudsucker::Error>));
    Ok(CapturedBody {
        wire: Body::from(StreamBody::new(frames)),
        captured,
        truncated: false,
    })
}

/// Runtime configuration for the proxy.
pub struct EngineConfig {
    pub listen: SocketAddr,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
}

/// Per-connection capturing handler. Cloned by hudsucker for each connection.
#[derive(Clone)]
struct CaptureHandler {
    store: Arc<dyn FlowStore>,
    events: broadcast::Sender<FlowEvent>,
    intercept: Arc<Intercept>,
    rules: Arc<Rules>,
    scanner: Arc<Scanner>,
    vars: Arc<Vars>,
    plugins: Arc<bogbogprox_plugin::PluginHost>,
    /// Outstanding (flow_id, started, host) tuples, oldest first. Host lets
    /// response interception honour scope.
    pending: VecDeque<(i64, Instant, String)>,
}

/// Map an edited plugin request back onto the engine model (host/scheme/port are
/// kept — the MITM connection already targets the original host).
fn apply_plugin_req(req: &mut HttpRequest, edited: bogbogprox_plugin::Req) {
    req.method = edited.method;
    req.headers = edited.headers;
    req.body = edited.body;
    if let Ok(uri) = edited.url.parse::<Uri>() {
        req.path = uri.path().to_string();
        req.query = uri.query().map(|q| q.to_string());
    }
}

fn apply_plugin_resp(resp: &mut HttpResponse, edited: bogbogprox_plugin::Resp) {
    resp.status = edited.status;
    resp.headers = edited.headers;
    resp.body = edited.body;
}

fn to_headers(map: &hudsucker::hyper::HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn host_header_name(value: &str) -> String {
    value
        .parse::<hudsucker::hyper::http::uri::Authority>()
        .map(|authority| authority.host().to_string())
        .unwrap_or_else(|_| value.trim_matches(['[', ']']).to_string())
}

/// Apply an (edited) request model back onto the outgoing wire request. Used
/// only after an intercept forward; the MITM'd connection already targets the
/// host, so we keep origin-form and let hyper recompute Content-Length.
fn rebuild_parts(parts: &mut hudsucker::hyper::http::request::Parts, req: &HttpRequest) {
    if let Ok(m) = hudsucker::hyper::Method::from_bytes(req.method.as_bytes()) {
        parts.method = m;
    }
    // Preserve the original scheme/authority (hudsucker routes on them); only
    // swap the path+query so an edited path still reaches the right upstream.
    let mut pq = req.path.clone();
    if let Some(q) = &req.query {
        pq.push('?');
        pq.push_str(q);
    }
    if let Ok(pq) = pq.parse::<hudsucker::hyper::http::uri::PathAndQuery>() {
        let mut builder = Uri::builder();
        if let Some(scheme) = parts.uri.scheme() {
            builder = builder.scheme(scheme.clone());
        }
        if let Some(authority) = parts.uri.authority() {
            builder = builder.authority(authority.clone());
        }
        if let Ok(uri) = builder.path_and_query(pq).build() {
            parts.uri = uri;
        }
    }
    let mut headers = hudsucker::hyper::HeaderMap::new();
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-length") {
            continue; // hyper sets this from the actual body
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.append(name, val);
        }
    }
    parts.headers = headers;
}

/// Apply an (edited) response model back onto the outgoing wire response.
fn rebuild_resp_parts(parts: &mut hudsucker::hyper::http::response::Parts, resp: &HttpResponse) {
    if let Ok(s) = StatusCode::from_u16(resp.status) {
        parts.status = s;
    }
    let mut headers = hudsucker::hyper::HeaderMap::new();
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            continue; // hyper sets this from the actual body
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.append(name, val);
        }
    }
    parts.headers = headers;
}

fn summary_of_request(id: i64, ts: i64, req: &HttpRequest) -> FlowSummary {
    FlowSummary {
        id,
        ts,
        source: Source::Proxy,
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

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // CONNECT establishes the TLS tunnel — hudsucker handles it and then
        // replays the decrypted inner requests through this handler. Capturing
        // the CONNECT itself would desync the request→response FIFO (the tunnel
        // never gets its own response), so forward it untouched.
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }
        // WebSocket upgrades are dispatched by hudsucker to the WS handler; pass
        // them through untouched so buffering/rebuilding the body doesn't disturb
        // the upgrade. Capture happens per-message in `WsHandler`.
        if req
            .headers()
            .get(hudsucker::hyper::header::UPGRADE)
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            .unwrap_or(false)
        {
            return req.into();
        }
        let (mut parts, body) = req.into_parts();
        let captured_body = match capture_body(body, MAX_CAPTURE_BODY_BYTES).await {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("request body read failed: {e:#}");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("invalid request body"))
                    .unwrap_or_else(|_| Response::new(Body::empty()))
                    .into();
            }
        };
        let CapturedBody {
            wire,
            captured,
            truncated,
        } = captured_body;

        let uri = &parts.uri;
        let host_hdr = parts
            .headers
            .get(hudsucker::hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(host_header_name);
        // Origin-form requests seen here are the decrypted side of a CONNECT.
        let scheme = uri
            .scheme_str()
            .map(str::to_string)
            .unwrap_or_else(|| "https".into());
        let host = uri
            .host()
            .map(|s| s.to_string())
            .or(host_hdr)
            .unwrap_or_else(|| "unknown".into());
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "http" { 80 } else { 443 });

        let mut request = HttpRequest {
            method: parts.method.as_str().to_string(),
            scheme,
            host,
            port,
            path: uri.path().to_string(),
            query: uri.query().map(|q| q.to_string()),
            http_version: format!("{:?}", parts.version),
            headers: to_headers(&parts.headers),
            body: captured,
            body_truncated: truncated,
        };

        // Match & Replace: automatic regex rewrites (with {{var}} injection)
        // before anything else sees it.
        let mut dirty = self
            .rules
            .apply_request(&mut request, &self.vars.snapshot());

        // WASM plugins: on-request hooks, after M&R and before intercept.
        // Skipped for truncated bodies (the plugin would see a partial body).
        if !self.plugins.is_empty() && !request.body_truncated {
            let preq = bogbogprox_plugin::Req {
                method: request.method.clone(),
                url: request.url(),
                headers: request.headers.clone(),
                body: request.body.clone(),
            };
            match self.plugins.on_request(preq) {
                bogbogprox_plugin::Decision::Drop => {
                    let resp = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(Full::new(bytes::Bytes::from_static(
                            b"dropped by plugin",
                        ))))
                        .expect("static drop response");
                    return resp.into();
                }
                bogbogprox_plugin::Decision::Forward(edited) => {
                    apply_plugin_req(&mut request, edited);
                    dirty = true;
                }
                bogbogprox_plugin::Decision::Unchanged => {}
            }
        }

        // Interactive intercept (§5.1): hold the request at the breakpoint until
        // the operator forwards (optionally edited) or drops it.
        if self.intercept.enabled() && self.intercept.in_scope(&request.host) {
            let (iid, rx) = self.intercept.register(request.clone());
            let _ = self.events.send(FlowEvent::InterceptPaused {
                id: iid,
                request: request.clone(),
            });
            match rx.await {
                Ok(Decision::Drop) => {
                    let _ = self.events.send(FlowEvent::InterceptResolved {
                        id: iid,
                        action: "drop".into(),
                    });
                    let resp = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(Full::new(bytes::Bytes::from_static(
                            b"dropped by BogBogProx",
                        ))))
                        .expect("static drop response");
                    return resp.into();
                }
                Ok(Decision::Forward(edited)) => {
                    let _ = self.events.send(FlowEvent::InterceptResolved {
                        id: iid,
                        action: "forward".into(),
                    });
                    request = *edited;
                    dirty = true;
                }
                Err(_) => {} // decision channel dropped — forward as captured
            }
        }

        // Rebuild the wire request once if rules or intercept changed it.
        if dirty {
            rebuild_parts(&mut parts, &request);
        }
        let forwarded_body = if dirty && !request.body_truncated {
            Body::from(Full::new(bytes::Bytes::from(request.body.clone())))
        } else {
            wire
        };

        let ts = bogbogprox_core::now_millis();
        match self.store.insert_request(ts, Source::Proxy, &request) {
            Ok(id) => {
                let _ = self.events.send(FlowEvent::FlowNew {
                    summary: summary_of_request(id, ts, &request),
                });
                self.pending
                    .push_back((id, Instant::now(), request.host.clone()));
            }
            Err(e) => tracing::warn!("store insert_request failed: {e:#}"),
        }

        Request::from_parts(parts, forwarded_body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        let captured_body = match capture_body(body, MAX_CAPTURE_BODY_BYTES).await {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("response body read failed: {e:#}");
                parts.status = StatusCode::BAD_GATEWAY;
                parts.headers.clear();
                let msg = b"upstream response body failed".to_vec();
                CapturedBody {
                    wire: Body::from(Full::new(bytes::Bytes::from(msg.clone()))),
                    captured: msg,
                    truncated: false,
                }
            }
        };
        let CapturedBody {
            wire,
            captured,
            truncated,
        } = captured_body;

        let mut response = HttpResponse {
            status: parts.status.as_u16(),
            http_version: format!("{:?}", parts.version),
            headers: to_headers(&parts.headers),
            body: captured,
            body_truncated: truncated,
        };

        // Match & Replace on the response.
        let mut dirty = self
            .rules
            .apply_response(&mut response, &self.vars.snapshot());

        // WASM plugins: on-response hooks (skipped for truncated bodies).
        if !self.plugins.is_empty() && !response.body_truncated {
            let presp = bogbogprox_plugin::Resp {
                status: response.status,
                headers: response.headers.clone(),
                body: response.body.clone(),
            };
            match self.plugins.on_response(presp) {
                bogbogprox_plugin::Decision::Drop => {
                    response = HttpResponse {
                        status: StatusCode::FORBIDDEN.as_u16(),
                        http_version: response.http_version.clone(),
                        headers: vec![],
                        body: b"dropped by plugin".to_vec(),
                        body_truncated: false,
                    };
                    dirty = true;
                }
                bogbogprox_plugin::Decision::Forward(edited) => {
                    apply_plugin_resp(&mut response, edited);
                    dirty = true;
                }
                bogbogprox_plugin::Decision::Unchanged => {}
            }
        }

        let entry = self.pending.pop_front();
        let host = entry.as_ref().map(|(_, _, h)| h.as_str()).unwrap_or("");

        // Interactive intercept — response side. Hold it if response intercept is
        // on and the originating host is in scope.
        if self.intercept.responses_enabled() && self.intercept.in_scope(host) {
            let (iid, rx) = self.intercept.register_response(response.clone());
            let _ = self.events.send(FlowEvent::InterceptRespPaused {
                id: iid,
                response: response.clone(),
            });
            match rx.await {
                Ok(RespDecision::Drop) => {
                    let _ = self.events.send(FlowEvent::InterceptResolved {
                        id: iid,
                        action: "drop".into(),
                    });
                    response = HttpResponse {
                        status: StatusCode::FORBIDDEN.as_u16(),
                        http_version: response.http_version.clone(),
                        headers: vec![],
                        body: b"dropped by BogBogProx".to_vec(),
                        body_truncated: false,
                    };
                    dirty = true;
                }
                Ok(RespDecision::Forward(edited)) => {
                    let _ = self.events.send(FlowEvent::InterceptResolved {
                        id: iid,
                        action: "forward".into(),
                    });
                    response = *edited;
                    dirty = true;
                }
                Err(_) => {}
            }
        }

        if dirty {
            rebuild_resp_parts(&mut parts, &response);
        }
        let response_body = if dirty && !response.body_truncated {
            Body::from(Full::new(bytes::Bytes::from(response.body.clone())))
        } else {
            wire
        };

        if let Some((id, started, _)) = entry {
            let dur = started.elapsed().as_millis() as u64;
            if let Err(e) = self.store.attach_response(id, &response, dur) {
                tracing::warn!("store attach_response failed: {e:#}");
            } else if let Ok(Some(flow)) = self.store.get_flow(id) {
                let mut summary = summary_of_request(id, flow.ts, &flow.request);
                summary.status = Some(response.status);
                summary.mime = response.mime().map(|s| s.to_string());
                summary.resp_size = Some(response.body.len() as u64);
                summary.duration_ms = Some(dur);
                let _ = self.events.send(FlowEvent::FlowUpdate { summary });
                // Passive scan the completed flow; stream any new findings.
                for finding in self.scanner.scan(&flow) {
                    let _ = self.events.send(FlowEvent::Finding { finding });
                }
            }
        }

        Response::from_parts(parts, response_body)
    }
}

/// Capture-only WebSocket handler: logs every message and forwards it unchanged.
#[derive(Clone)]
struct WsHandler {
    events: broadcast::Sender<FlowEvent>,
    wslog: Arc<WsLog>,
}

impl WebSocketHandler for WsHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (host, direction) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => {
                (dst.host().unwrap_or("").to_string(), "send")
            }
            WebSocketContext::ServerToClient { src, .. } => {
                (src.host().unwrap_or("").to_string(), "recv")
            }
        };
        let (kind, data, size) = match &message {
            Message::Text(t) => ("text", t.clone(), t.len()),
            Message::Binary(b) => ("binary", base64_encode(b), b.len()),
            Message::Ping(b) => ("ping", String::new(), b.len()),
            Message::Pong(b) => ("pong", String::new(), b.len()),
            Message::Close(_) => ("close", String::new(), 0),
            Message::Frame(_) => ("frame", String::new(), 0),
        };
        let msg = self
            .wslog
            .record(bogbogprox_core::now_millis(), host, direction, kind, data, size);
        let _ = self.events.send(FlowEvent::WsMessage { msg });
        Some(message) // capture only — forward unchanged
    }
}

/// Load a persisted CA (key + cert PEM) into a hudsucker authority.
fn authority(cfg: &EngineConfig) -> Result<RcgenAuthority> {
    let key_pair = KeyPair::from_pem(&cfg.ca_key_pem).context("parse CA key")?;
    let ca_cert = CertificateParams::from_ca_cert_pem(&cfg.ca_cert_pem)
        .context("parse CA cert")?
        .self_signed(&key_pair)
        .context("reconstruct CA cert")?;
    Ok(RcgenAuthority::new(
        key_pair,
        ca_cert,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}

/// Collaborators shared by each per-connection capture handler.
pub struct EngineServices {
    pub store: Arc<dyn FlowStore>,
    pub events: broadcast::Sender<FlowEvent>,
    pub intercept: Arc<Intercept>,
    pub rules: Arc<Rules>,
    pub scanner: Arc<Scanner>,
    pub vars: Arc<Vars>,
    pub wslog: Arc<WsLog>,
    pub plugins: Arc<bogbogprox_plugin::PluginHost>,
}

/// Run the proxy until `shutdown` resolves.
pub async fn run<F>(cfg: EngineConfig, services: EngineServices, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let ca = authority(&cfg)?;
    let EngineServices {
        store,
        events,
        intercept,
        rules,
        scanner,
        vars,
        wslog,
        plugins,
    } = services;
    let handler = CaptureHandler {
        store,
        events: events.clone(),
        intercept,
        rules,
        scanner,
        vars,
        plugins,
        pending: VecDeque::new(),
    };
    let ws_handler = WsHandler { events, wslog };

    let proxy = Proxy::builder()
        .with_addr(cfg.listen)
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_websocket_handler(ws_handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .context("build proxy")?;

    tracing::info!("proxy listening on {}", cfg.listen);
    proxy.start().await.context("proxy run")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_body_is_forwarded_in_full_and_capture_is_bounded() {
        let input = bytes::Bytes::from_static(b"abcdefghij");
        let captured = capture_body(Body::from(Full::new(input.clone())), 4)
            .await
            .unwrap();
        assert_eq!(captured.captured, b"abcd");
        assert!(captured.truncated);
        let forwarded = captured.wire.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, input);
    }

    #[tokio::test]
    async fn small_body_is_captured_without_truncation() {
        let captured = capture_body(Body::from("hello"), 16).await.unwrap();
        assert_eq!(captured.captured, b"hello");
        assert!(!captured.truncated);
        assert_eq!(captured.wire.collect().await.unwrap().to_bytes(), "hello");
    }
}
