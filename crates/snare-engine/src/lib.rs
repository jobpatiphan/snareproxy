//! `snare-engine` — the TLS-intercepting proxy data-plane (§6).
//!
//! Built on [hudsucker] (hyper + rustls + rcgen). It captures every
//! request/response pair, writes it through the [`FlowStore`] port, and emits
//! [`FlowEvent`]s for realtime frontends.
//!
//! Phase-0 correlation of request→response is per-connection FIFO (correct for
//! HTTP/1.1 keep-alive; HTTP/2 multiplexing is a Phase-1 refinement).

pub mod ca;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{
        header::{HeaderName, HeaderValue},
        Request, Response, StatusCode, Uri,
    },
    rcgen::{CertificateParams, KeyPair},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use snare_core::intercept::{Decision, Intercept};
use snare_core::model::{
    FlowEvent, FlowSummary, Header, HttpRequest, HttpResponse, Source,
};
use snare_core::store::FlowStore;
use tokio::sync::broadcast;

pub use ca::{generate_ca, GeneratedCa};

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
    /// Outstanding (flow_id, started) pairs, oldest first.
    pending: VecDeque<(i64, Instant)>,
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
        let (mut parts, body) = req.into_parts();
        let bytes = match body.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                // couldn't buffer body — forward an empty one rather than drop
                return Request::from_parts(parts, Body::empty()).into();
            }
        };

        let uri = &parts.uri;
        let host_hdr = parts
            .headers
            .get(hudsucker::hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(':').next().unwrap_or(s).to_string());
        let scheme = uri.scheme_str().map(|s| s.to_string()).unwrap_or_else(|| {
            if uri.port_u16() == Some(443) {
                "https".into()
            } else {
                "https".into() // MITM'd origin-form requests are TLS
            }
        });
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
            body: bytes.to_vec(),
        };

        // Interactive intercept (§5.1): hold the request at the breakpoint until
        // the operator forwards (optionally edited) or drops it.
        let mut forwarded_bytes = bytes;
        if self.intercept.enabled() {
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
                            b"dropped by Snare",
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
                    forwarded_bytes = bytes::Bytes::from(request.body.clone());
                    rebuild_parts(&mut parts, &request);
                }
                Err(_) => {} // decision channel dropped — forward as captured
            }
        }

        let ts = snare_core::now_millis();
        match self.store.insert_request(ts, Source::Proxy, &request) {
            Ok(id) => {
                let _ = self.events.send(FlowEvent::FlowNew {
                    summary: summary_of_request(id, ts, &request),
                });
                self.pending.push_back((id, Instant::now()));
            }
            Err(e) => tracing::warn!("store insert_request failed: {e:#}"),
        }

        Request::from_parts(parts, Body::from(Full::new(forwarded_bytes))).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let bytes = match body.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Response::from_parts(parts, Body::empty()),
        };

        let response = HttpResponse {
            status: parts.status.as_u16(),
            http_version: format!("{:?}", parts.version),
            headers: to_headers(&parts.headers),
            body: bytes.to_vec(),
        };

        if let Some((id, started)) = self.pending.pop_front() {
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
            }
        }

        Response::from_parts(parts, Body::from(Full::new(bytes)))
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

/// Run the proxy until `shutdown` resolves.
pub async fn run<F>(
    cfg: EngineConfig,
    store: Arc<dyn FlowStore>,
    events: broadcast::Sender<FlowEvent>,
    intercept: Arc<Intercept>,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let ca = authority(&cfg)?;
    let handler = CaptureHandler {
        store,
        events,
        intercept,
        pending: VecDeque::new(),
    };

    let proxy = Proxy::builder()
        .with_addr(cfg.listen)
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .context("build proxy")?;

    tracing::info!("proxy listening on {}", cfg.listen);
    proxy.start().await.context("proxy run")?;
    Ok(())
}
