//! REST API (§8) — the surface every frontend and the MCP server can use.
//!
//! Beyond plain REST it exposes a Server-Sent-Events stream (`/api/v1/stream`)
//! so any browser can watch captured traffic — and AI activity — the instant it
//! happens, and an activity sink (`POST /api/v1/activity`) the MCP server pushes
//! to so the operator sees exactly what an agent is doing.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use snare_core::intercept::{Edit, Intercept, RespEdit};
use snare_core::model::{Activity, FlowEvent, Header};
use snare_core::rules::{Part, Rules};
use snare_core::scanner::Scanner;
use snare_core::store::{FlowQuery, FlowStore};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

use crate::{active_scan, intruder, repeater};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn FlowStore>,
    /// Live event bus shared with the proxy engine and the activity sink.
    pub events: broadcast::Sender<FlowEvent>,
    /// Interactive intercept breakpoint shared with the engine.
    pub intercept: Arc<Intercept>,
    /// Match & Replace rules shared with the engine.
    pub rules: Arc<Rules>,
    /// Passive scanner shared with the engine.
    pub scanner: Arc<Scanner>,
    /// Captured WebSocket messages shared with the engine.
    pub wslog: Arc<snare_core::ws::WsLog>,
    /// Where persisted settings (rules/scope/scanner) are written.
    pub config_path: std::path::PathBuf,
}

impl AppState {
    /// Persist rules/scope/scanner after a mutation. Best-effort.
    fn persist(&self) {
        let snap = crate::config::snapshot(&self.rules, &self.intercept, &self.scanner);
        crate::config::save(&self.config_path, &snap);
    }
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub search: Option<String>,
    pub host: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/v1/health", get(health))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/flows", get(list_flows))
        .route("/api/v1/flows/:id", get(get_flow))
        .route("/api/v1/stream", get(stream))
        .route("/api/v1/activity", post(post_activity))
        .route("/api/v1/repeater", post(repeater_custom))
        .route("/api/v1/repeater/from/:id", post(repeater_from))
        .route("/api/v1/intercept", get(intercept_get).post(intercept_toggle))
        .route("/api/v1/intercept/scope", post(intercept_scope))
        .route("/api/v1/intercept/:id/forward", post(intercept_forward))
        .route("/api/v1/intercept/:id/drop", post(intercept_drop))
        .route("/api/v1/intercept/:id/forward-response", post(intercept_forward_resp))
        .route("/api/v1/intercept/:id/drop-response", post(intercept_drop_resp))
        .route("/api/v1/rules", get(rules_list).post(rules_add))
        .route("/api/v1/rules/:id", axum::routing::delete(rules_delete))
        .route("/api/v1/rules/:id/toggle", post(rules_toggle))
        .route("/api/v1/intruder", post(intruder_run))
        .route("/api/v1/findings", get(findings_list).post(scanner_toggle))
        .route("/api/v1/scan/active", post(active_scan_run))
        .route("/api/v1/ws", get(ws_list).post(ws_clear))
        .with_state(state)
}

/// The self-contained live dashboard (§9 web frontend, Phase-1 slice).
async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "snared" }))
}

async fn stats(State(st): State<AppState>) -> Response {
    match st.store.count() {
        Ok(count) => Json(json!({ "flows": count })).into_response(),
        Err(e) => err(e),
    }
}

async fn list_flows(State(st): State<AppState>, Query(p): Query<ListParams>) -> Response {
    let q = FlowQuery {
        search: p.search,
        host: p.host,
        limit: p.limit.unwrap_or(200),
        offset: p.offset.unwrap_or(0),
    };
    match st.store.list_flows(&q) {
        Ok(flows) => Json(flows).into_response(),
        Err(e) => err(e),
    }
}

async fn get_flow(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
    match st.store.get_flow(id) {
        Ok(Some(flow)) => Json(flow).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
        Err(e) => err(e),
    }
}

/// Server-Sent-Events firehose: every flow + AI activity as it happens.
async fn stream(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.events.subscribe();
    // A lagged receiver (slow client) yields an error we simply skip rather than
    // tear the connection down — the client can re-sync via REST if it cares.
    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(ev) => serde_json::to_string(&ev)
            .ok()
            .map(|json| Ok(Event::default().data(json))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Sink for AI/automation activity — the MCP server POSTs here so the operator
/// watches, live, what the agent is doing. Best-effort broadcast; never stored.
async fn post_activity(State(st): State<AppState>, Json(mut a): Json<Activity>) -> Response {
    if a.ts == 0 {
        a.ts = snare_core::now_millis();
    }
    let _ = st.events.send(FlowEvent::Activity { activity: a });
    Json(json!({ "ok": true })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RepeaterBody {
    pub method: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub headers: Vec<Header>,
    /// Request body as UTF-8 text (Phase-1 simplification).
    #[serde(default)]
    pub body: String,
}

/// Send a fully custom request through the repeater.
async fn repeater_custom(State(st): State<AppState>, Json(b): Json<RepeaterBody>) -> Response {
    let (Some(method), Some(url)) = (b.method, b.url) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "method and url required" })))
            .into_response();
    };
    match repeater::send(&st.store, &st.events, snare_core::model::Source::Repeater, &method, &url, &b.headers, b.body.into_bytes()).await
    {
        Ok(flow) => Json(flow).into_response(),
        Err(e) => err(e),
    }
}

/// Resend an existing flow's request verbatim (the `r` hotkey / "Resend" button).
async fn repeater_from(State(st): State<AppState>, Path(id): Path<i64>) -> Response {
    let flow = match st.store.get_flow(id) {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "flow not found" })))
                .into_response()
        }
        Err(e) => return err(e),
    };
    let r = &flow.request;
    match repeater::send(&st.store, &st.events, snare_core::model::Source::Repeater, &r.method, &r.url(), &r.headers, r.body.clone()).await
    {
        Ok(flow) => Json(flow).into_response(),
        Err(e) => err(e),
    }
}

// ---- Interactive intercept (§5.1) ----

/// Current intercept state (both toggles + scope) and the held queues.
async fn intercept_get(State(st): State<AppState>) -> Response {
    let queue: Vec<_> = st
        .intercept
        .queue()
        .into_iter()
        .map(|(id, req)| json!({ "id": id, "kind": "request", "request": req }))
        .collect();
    let resp_queue: Vec<_> = st
        .intercept
        .queue_responses()
        .into_iter()
        .map(|(id, resp)| json!({ "id": id, "kind": "response", "response": resp }))
        .collect();
    Json(json!({
        "on": st.intercept.enabled(),
        "responses": st.intercept.responses_enabled(),
        "scope": st.intercept.scope(),
        "queue": queue,
        "resp_queue": resp_queue,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ToggleBody {
    pub on: Option<bool>,
    pub responses: Option<bool>,
}

/// Toggle request and/or response intercept. Turning a side off releases what it
/// was holding so nothing hangs.
async fn intercept_toggle(State(st): State<AppState>, Json(b): Json<ToggleBody>) -> Response {
    if let Some(on) = b.on {
        st.intercept.set_enabled(on);
        if !on {
            st.intercept.release_requests();
        }
    }
    if let Some(r) = b.responses {
        st.intercept.set_responses_enabled(r);
        if !r {
            st.intercept.release_responses();
        }
    }
    let on = st.intercept.enabled();
    let responses = st.intercept.responses_enabled();
    let _ = st.events.send(FlowEvent::InterceptState { on, responses });
    Json(json!({ "on": on, "responses": responses })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ScopeBody {
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Set the intercept scope (host substrings; empty = every host).
async fn intercept_scope(State(st): State<AppState>, Json(b): Json<ScopeBody>) -> Response {
    st.intercept.set_scope(b.hosts);
    st.persist();
    Json(json!({ "scope": st.intercept.scope() })).into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct RespEditBody {
    pub status: Option<u16>,
    pub headers: Option<Vec<Header>>,
    pub body: Option<String>,
}

/// Return a held response, applying any edits.
async fn intercept_forward_resp(
    State(st): State<AppState>,
    Path(id): Path<u64>,
    body: Option<Json<RespEditBody>>,
) -> Response {
    let edit = body.map(|Json(e)| RespEdit {
        status: e.status,
        headers: e.headers,
        body: e.body.map(String::into_bytes),
    });
    if st.intercept.forward_response(id, edit) {
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such held response" }))).into_response()
    }
}

/// Drop a held response.
async fn intercept_drop_resp(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    if st.intercept.discard_response(id) {
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such held response" }))).into_response()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct EditBody {
    pub method: Option<String>,
    pub path: Option<String>,
    /// Present with a string sets the query; present as null clears it; absent keeps it.
    #[serde(default, deserialize_with = "double_option")]
    pub query: Option<Option<String>>,
    pub headers: Option<Vec<Header>>,
    /// Request body as UTF-8 text.
    pub body: Option<String>,
}

/// Distinguish "field absent" from "field present but null" for `query`.
fn double_option<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(d)?))
}

/// Forward a held request, applying any edits in the body.
async fn intercept_forward(
    State(st): State<AppState>,
    Path(id): Path<u64>,
    body: Option<Json<EditBody>>,
) -> Response {
    let edit = body.map(|Json(e)| Edit {
        method: e.method,
        path: e.path,
        query: e.query,
        headers: e.headers,
        body: e.body.map(String::into_bytes),
    });
    if st.intercept.forward(id, edit) {
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such held request" }))).into_response()
    }
}

/// Drop a held request.
async fn intercept_drop(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    if st.intercept.discard(id) {
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such held request" }))).into_response()
    }
}

// ---- Match & Replace rules ----

async fn rules_list(State(st): State<AppState>) -> Response {
    Json(st.rules.list()).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RuleBody {
    #[serde(default)]
    pub name: String,
    pub part: Part,
    pub pattern: String,
    #[serde(default)]
    pub replace: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}

async fn rules_add(State(st): State<AppState>, Json(b): Json<RuleBody>) -> Response {
    match st.rules.add(b.name, b.part, b.pattern, b.replace, b.enabled) {
        Ok(spec) => {
            st.persist();
            Json(spec).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

async fn rules_delete(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    if st.rules.remove(id) {
        st.persist();
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such rule" }))).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleToggle {
    pub on: bool,
}

async fn rules_toggle(
    State(st): State<AppState>,
    Path(id): Path<u64>,
    Json(b): Json<RuleToggle>,
) -> Response {
    if st.rules.set_enabled(id, b.on) {
        st.persist();
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such rule" }))).into_response()
    }
}

// ---- Intruder ----

#[derive(Debug, Deserialize)]
pub struct IntruderBody {
    /// Flow id to use as the request template (used when `base` is absent).
    pub from_flow: Option<i64>,
    /// Explicit request template (from the Web editor, with markers inserted).
    pub base: Option<RepeaterBody>,
    /// Marker string to substitute (default "§").
    #[serde(default = "default_marker")]
    pub marker: String,
    pub payloads: Vec<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}
fn default_marker() -> String {
    "§".into()
}
fn default_concurrency() -> usize {
    10
}

/// Fuzz a request template with a list of payloads, bounded-parallel.
async fn intruder_run(State(st): State<AppState>, Json(b): Json<IntruderBody>) -> Response {
    let base = match (b.base, b.from_flow) {
        (Some(rb), _) => {
            let (Some(method), Some(url)) = (rb.method, rb.url) else {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": "base needs method and url" }))).into_response();
            };
            match intruder::base_from_request(method, &url, rb.headers, rb.body.into_bytes()) {
                Ok(r) => r,
                Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
            }
        }
        (None, Some(id)) => match intruder::base_from_flow(&st.store, id) {
            Ok(r) => r,
            Err(e) => return (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
        },
        (None, None) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "from_flow or base required" }))).into_response()
        }
    };
    let n = b.payloads.len();
    let results = intruder::run(&st.store, &st.events, &base, &b.marker, b.payloads, b.concurrency).await;
    Json(json!({ "count": n, "results": results })).into_response()
}

// ---- Passive scanner ----

async fn findings_list(State(st): State<AppState>) -> Response {
    Json(json!({ "on": st.scanner.enabled(), "findings": st.scanner.list() })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ScannerToggle {
    pub on: Option<bool>,
    #[serde(default)]
    pub clear: bool,
}

async fn scanner_toggle(State(st): State<AppState>, Json(b): Json<ScannerToggle>) -> Response {
    if let Some(on) = b.on {
        st.scanner.set_enabled(on);
    }
    if b.clear {
        st.scanner.clear();
    }
    st.persist();
    Json(json!({ "on": st.scanner.enabled() })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ActiveScanBody {
    pub from_flow: i64,
}

/// Active-scan a captured flow's query parameters (XSS / SQLi probes).
async fn active_scan_run(State(st): State<AppState>, Json(b): Json<ActiveScanBody>) -> Response {
    let base = match intruder::base_from_flow(&st.store, b.from_flow) {
        Ok(r) => r,
        Err(e) => return (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let results = active_scan::scan(&st.store, &st.events, &st.scanner, &base).await;
    Json(json!({ "results": results })).into_response()
}

// ---- WebSocket capture ----

async fn ws_list(State(st): State<AppState>) -> Response {
    Json(st.wslog.list()).into_response()
}

async fn ws_clear(State(st): State<AppState>) -> Response {
    st.wslog.clear();
    Json(json!({ "ok": true })).into_response()
}

fn err(e: anyhow::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}
