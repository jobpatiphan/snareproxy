//! REST API (§8) — the surface every frontend and the MCP server can use.
//!
//! Beyond plain REST it exposes a Server-Sent-Events stream (`/api/v1/stream`)
//! so any browser can watch captured traffic — and AI activity — the instant it
//! happens, and an activity sink (`POST /api/v1/activity`) the MCP server pushes
//! to so the operator sees exactly what an agent is doing.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
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

use crate::{active_scan, intruder, repeater, sequencer};

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
    /// Session variables shared with the engine (for `{{var}}` injection).
    pub vars: Arc<snare_core::session::Vars>,
    /// Session macros.
    pub macros: Arc<snare_core::session::Macros>,
    /// Team-mode auth (no-op in local mode).
    pub auth: Arc<crate::auth::Auth>,
    /// Cross-process events relayed from other daemons (topology B).
    pub remote_events: broadcast::Sender<FlowEvent>,
    /// Where persisted settings are written.
    pub config_path: std::path::PathBuf,
}

impl AppState {
    /// Persist rules/scope/scanner/vars/macros after a mutation. Best-effort.
    fn persist(&self) {
        let snap = crate::config::snapshot(
            &self.rules,
            &self.intercept,
            &self.scanner,
            &self.vars,
            &self.macros,
        );
        crate::config::save(&self.config_path, &snap);
    }

    /// Persist and tell other operators to reload this config kind (team mode).
    fn config_changed(&self, kind: &str) {
        self.persist();
        let _ = self.events.send(FlowEvent::ConfigChanged { kind: kind.into() });
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
        .route("/api/v1/team/join", post(team_join))
        .route("/api/v1/team/whoami", get(team_whoami))
        .route("/api/v1/operators", get(operators_list))
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
        .route("/api/v1/report", get(report))
        .route("/api/v1/sequencer", post(sequencer_run))
        .route("/api/v1/vars", get(vars_list).put(vars_set))
        .route("/api/v1/vars/:name", axum::routing::delete(vars_delete))
        .route("/api/v1/macros", get(macros_list).post(macros_add))
        .route("/api/v1/macros/:id", axum::routing::delete(macros_delete))
        .route("/api/v1/macros/:id/run", post(macros_run))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state)
}

/// Team-mode auth gate. No-op in local mode. Exempts the dashboard, health, and
/// the join/whoami endpoints; everything else needs a valid session token
/// (header `Authorization: Bearer` or, for EventSource, `?token=`).
async fn auth_mw(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    if !st.auth.enabled() {
        return next.run(req).await;
    }
    let path = req.uri().path();
    let exempt = path == "/"
        || path == "/api/v1/health"
        || path == "/api/v1/team/join"
        || path == "/api/v1/team/whoami"
        || !path.starts_with("/api/");
    if exempt {
        return next.run(req).await;
    }
    let from_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string);
    let from_query = req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("token="))
            .map(str::to_string)
    });
    match from_header.or(from_query).and_then(|t| st.auth.verify_session(&t)) {
        Some(op) => {
            req.extensions_mut().insert(op);
            next.run(req).await
        }
        None => (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response(),
    }
}

/// The self-contained live dashboard (§9 web frontend, Phase-1 slice).
async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "snared" }))
}

// ---- Team mode: auth ----

#[derive(Debug, Deserialize)]
pub struct JoinBody {
    pub project_token: String,
    #[serde(default)]
    pub display_name: String,
}

/// Join a team engagement: exchange the shared project token for a session token.
async fn team_join(State(st): State<AppState>, Json(b): Json<JoinBody>) -> Response {
    if !st.auth.enabled() {
        return Json(json!({ "auth": false, "session_token": null })).into_response();
    }
    if !st.auth.verify_project(&b.project_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid project token" }))).into_response();
    }
    let (token, op) = st.auth.create_session(b.display_name);
    let _ = st.events.send(FlowEvent::Presence {
        operator: op.display_name.clone(),
        status: "join".into(),
    });
    Json(json!({
        "auth": true,
        "session_token": token,
        "operator_id": op.id,
        "display_name": op.display_name,
    }))
    .into_response()
}

/// Operators currently online (seen within the presence window).
async fn operators_list(State(st): State<AppState>) -> Response {
    Json(st.auth.online()).into_response()
}

/// Whether auth is required, and (if a valid token is supplied) who you are.
async fn team_whoami(State(st): State<AppState>, req: Request) -> Response {
    if !st.auth.enabled() {
        return Json(json!({ "auth": false })).into_response();
    }
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string);
    match token.and_then(|t| st.auth.verify_session(&t)) {
        Some(op) => Json(json!({ "auth": true, "authenticated": true, "display_name": op.display_name })).into_response(),
        None => Json(json!({ "auth": true, "authenticated": false })).into_response(),
    }
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
    // Merge the local event bus with the cross-process (remote) bus, so an
    // operator sees events from every proxy sharing this engagement.
    let to_event = |res: Result<FlowEvent, _>| match res {
        Ok(ev) => serde_json::to_string(&ev)
            .ok()
            .map(|json| Ok(Event::default().data(json))),
        Err(_) => None,
    };
    let local = BroadcastStream::new(st.events.subscribe()).filter_map(to_event);
    let remote = BroadcastStream::new(st.remote_events.subscribe()).filter_map(to_event);
    let stream = local.merge(remote);
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
    st.config_changed("scope");
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
            st.config_changed("rules");
            Json(spec).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

async fn rules_delete(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    if st.rules.remove(id) {
        st.config_changed("rules");
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
        st.config_changed("rules");
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
    st.config_changed("scanner");
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

// ---- Session handling: variables & macros ----

async fn vars_list(State(st): State<AppState>) -> Response {
    let obj: serde_json::Map<String, serde_json::Value> =
        st.vars.list().into_iter().map(|(k, v)| (k, json!(v))).collect();
    Json(obj).into_response()
}

#[derive(Debug, Deserialize)]
pub struct VarBody {
    pub name: String,
    pub value: String,
}

async fn vars_set(State(st): State<AppState>, Json(b): Json<VarBody>) -> Response {
    st.vars.set(&b.name, &b.value);
    st.config_changed("vars");
    Json(json!({ "ok": true })).into_response()
}

async fn vars_delete(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    st.vars.remove(&name);
    st.config_changed("vars");
    Json(json!({ "ok": true })).into_response()
}

async fn macros_list(State(st): State<AppState>) -> Response {
    Json(st.macros.list()).into_response()
}

#[derive(Debug, Deserialize)]
pub struct MacroBody {
    #[serde(default)]
    pub name: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: String,
    pub extract: String,
    pub var: String,
}

async fn macros_add(State(st): State<AppState>, Json(b): Json<MacroBody>) -> Response {
    let spec = snare_core::session::MacroSpec {
        id: 0,
        name: b.name,
        method: b.method,
        url: b.url,
        headers: b.headers,
        body: b.body,
        extract: b.extract,
        var: b.var,
    };
    let stored = st.macros.add(spec);
    st.config_changed("macros");
    Json(stored).into_response()
}

async fn macros_delete(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    if st.macros.remove(id) {
        st.config_changed("macros");
        Json(json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "no such macro" }))).into_response()
    }
}

/// Run a macro: send its request, extract, store the variable. Returns the value.
async fn macros_run(State(st): State<AppState>, Path(id): Path<u64>) -> Response {
    let Some(m) = st.macros.get(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "no such macro" }))).into_response();
    };
    match crate::macros::run(&st.store, &st.events, &st.vars, &m).await {
        Ok(Some(value)) => {
            st.config_changed("vars");
            Json(json!({ "ok": true, "var": m.var, "value": value })).into_response()
        }
        Ok(None) => (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "extract pattern did not match the response" }))).into_response(),
        Err(e) => err(e),
    }
}

// ---- Sequencer ----

#[derive(Debug, Deserialize)]
pub struct SequencerBody {
    /// Tokens to analyse directly.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Or collect from a flow: resend it `count` times and extract with `extract`.
    pub from_flow: Option<i64>,
    #[serde(default = "seq_count")]
    pub count: usize,
    pub extract: Option<String>,
}
fn seq_count() -> usize {
    30
}

async fn sequencer_run(State(st): State<AppState>, Json(b): Json<SequencerBody>) -> Response {
    let tokens = if !b.tokens.is_empty() {
        b.tokens
    } else if let (Some(id), Some(extract)) = (b.from_flow, b.extract.as_deref()) {
        let base = match intruder::base_from_flow(&st.store, id) {
            Ok(r) => r,
            Err(e) => return (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
        };
        match sequencer::collect(&st.store, &st.events, &base, b.count, extract).await {
            Ok(t) => t,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
        }
    } else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "provide tokens[] or from_flow+extract" }))).into_response();
    };
    Json(sequencer::analyze(&tokens)).into_response()
}

// ---- Reporting ----

#[derive(Debug, Deserialize)]
pub struct ReportParams {
    /// "md" (default) or "sarif".
    #[serde(default)]
    pub format: Option<String>,
}

/// Generate an engagement report from the scanner findings.
async fn report(State(st): State<AppState>, Query(p): Query<ReportParams>) -> Response {
    use snare_core::scanner::Severity;
    let findings = st.scanner.list();
    let flow_count = st.store.count().unwrap_or(0);

    match p.format.as_deref() {
        Some("sarif") => {
            let results: Vec<_> = findings
                .iter()
                .map(|f| {
                    let level = match f.severity {
                        Severity::High => "error",
                        Severity::Medium => "warning",
                        _ => "note",
                    };
                    json!({
                        "ruleId": f.title,
                        "level": level,
                        "message": { "text": f.detail },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": format!("https://{}", f.host) }
                            }
                        }]
                    })
                })
                .collect();
            let sarif = json!({
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [{
                    "tool": { "driver": { "name": "Snare", "informationUri": "https://github.com/jobpatiphan/bogbogprox" } },
                    "results": results
                }]
            });
            (
                [("content-type", "application/sarif+json"),
                 ("content-disposition", "attachment; filename=\"snare-report.sarif\"")],
                serde_json::to_string_pretty(&sarif).unwrap_or_default(),
            )
                .into_response()
        }
        _ => {
            let mut counts = [0usize; 4]; // info, low, medium, high
            for f in &findings {
                counts[match f.severity {
                    Severity::Info => 0,
                    Severity::Low => 1,
                    Severity::Medium => 2,
                    Severity::High => 3,
                }] += 1;
            }
            let mut md = String::new();
            md.push_str("# Snare — security report\n\n");
            md.push_str(&format!("- Flows captured: **{flow_count}**\n"));
            md.push_str(&format!(
                "- Findings: **{}** (high {}, medium {}, low {}, info {})\n\n",
                findings.len(), counts[3], counts[2], counts[1], counts[0]
            ));
            md.push_str("## Findings\n\n");
            if findings.is_empty() {
                md.push_str("_No findings._\n");
            } else {
                md.push_str("| Severity | Title | Host | Detail |\n|---|---|---|---|\n");
                // High → info order
                let mut sorted = findings.clone();
                sorted.sort_by_key(|f| match f.severity {
                    Severity::High => 0,
                    Severity::Medium => 1,
                    Severity::Low => 2,
                    Severity::Info => 3,
                });
                for f in sorted {
                    let sev = match f.severity {
                        Severity::High => "HIGH",
                        Severity::Medium => "MEDIUM",
                        Severity::Low => "LOW",
                        Severity::Info => "INFO",
                    };
                    let detail = f.detail.replace('|', "\\|").replace('\n', " ");
                    md.push_str(&format!("| {sev} | {} | {} | {} |\n", f.title, f.host, detail));
                }
            }
            (
                [("content-type", "text/markdown; charset=utf-8")],
                md,
            )
                .into_response()
        }
    }
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
