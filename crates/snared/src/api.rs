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
use snare_core::model::{Activity, FlowEvent, Header};
use snare_core::store::{FlowQuery, FlowStore};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

use crate::repeater;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn FlowStore>,
    /// Live event bus shared with the proxy engine and the activity sink.
    pub events: broadcast::Sender<FlowEvent>,
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
    match repeater::send(&st.store, &st.events, &method, &url, &b.headers, b.body.into_bytes()).await
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
    match repeater::send(&st.store, &st.events, &r.method, &r.url(), &r.headers, r.body.clone()).await
    {
        Ok(flow) => Json(flow).into_response(),
        Err(e) => err(e),
    }
}

fn err(e: anyhow::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}
