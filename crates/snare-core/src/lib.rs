//! `snare-core` — the domain library shared by every Snare frontend and backend.
//!
//! It holds the data model ([`model`]) and the storage port ([`store`]).
//! All business logic lives here so the daemon, TUI, MCP server, and future
//! web/desktop frontends stay thin.

pub mod annotate;
pub mod intercept;
pub mod model;
pub mod render;
pub mod rules;
pub mod scanner;
pub mod session;
pub mod store;
pub mod ws;

pub use annotate::{Annotation, AnnotationPatch, Annotations};
pub use model::{
    Activity, Flow, FlowEvent, FlowSummary, Header, HttpRequest, HttpResponse, Source,
};
pub use render::RenderOpts;
pub use store::{FlowQuery, FlowStore};

/// Current unix time in milliseconds.
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
