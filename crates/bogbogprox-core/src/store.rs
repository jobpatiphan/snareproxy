//! Storage port — the trait every backend (SQLite, Postgres, …) implements.

use crate::model::{Flow, FlowSummary, HttpRequest, HttpResponse, Source};

/// Query for listing flows (HTTPQL lands here later; for now: substring + host filter).
#[derive(Debug, Clone, Default)]
pub struct FlowQuery {
    /// Case-insensitive substring matched against method/host/path.
    pub search: Option<String>,
    pub host: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

impl FlowQuery {
    pub fn new() -> Self {
        Self {
            limit: 200,
            ..Default::default()
        }
    }
}

/// The storage port. Implementations must be cheap to `Clone` (share an inner Arc).
pub trait FlowStore: Send + Sync + 'static {
    /// Insert a request (response not yet known). Returns the new flow id.
    fn insert_request(&self, ts: i64, source: Source, req: &HttpRequest) -> anyhow::Result<i64>;

    /// Attach the response to an existing flow.
    fn attach_response(&self, id: i64, resp: &HttpResponse, duration_ms: u64)
        -> anyhow::Result<()>;

    /// List flow summaries newest-first.
    fn list_flows(&self, q: &FlowQuery) -> anyhow::Result<Vec<FlowSummary>>;

    /// Fetch one full flow (with bodies).
    fn get_flow(&self, id: i64) -> anyhow::Result<Option<Flow>>;

    /// Total number of flows stored.
    fn count(&self) -> anyhow::Result<i64>;

    /// Remove every flow (used by `bogbogproxd flush`).
    fn clear(&self) -> anyhow::Result<()>;
}
