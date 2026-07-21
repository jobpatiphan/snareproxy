//! Macro runner — sends a saved request (with `{{var}}` templating) and extracts
//! a value from the response into a variable. This is the refresh half of
//! session handling; Match & Replace injects the variable back into traffic.

use std::sync::Arc;

use anyhow::Result;
use regex::Regex;
use bogbogprox_core::model::{FlowEvent, Header, Source};
use bogbogprox_core::session::{template, MacroSpec, Vars};
use bogbogprox_core::store::FlowStore;
use tokio::sync::broadcast;

use crate::repeater;

/// Run a macro: send its request, extract the value, store it in the variable.
/// Returns the extracted value (or None if the pattern didn't match).
pub async fn run(
    store: &Arc<dyn FlowStore>,
    events: &broadcast::Sender<FlowEvent>,
    vars: &Vars,
    m: &MacroSpec,
) -> Result<Option<String>> {
    let snap = vars.snapshot();
    let url = template(&m.url, &snap);
    let headers: Vec<Header> = m
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), template(v, &snap)))
        .collect();
    let body = template(&m.body, &snap).into_bytes();

    let flow = repeater::send(
        store,
        events,
        Source::Repeater,
        &m.method,
        &url,
        &headers,
        body,
    )
    .await?;

    let re = Regex::new(&m.extract)?;
    if let Some(resp) = &flow.response {
        let headers_s = resp
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let hay = format!("{headers_s}\n\n{}", String::from_utf8_lossy(&resp.body));
        if let Some(cap) = re.captures(&hay) {
            if let Some(mm) = cap.get(1).or_else(|| cap.get(0)) {
                let val = mm.as_str().to_string();
                vars.set(&m.var, &val);
                return Ok(Some(val));
            }
        }
    }
    Ok(None)
}
