//! `snare-mcp` — Model Context Protocol server over stdio (§10).
//!
//! Exposes Snare's captured flows to AI agents. Phase-0 transport is a small
//! hand-rolled JSON-RPC 2.0 loop (newline-delimited) — no external MCP SDK — so
//! it is dependency-light and stable. All operations go through the daemon API
//! so local, Postgres, authenticated, and HTTPS deployments behave identically.

use std::io::{BufRead, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use snare_core::model::{Flow, FlowSummary};

const PROTOCOL_VERSION: &str = "2024-11-05";

fn summary_url(flow: &FlowSummary) -> String {
    let default_port =
        (flow.scheme == "https" && flow.port == 443) || (flow.scheme == "http" && flow.port == 80);
    let host = if flow.host.contains(':') && !flow.host.starts_with('[') {
        format!("[{}]", flow.host)
    } else {
        flow.host.clone()
    };
    let authority = if default_port {
        host
    } else {
        format!("{host}:{}", flow.port)
    };
    format!("{}://{}{}", flow.scheme, authority, flow.path)
}

struct ApiClient {
    base: String,
    token: Option<String>,
    client: Client,
}

impl ApiClient {
    fn from_env() -> Result<Self> {
        let base = std::env::var("SNARE_API")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".into())
            .trim_end_matches('/')
            .to_string();
        reqwest::Url::parse(&base).context("invalid SNARE_API URL")?;
        let token = std::env::var("SNARE_TOKEN").ok().filter(|v| !v.is_empty());
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self {
            base,
            token,
            client,
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let request = self
            .client
            .request(method, format!("{}{}", self.base, path));
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    fn checked(response: Response) -> Result<Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let detail = response.text().unwrap_or_default();
        bail!("daemon returned HTTP {status}: {detail}")
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(Self::checked(self.request(reqwest::Method::GET, path).send()?)?.json()?)
    }

    fn get_query<T: DeserializeOwned>(&self, path: &str, query: &[(&str, String)]) -> Result<T> {
        Ok(Self::checked(
            self.request(reqwest::Method::GET, path)
                .query(query)
                .send()?,
        )?
        .json()?)
    }

    fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(Self::checked(
            self.request(reqwest::Method::POST, path)
                .json(body)
                .send()?,
        )?
        .json()?)
    }

    /// GET a text/plain-ish endpoint (e.g. the markdown report) as a String.
    fn get_text(&self, path: &str, query: &[(&str, String)]) -> Result<String> {
        Ok(Self::checked(
            self.request(reqwest::Method::GET, path)
                .query(query)
                .send()?,
        )?
        .text()?)
    }

    fn notify_activity(&self, tool: &str, detail: &str) {
        let agent = std::env::var("SNARE_AGENT").unwrap_or_else(|_| "ai-agent".into());
        let body = json!({
            "ts": snare_core::now_millis(),
            "agent": agent,
            "tool": tool,
            "detail": detail,
        });
        let result = self
            .request(reqwest::Method::POST, "/api/v1/activity")
            .timeout(Duration::from_millis(750))
            .json(&body)
            .send()
            .and_then(|response| response.error_for_status());
        if let Err(e) = result {
            eprintln!("[snare-mcp] activity notification failed: {e}");
        }
    }
}

fn main() -> Result<()> {
    let api = ApiClient::from_env()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[snare-mcp] bad json: {e}");
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        eprintln!("[snare-mcp] -> {method}");

        // Notifications (no id) get no reply.
        let Some(id) = id else {
            continue;
        };

        let reply = match handle(method, msg.get("params"), &api) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32603, "message": e.to_string() }
            }),
        };
        writeln!(stdout, "{}", serde_json::to_string(&reply)?)?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle(method: &str, params: Option<&Value>, api: &ApiClient) -> Result<Value> {
    match method {
        "initialize" => {
            api.notify_activity("connect", "AI agent connected to Snare");
            Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "snare-mcp", "version": env!("CARGO_PKG_VERSION") }
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_specs() })),
        "tools/call" => tools_call(params, api),
        other => anyhow::bail!("method not found: {other}"),
    }
}

fn tool_specs() -> Value {
    json!([
        {
            "name": "proxy_list_flows",
            "description": "List captured HTTP flows (newest first). Optional case-insensitive substring search over method/host/path.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "search": { "type": "string", "description": "substring filter" },
                    "limit": { "type": "integer", "description": "max rows (default 50)" }
                }
            }
        },
        {
            "name": "proxy_get_flow",
            "description": "Fetch one full flow (request + response) by id. `part` = request|response|all (default all).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "integer" },
                    "part": { "type": "string", "enum": ["request", "response", "all"] }
                },
                "required": ["id"]
            }
        },
        {
            "name": "proxy_stats",
            "description": "Total number of flows captured.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "repeater_send",
            "description": "Resend a captured request through the repeater by flow id. Returns the new flow (request + response). Needs a running `snared`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "integer", "description": "flow id to resend" }
                },
                "required": ["id"]
            }
        },
        {
            "name": "intruder_run",
            "description": "Fuzz a captured request: substitute `marker` in its URL/headers/body with each payload and send them (bounded-parallel). Returns status/length per payload. Needs a running `snared`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from_flow": { "type": "integer", "description": "flow id to use as template" },
                    "marker": { "type": "string", "description": "marker to substitute (default §)" },
                    "payloads": { "type": "array", "items": { "type": "string" } },
                    "concurrency": { "type": "integer", "description": "parallel requests (default 10)" }
                },
                "required": ["from_flow", "payloads"]
            }
        },
        {
            "name": "active_scan",
            "description": "Active-scan a captured flow's query parameters for reflected-XSS and error-based SQLi. Returns per-probe results; findings appear in the dashboard. Needs a running `snared`.",
            "inputSchema": {
                "type": "object",
                "properties": { "from_flow": { "type": "integer", "description": "flow id to scan" } },
                "required": ["from_flow"]
            }
        },
        {
            "name": "annotate_flow",
            "description": "Curate a captured flow for the writeup (Burp-style comment/highlight). Set a `label` (section heading, e.g. \"Sandbox escape\"), a `note` (prose explaining why it matters), a `step` (ordering), a `highlight` (the payload substring to spotlight in the transcript), and/or a `color`. Annotated flows become the default writeup, narrated and in step order.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "flow_id": { "type": "integer", "description": "flow id to annotate" },
                    "label": { "type": "string", "description": "short section heading" },
                    "note": { "type": "string", "description": "prose explaining the step" },
                    "step": { "type": "integer", "description": "ordering position (lower = earlier)" },
                    "highlight": { "type": "string", "description": "payload substring to spotlight" },
                    "color": { "type": "string", "description": "row highlight colour (red/orange/yellow/green/cyan/blue/pink)" },
                    "include": { "type": "boolean", "description": "include in writeup (default true)" }
                },
                "required": ["flow_id"]
            }
        },
        {
            "name": "report_writeup",
            "description": "Render the writeup as paste-ready Markdown: each flow narrated (annotation label as heading, note as prose) with smart ```http transcripts — secrets redacted, JSON pretty-printed, the payload spotlighted — plus scanner findings correlated by host. Omit `flows` to use the annotated flows in step order (annotate them first with `annotate_flow`); pass `flows` to force a specific set/order. `highlight` spotlights a payload across every flow; `redact=false` keeps raw secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "flows": {
                        "type": "array",
                        "items": { "type": "integer" },
                        "description": "flow ids to include, in order (overrides annotation curation)"
                    },
                    "highlight": { "type": "string", "description": "payload to spotlight in every transcript" },
                    "redact": { "type": "boolean", "description": "redact secrets in headers (default true)" }
                }
            }
        }
    ])
}

/// Shape a full flow for AI consumption (decoded bodies, no base64 noise).
fn format_flow(flow: &snare_core::model::Flow, part: &str) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("id".into(), json!(flow.id));
    out.insert("source".into(), json!(flow.source.as_str()));
    if part == "request" || part == "all" {
        out.insert(
            "request".into(),
            json!({
                "method": flow.request.method,
                "url": flow.request.url(),
                "http_version": flow.request.http_version,
                "headers": flow.request.headers,
                "body": String::from_utf8_lossy(&flow.request.body),
                "body_truncated": flow.request.body_truncated,
            }),
        );
    }
    if part == "response" || part == "all" {
        if let Some(resp) = &flow.response {
            out.insert(
                "response".into(),
                json!({
                    "status": resp.status,
                    "headers": resp.headers,
                    "body": String::from_utf8_lossy(&resp.body),
                    "body_truncated": resp.body_truncated,
                }),
            );
        }
    }
    Value::Object(out)
}

fn text_result(text: String) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ] })
}

/// A short human-readable description of a tool call for the activity feed.
fn summarize_call(name: &str, args: &Value) -> String {
    match name {
        "proxy_list_flows" => {
            let search = args.get("search").and_then(|s| s.as_str());
            let limit = args.get("limit").and_then(|l| l.as_i64()).unwrap_or(50);
            match search {
                Some(s) => format!("list flows matching \"{s}\" (limit {limit})"),
                None => format!("list latest {limit} flows"),
            }
        }
        "proxy_get_flow" => {
            let id = args.get("id").and_then(|i| i.as_i64()).unwrap_or(-1);
            let part = args.get("part").and_then(|p| p.as_str()).unwrap_or("all");
            format!("inspect flow #{id} ({part})")
        }
        "proxy_stats" => "count captured flows".into(),
        "repeater_send" => {
            let id = args.get("id").and_then(|i| i.as_i64()).unwrap_or(-1);
            format!("resend flow #{id} via repeater")
        }
        "intruder_run" => {
            let id = args
                .get("id")
                .or_else(|| args.get("from_flow"))
                .and_then(|i| i.as_i64())
                .unwrap_or(-1);
            let n = args
                .get("payloads")
                .and_then(|p| p.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            format!("intruder: fuzz flow #{id} with {n} payloads")
        }
        "active_scan" => {
            let id = args.get("from_flow").and_then(|i| i.as_i64()).unwrap_or(-1);
            format!("active-scan flow #{id} (XSS/SQLi)")
        }
        "annotate_flow" => {
            let id = args.get("flow_id").and_then(|i| i.as_i64()).unwrap_or(-1);
            match args.get("label").and_then(|v| v.as_str()) {
                Some(label) => format!("annotate flow #{id}: \"{label}\""),
                None => format!("annotate flow #{id}"),
            }
        }
        "report_writeup" => {
            let n = args
                .get("flows")
                .and_then(|f| f.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if n > 0 {
                format!("export writeup of {n} selected flow(s)")
            } else {
                "export writeup of annotated flows".into()
            }
        }
        other => format!("call {other}"),
    }
}

fn tools_call(params: Option<&Value>, api: &ApiClient) -> Result<Value> {
    let params = params.cloned().unwrap_or_else(|| json!({}));
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Surface the intent on the live dashboard *before* running it, so the
    // operator sees what the agent is about to do in real time.
    api.notify_activity(name, &summarize_call(name, &args));

    match name {
        "proxy_stats" => {
            let stats: Value = api.get("/api/v1/stats")?;
            Ok(text_result(stats.to_string()))
        }
        "proxy_list_flows" => {
            let mut query = vec![(
                "limit",
                args.get("limit")
                    .and_then(|l| l.as_i64())
                    .unwrap_or(50)
                    .to_string(),
            )];
            if let Some(search) = args.get("search").and_then(|s| s.as_str()) {
                query.push(("search", search.to_string()));
            }
            let flows: Vec<FlowSummary> = api.get_query("/api/v1/flows", &query)?;
            let rows: Vec<Value> = flows
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "method": f.method,
                        "url": summary_url(f),
                        "status": f.status,
                        "mime": f.mime,
                        "size": f.resp_size,
                        "ms": f.duration_ms
                    })
                })
                .collect();
            Ok(text_result(serde_json::to_string_pretty(&rows)?))
        }
        "proxy_get_flow" => {
            let id = args
                .get("id")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `id`"))?;
            let part = args.get("part").and_then(|p| p.as_str()).unwrap_or("all");
            let flow: Flow = api.get(&format!("/api/v1/flows/{id}"))?;
            Ok(text_result(serde_json::to_string_pretty(&format_flow(
                &flow, part,
            ))?))
        }
        "repeater_send" => {
            let id = args
                .get("id")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `id`"))?;
            let flow: Flow = api.post(&format!("/api/v1/repeater/from/{id}"), &json!({}))?;
            Ok(text_result(serde_json::to_string_pretty(&format_flow(
                &flow, "all",
            ))?))
        }
        "intruder_run" => {
            let from_flow = args
                .get("from_flow")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `from_flow`"))?;
            let payloads = args
                .get("payloads")
                .and_then(|p| p.as_array())
                .ok_or_else(|| anyhow::anyhow!("missing `payloads` array"))?;
            let body = json!({
                "from_flow": from_flow,
                "marker": args.get("marker").and_then(|m| m.as_str()).unwrap_or("§"),
                "payloads": payloads,
                "concurrency": args.get("concurrency").and_then(|c| c.as_i64()).unwrap_or(10),
            });
            let out: Value = api.post("/api/v1/intruder", &body)?;
            Ok(text_result(serde_json::to_string_pretty(&out)?))
        }
        "active_scan" => {
            let from_flow = args
                .get("from_flow")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `from_flow`"))?;
            let body = json!({ "from_flow": from_flow });
            let out: Value = api.post("/api/v1/scan/active", &body)?;
            Ok(text_result(serde_json::to_string_pretty(&out)?))
        }
        "annotate_flow" => {
            let flow_id = args
                .get("flow_id")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `flow_id`"))?;
            // Forward only the provided annotation fields as a patch.
            let mut patch = serde_json::Map::new();
            for key in ["label", "note", "highlight", "color"] {
                if let Some(v) = args.get(key).and_then(|v| v.as_str()) {
                    patch.insert(key.into(), json!(v));
                }
            }
            if let Some(v) = args.get("step").and_then(|v| v.as_i64()) {
                patch.insert("step".into(), json!(v));
            }
            if let Some(v) = args.get("include").and_then(|v| v.as_bool()) {
                patch.insert("include".into(), json!(v));
            }
            let out: Value = api.post(
                &format!("/api/v1/flows/{flow_id}/note"),
                &Value::Object(patch),
            )?;
            Ok(text_result(serde_json::to_string_pretty(&out)?))
        }
        "report_writeup" => {
            let mut query = vec![("format", "writeup".to_string())];
            if let Some(ids) = args.get("flows").and_then(|f| f.as_array()) {
                let list = ids
                    .iter()
                    .filter_map(|v| v.as_i64())
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                if !list.is_empty() {
                    query.push(("flows", list));
                }
            }
            if let Some(h) = args.get("highlight").and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    query.push(("highlight", h.to_string()));
                }
            }
            if let Some(false) = args.get("redact").and_then(|v| v.as_bool()) {
                query.push(("redact", "false".to_string()));
            }
            let md = api.get_text("/api/v1/report", &query)?;
            Ok(text_result(md))
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snare_core::model::Source;

    fn summary(scheme: &str, host: &str, port: u16) -> FlowSummary {
        FlowSummary {
            id: 1,
            ts: 0,
            source: Source::Proxy,
            method: "GET".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: "/health".into(),
            status: Some(200),
            mime: None,
            resp_size: None,
            duration_ms: None,
        }
    }

    #[test]
    fn summary_url_preserves_non_default_ports_and_ipv6() {
        assert_eq!(
            summary_url(&summary("http", "127.0.0.1", 18081)),
            "http://127.0.0.1:18081/health"
        );
        assert_eq!(
            summary_url(&summary("https", "2001:db8::1", 8443)),
            "https://[2001:db8::1]:8443/health"
        );
        assert_eq!(
            summary_url(&summary("https", "example.test", 443)),
            "https://example.test/health"
        );
    }
}
