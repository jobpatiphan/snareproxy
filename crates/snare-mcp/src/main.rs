//! `snare-mcp` — Model Context Protocol server over stdio (§10).
//!
//! Exposes Snare's captured flows to AI agents. Phase-0 transport is a small
//! hand-rolled JSON-RPC 2.0 loop (newline-delimited) — no external MCP SDK — so
//! it is dependency-light and stable. It reads the SQLite store directly.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::Result;
use serde_json::{json, Value};
use snare_core::store::{FlowQuery, FlowStore};
use snare_store_sqlite::SqliteStore;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Resolve the daemon's REST host/port from `SNARE_API` (default localhost:9000).
fn api_host_port() -> (String, u16) {
    let base = std::env::var("SNARE_API").unwrap_or_else(|_| "http://127.0.0.1:9000".into());
    let hostport = base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:9000");
    match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(9000u16)),
        None => (hostport.to_string(), 9000u16),
    }
}

/// Best-effort: tell the running daemon what the agent is doing so it shows up
/// on the live dashboard the instant it happens. Never fails the tool call —
/// if the daemon isn't up, we just skip it.
fn notify_activity(tool: &str, detail: &str) {
    let (host, port) = api_host_port();
    let agent = std::env::var("SNARE_AGENT").unwrap_or_else(|_| "ai-agent".into());
    let body = json!({
        "ts": snare_core::now_millis(),
        "agent": agent,
        "tool": tool,
        "detail": detail,
    })
    .to_string();
    if let Err(e) = post_json(&host, port, "/api/v1/activity", &body, 500) {
        eprintln!("[snare-mcp] activity POST to {host}:{port} failed: {e}");
    }
}

/// POST `body` and return the full response body as a string (Connection:
/// close → read to EOF). Used for tools that need the daemon's reply.
fn post_read_body(host: &str, port: u16, path: &str, body: &str, read_timeout_ms: u64) -> std::io::Result<String> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream.set_write_timeout(Some(std::time::Duration::from_millis(500)))?;
    stream.set_read_timeout(Some(std::time::Duration::from_millis(read_timeout_ms)))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_else(|| text.into_owned()))
}

/// Minimal one-shot HTTP/1.1 POST to localhost. Reads the first response bytes
/// (which the daemon only sends once the handler has finished) so we both avoid
/// racing the server read and know the request completed. `read_timeout_ms`
/// bounds how long we wait — short for activity, long for a repeater round-trip.
fn post_json(host: &str, port: u16, path: &str, body: &str, read_timeout_ms: u64) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream.set_write_timeout(Some(std::time::Duration::from_millis(500)))?;
    stream.set_read_timeout(Some(std::time::Duration::from_millis(read_timeout_ms)))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 256];
    let _ = stream.read(&mut buf);
    Ok(())
}

fn db_path() -> PathBuf {
    if let Ok(home) = std::env::var("SNARE_HOME") {
        return PathBuf::from(home).join("data").join("flows.sqlite");
    }
    directories::ProjectDirs::from("dev", "Snare", "snare")
        .map(|pd| pd.data_dir().join("flows.sqlite"))
        .unwrap_or_else(|| PathBuf::from("flows.sqlite"))
}

fn main() -> Result<()> {
    let store = SqliteStore::open(db_path())?;
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

        let reply = match handle(method, msg.get("params"), &store) {
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

fn handle(method: &str, params: Option<&Value>, store: &SqliteStore) -> Result<Value> {
    match method {
        "initialize" => {
            notify_activity("connect", "AI agent connected to Snare");
            Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "snare-mcp", "version": env!("CARGO_PKG_VERSION") }
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_specs() })),
        "tools/call" => tools_call(params, store),
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
            let id = args.get("id").or_else(|| args.get("from_flow")).and_then(|i| i.as_i64()).unwrap_or(-1);
            let n = args.get("payloads").and_then(|p| p.as_array()).map(|a| a.len()).unwrap_or(0);
            format!("intruder: fuzz flow #{id} with {n} payloads")
        }
        other => format!("call {other}"),
    }
}

fn tools_call(params: Option<&Value>, store: &SqliteStore) -> Result<Value> {
    let params = params.cloned().unwrap_or_else(|| json!({}));
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    // Surface the intent on the live dashboard *before* running it, so the
    // operator sees what the agent is about to do in real time.
    notify_activity(name, &summarize_call(name, &args));

    match name {
        "proxy_stats" => {
            let n = store.count()?;
            Ok(text_result(json!({ "flows": n }).to_string()))
        }
        "proxy_list_flows" => {
            let q = FlowQuery {
                search: args.get("search").and_then(|s| s.as_str()).map(String::from),
                host: None,
                limit: args.get("limit").and_then(|l| l.as_i64()).unwrap_or(50),
                offset: 0,
            };
            let flows = store.list_flows(&q)?;
            let rows: Vec<Value> = flows
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "method": f.method,
                        "url": format!("{}://{}{}", f.scheme, f.host, f.path),
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
            let flow = store
                .get_flow(id)?
                .ok_or_else(|| anyhow::anyhow!("flow {id} not found"))?;
            Ok(text_result(serde_json::to_string_pretty(&format_flow(&flow, part))?))
        }
        "repeater_send" => {
            let id = args
                .get("id")
                .and_then(|i| i.as_i64())
                .ok_or_else(|| anyhow::anyhow!("missing `id`"))?;
            let (host, port) = api_host_port();
            // Trigger the send on the daemon (long timeout: it does a real round-trip).
            post_json(&host, port, &format!("/api/v1/repeater/from/{id}"), "", 20_000)
                .map_err(|e| anyhow::anyhow!("repeater send failed (is `snared run` up?): {e}"))?;
            // The daemon stored the new flow before responding — it's now the newest.
            let newest = store.list_flows(&FlowQuery {
                search: None,
                host: None,
                limit: 1,
                offset: 0,
            })?;
            let f = newest
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no flow after repeat"))?;
            let flow = store
                .get_flow(f.id)?
                .ok_or_else(|| anyhow::anyhow!("repeated flow vanished"))?;
            Ok(text_result(serde_json::to_string_pretty(&format_flow(&flow, "all"))?))
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
            let (host, port) = api_host_port();
            let body = json!({
                "from_flow": from_flow,
                "marker": args.get("marker").and_then(|m| m.as_str()).unwrap_or("§"),
                "payloads": payloads,
                "concurrency": args.get("concurrency").and_then(|c| c.as_i64()).unwrap_or(10),
            })
            .to_string();
            let out = post_read_body(&host, port, "/api/v1/intruder", &body, 60_000)
                .map_err(|e| anyhow::anyhow!("intruder failed (is `snared run` up?): {e}"))?;
            Ok(text_result(out))
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}
