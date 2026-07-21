//! Core domain model shared by every crate.

use serde::{Deserialize, Serialize};

/// A single HTTP header (case preserved as sent on the wire).
pub type Header = (String, String);

/// Where a flow originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Proxy,
    Repeater,
    Intruder,
    Scanner,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Proxy => "proxy",
            Source::Repeater => "repeater",
            Source::Intruder => "intruder",
            Source::Scanner => "scanner",
        }
    }
}

/// A captured HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub http_version: String,
    pub headers: Vec<Header>,
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// True when BogBogProx deliberately retained only the configured capture prefix.
    /// The bytes forwarded on the wire are still complete.
    #[serde(default)]
    pub body_truncated: bool,
}

impl HttpRequest {
    /// Full URL reconstructed from parts.
    pub fn url(&self) -> String {
        let default_port = (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80);
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let authority = if default_port {
            host
        } else {
            format!("{}:{}", host, self.port)
        };
        let mut url = format!("{}://{}{}", self.scheme, authority, self.path);
        if let Some(q) = &self.query {
            url.push('?');
            url.push_str(q);
        }
        url
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Reconstruct the request as an HTTP wire-format transcript
    /// (`\n`-terminated for readability). Body is decoded lossily as UTF-8;
    /// this is meant for human display / writeups, not byte-exact replay.
    pub fn to_raw(&self) -> String {
        let target = match &self.query {
            Some(q) if !q.is_empty() => format!("{}?{}", self.path, q),
            _ => self.path.clone(),
        };
        let mut out = format!("{} {} {}\n", self.method, target, self.http_version);
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\n"));
        }
        out.push('\n');
        if !self.body.is_empty() {
            out.push_str(&String::from_utf8_lossy(&self.body));
        }
        if self.body_truncated {
            out.push_str("\n… [body truncated by capture limit]");
        }
        out
    }
}

/// A captured HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub http_version: String,
    pub headers: Vec<Header>,
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// True when BogBogProx deliberately retained only the configured capture prefix.
    #[serde(default)]
    pub body_truncated: bool,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn mime(&self) -> Option<&str> {
        self.header("content-type")
            .map(|ct| ct.split(';').next().unwrap_or(ct).trim())
    }

    /// Reconstruct the response as an HTTP wire-format transcript
    /// (`\n`-terminated for readability). Body is decoded lossily as UTF-8;
    /// this is meant for human display / writeups, not byte-exact replay.
    pub fn to_raw(&self) -> String {
        let mut out = format!(
            "{} {}{}\n",
            self.http_version,
            self.status,
            reason_phrase(self.status)
                .map(|r| format!(" {r}"))
                .unwrap_or_default()
        );
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\n"));
        }
        out.push('\n');
        if !self.body.is_empty() {
            out.push_str(&String::from_utf8_lossy(&self.body));
        }
        if self.body_truncated {
            out.push_str("\n… [body truncated by capture limit]");
        }
        out
    }
}

/// Canonical reason phrase for common status codes (best-effort; the wire
/// phrase is not retained, so this is reconstructed for readability only).
pub(crate) fn reason_phrase(status: u16) -> Option<&'static str> {
    Some(match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => return None,
    })
}

/// A full request/response pair as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: i64,
    /// Unix millis when the request was seen.
    pub ts: i64,
    pub source: Source,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub duration_ms: Option<u64>,
}

/// A lightweight row for lists (no bodies) — what the WS/REST list endpoints return.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub id: i64,
    pub ts: i64,
    pub source: Source,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub resp_size: Option<u64>,
    pub duration_ms: Option<u64>,
    /// Waterfall (live only): time to establish a new upstream connection
    /// (DNS + TCP + TLS). `None` when the connection was reused from the pool.
    #[serde(default)]
    pub connect_ms: Option<u64>,
    /// Waterfall (live only): time from request sent to response headers
    /// (TTFB-ish). `None` for flows loaded from storage.
    #[serde(default)]
    pub wait_ms: Option<u64>,
    /// Waterfall (live only): time spent reading the response body.
    #[serde(default)]
    pub download_ms: Option<u64>,
    /// Who initiated the request, from the browser via CDP (live only): e.g.
    /// "script app.js:42 render()" / "parser" / "user". `None` when no CDP
    /// browser is attached or the request came from another client.
    #[serde(default)]
    pub initiator: Option<String>,
}

/// Shared map of `request URL → (initiator label, unix-ms)` populated by the CDP
/// bridge when an instrumented browser is attached, read by the engine to tag
/// flows. Best-effort: keyed by URL, newest wins, pruned by capacity.
pub type InitiatorSink = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (String, i64)>>>;

/// An AI / automation action, surfaced live so the operator can watch — in
/// real time — exactly what an agent driving BogBogProx is doing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    /// Unix millis; 0 (or omitted) means "stamp it on arrival".
    #[serde(default)]
    pub ts: i64,
    /// Who is acting, e.g. "claude" or the MCP client name.
    pub agent: String,
    /// The tool/action invoked, e.g. "proxy_list_flows".
    pub tool: String,
    /// Human-readable summary of the arguments/intent.
    #[serde(default)]
    pub detail: String,
}

/// Realtime events emitted by the engine/daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FlowEvent {
    FlowNew {
        summary: FlowSummary,
    },
    FlowUpdate {
        summary: FlowSummary,
    },
    /// An AI agent invoked a tool against BogBogProx.
    Activity {
        activity: Activity,
    },
    /// A request is held at the intercept breakpoint, awaiting a decision.
    InterceptPaused {
        id: u64,
        request: HttpRequest,
    },
    /// A response is held at the intercept breakpoint, awaiting a decision.
    InterceptRespPaused {
        id: u64,
        response: HttpResponse,
    },
    /// A held request/response was forwarded or dropped ("forward" | "drop").
    InterceptResolved {
        id: u64,
        action: String,
    },
    /// Intercept toggles changed (`on` = requests, `responses` = responses).
    InterceptState {
        on: bool,
        responses: bool,
    },
    /// The passive scanner raised a finding.
    Finding {
        finding: crate::scanner::Finding,
    },
    /// A WebSocket message was captured.
    WsMessage {
        msg: crate::ws::WsMessage,
    },
    /// Shared config changed (team mode) — clients reload the given kind
    /// ("rules" | "scope" | "vars" | "macros" | "scanner").
    ConfigChanged {
        kind: String,
    },
    /// An operator joined or left (team mode); `status` = "join" | "leave".
    Presence {
        operator: String,
        status: String,
    },
}

/// Base64-encode bytes (used for binary WebSocket frames, etc.).
pub fn base64_encode(data: &[u8]) -> String {
    b64::encode(data)
}

/// base64 (std, no padding issues) for byte bodies in JSON.
mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(CHARS[(n >> 18 & 63) as usize] as char);
            out.push(CHARS[(n >> 12 & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                CHARS[(n >> 6 & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                CHARS[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        fn val(c: u8) -> Result<u32, String> {
            match c {
                b'A'..=b'Z' => Ok((c - b'A') as u32),
                b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
                b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
                b'+' => Ok(62),
                b'/' => Ok(63),
                _ => Err("invalid base64".into()),
            }
        }
        let s = s.trim().as_bytes();
        if s.len() & 3 != 0 {
            return Err("invalid base64 length".into());
        }
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        let chunk_count = s.len() / 4;
        for (index, chunk) in s.chunks_exact(4).enumerate() {
            let is_last = index + 1 == chunk_count;
            if chunk[0] == b'=' || chunk[1] == b'=' {
                return Err("invalid base64 padding".into());
            }
            let pad = match (chunk[2] == b'=', chunk[3] == b'=') {
                (true, true) => 2,
                (false, true) => 1,
                (false, false) => 0,
                (true, false) => return Err("invalid base64 padding".into()),
            };
            if pad > 0 && !is_last {
                return Err("invalid base64 padding".into());
            }
            let a = val(chunk[0])?;
            let b = val(chunk[1])?;
            let c = if pad < 2 { val(chunk[2])? } else { 0 };
            let d = if pad == 0 { val(chunk[3])? } else { 0 };
            if (pad == 2 && b & 0x0f != 0) || (pad == 1 && c & 0x03 != 0) {
                return Err("invalid base64 trailing bits".into());
            }
            let n = a << 18 | b << 12 | c << 6 | d;
            out.push((n >> 16 & 0xFF) as u8);
            if pad < 2 {
                out.push((n >> 8 & 0xFF) as u8);
            }
            if pad < 1 {
                out.push((n & 0xFF) as u8);
            }
        }
        Ok(out)
    }

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_brackets_ipv6_hosts() {
        let request = HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "::1".into(),
            port: 8443,
            path: "/health".into(),
            query: None,
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            body_truncated: false,
        };
        assert_eq!(request.url(), "https://[::1]:8443/health");
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert!(b64::decode("A").is_err());
        assert!(b64::decode("====").is_err());
        assert!(b64::decode("AA=A").is_err());
        assert_eq!(b64::decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn request_to_raw_includes_query_headers_and_body() {
        let request = HttpRequest {
            method: "POST".into(),
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            path: "/login".into(),
            query: Some("next=/admin".into()),
            http_version: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "example.test".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: b"{\"u\":\"admin\"}".to_vec(),
            body_truncated: false,
        };
        let raw = request.to_raw();
        assert_eq!(
            raw,
            "POST /login?next=/admin HTTP/1.1\n\
             Host: example.test\n\
             Content-Type: application/json\n\
             \n\
             {\"u\":\"admin\"}"
        );
    }

    #[test]
    fn response_to_raw_maps_reason_phrase_and_flags_truncation() {
        let response = HttpResponse {
            status: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![("Content-Type".into(), "text/html".into())],
            body: b"<h1>hi".to_vec(),
            body_truncated: true,
        };
        let raw = response.to_raw();
        assert!(raw.starts_with("HTTP/1.1 200 OK\n"));
        assert!(raw.contains("Content-Type: text/html\n"));
        assert!(raw.contains("<h1>hi"));
        assert!(raw.contains("[body truncated by capture limit]"));
    }

    #[test]
    fn response_to_raw_omits_unknown_reason_phrase() {
        let response = HttpResponse {
            status: 799,
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            body_truncated: false,
        };
        assert_eq!(response.to_raw(), "HTTP/1.1 799\n\n");
    }
}
