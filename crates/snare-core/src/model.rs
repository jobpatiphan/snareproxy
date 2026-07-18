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
}

impl HttpRequest {
    /// Full URL reconstructed from parts.
    pub fn url(&self) -> String {
        let default_port =
            (self.scheme == "https" && self.port == 443) || (self.scheme == "http" && self.port == 80);
        let authority = if default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
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
}

/// A captured HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub http_version: String,
    pub headers: Vec<Header>,
    #[serde(with = "b64")]
    pub body: Vec<u8>,
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
}

/// An AI / automation action, surfaced live so the operator can watch — in
/// real time — exactly what an agent driving Snare is doing.
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
    FlowNew { summary: FlowSummary },
    FlowUpdate { summary: FlowSummary },
    /// An AI agent invoked a tool against Snare.
    Activity { activity: Activity },
    /// A request is held at the intercept breakpoint, awaiting a decision.
    InterceptPaused { id: u64, request: HttpRequest },
    /// A response is held at the intercept breakpoint, awaiting a decision.
    InterceptRespPaused { id: u64, response: HttpResponse },
    /// A held request/response was forwarded or dropped ("forward" | "drop").
    InterceptResolved { id: u64, action: String },
    /// Intercept toggles changed (`on` = requests, `responses` = responses).
    InterceptState { on: bool, responses: bool },
    /// The passive scanner raised a finding.
    Finding { finding: crate::scanner::Finding },
}

/// base64 (std, no padding issues) for byte bodies in JSON.
mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        for chunk in s.chunks(4) {
            if chunk.is_empty() {
                break;
            }
            let mut n = 0u32;
            let mut pad = 0;
            for (i, &c) in chunk.iter().enumerate() {
                if c == b'=' {
                    pad += 1;
                    n <<= 6;
                } else {
                    n = n << 6 | val(c)?;
                }
                let _ = i;
            }
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
