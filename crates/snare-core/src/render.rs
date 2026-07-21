//! Smart transcript rendering for writeups (§ writeup export, part B).
//!
//! Turns a captured request/response into a *readable* HTTP transcript rather
//! than a raw byte dump: JSON bodies are pretty-printed, secrets in headers are
//! redacted, an operator-supplied payload is spotlighted, and long bodies are
//! truncated around the interesting part. The plain [`HttpRequest::to_raw`] /
//! [`HttpResponse::to_raw`] stay byte-faithful; these opts-driven variants are
//! for human-facing reports.

use crate::model::{reason_phrase, Header, HttpRequest, HttpResponse};

/// Guillemets wrap a spotlighted payload inside a code block — visible and
/// unambiguous without needing markdown/HTML that a ```http fence would eat.
const HL_OPEN: char = '«';
const HL_CLOSE: char = '»';

/// How to render a transcript for a writeup.
#[derive(Debug, Clone)]
pub struct RenderOpts {
    /// Mask sensitive header values (cookies, auth tokens, …).
    pub redact: bool,
    /// Pretty-print JSON bodies.
    pub pretty: bool,
    /// Truncate bodies longer than this many bytes (0 = never truncate).
    pub max_body: usize,
    /// Substring to spotlight in the request/response (the payload).
    pub highlight: Option<String>,
}

impl Default for RenderOpts {
    fn default() -> Self {
        Self {
            redact: true,
            pretty: true,
            max_body: 2000,
            highlight: None,
        }
    }
}

/// Header names whose values are secrets and should be redacted in a writeup.
pub fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cookie"
            | "set-cookie"
            | "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-xsrf-token"
            | "x-session-token"
    )
}

/// Keep a short prefix so the reader knows the scheme/name, mask the rest.
fn redact_value(v: &str) -> String {
    let count = v.chars().count();
    if count <= 6 {
        "[redacted]".into()
    } else {
        let shown: String = v.chars().take(6).collect();
        format!("{shown}…[redacted]")
    }
}

fn render_headers(headers: &[Header], redact: bool) -> String {
    let mut out = String::new();
    for (k, v) in headers {
        let val = if redact && is_sensitive_header(k) {
            redact_value(v)
        } else {
            v.clone()
        };
        out.push_str(&format!("{k}: {val}\n"));
    }
    out
}

fn looks_like_json(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Decode the body (lossy UTF-8), pretty-printing JSON when applicable.
fn body_text(content_type: Option<&str>, body: &[u8], pretty: bool) -> String {
    let text = String::from_utf8_lossy(body);
    if pretty {
        let is_json =
            content_type.map(|ct| ct.contains("json")).unwrap_or(false) || looks_like_json(&text);
        if is_json {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Ok(p) = serde_json::to_string_pretty(&v) {
                    return p;
                }
            }
        }
    }
    text.into_owned()
}

/// Largest char boundary `<= idx`.
fn floor_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Case-insensitive search returning the byte offset of the first match.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .find(needle)
        .or_else(|| haystack.to_lowercase().find(&needle.to_lowercase()))
}

/// Wrap the first (case-insensitive) match of `needle` in highlight markers,
/// preserving the original casing of the matched span.
fn mark_first(text: &str, needle: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    if let Some(pos) = find_ci(text, needle) {
        let end = (pos + needle.len()).min(text.len());
        let end = floor_boundary(text, end);
        let mut out = String::with_capacity(text.len() + 2);
        out.push_str(&text[..pos]);
        out.push(HL_OPEN);
        out.push_str(&text[pos..end]);
        out.push(HL_CLOSE);
        out.push_str(&text[end..]);
        out
    } else {
        text.to_string()
    }
}

/// Truncate `body` to `opts.max_body`, keeping a window around a highlight match
/// when present, then spotlight the match.
fn shape_body(body: String, opts: &RenderOpts) -> String {
    let total = body.len();
    let hl = opts.highlight.as_deref().filter(|h| !h.is_empty());
    let match_pos = hl.and_then(|h| find_ci(&body, h).map(|p| (p, h.len())));

    let shown = if opts.max_body == 0 || total <= opts.max_body {
        body.clone()
    } else if let Some((pos, len)) = match_pos {
        // Center a window on the payload so it survives truncation.
        let start = floor_boundary(&body, pos.saturating_sub(300));
        let end = floor_boundary(&body, (pos + len + 700).min(total));
        let mut w = String::new();
        if start > 0 {
            w.push_str("… [head truncated]\n");
        }
        w.push_str(&body[start..end]);
        if end < total {
            w.push_str(&format!("\n… [truncated · {total} bytes total]"));
        }
        w
    } else {
        let end = floor_boundary(&body, opts.max_body);
        format!("{}\n… [truncated · {total} bytes total]", &body[..end])
    };

    match hl {
        Some(h) => mark_first(&shown, h),
        None => shown,
    }
}

impl HttpRequest {
    /// Render the request as a writeup-ready HTTP transcript with the given
    /// options (redaction, pretty JSON, payload highlight, truncation).
    pub fn to_raw_opts(&self, opts: &RenderOpts) -> String {
        let target = match &self.query {
            Some(q) if !q.is_empty() => format!("{}?{}", self.path, q),
            _ => self.path.clone(),
        };
        let mut out = format!("{} {} {}\n", self.method, target, self.http_version);
        out.push_str(&render_headers(&self.headers, opts.redact));
        out.push('\n');
        if !self.body.is_empty() {
            let text = body_text(self.header("content-type"), &self.body, opts.pretty);
            out.push_str(&shape_body(text, opts));
        }
        if self.body_truncated {
            out.push_str("\n… [body truncated by capture limit]");
        }
        out
    }
}

impl HttpResponse {
    /// Render the response as a writeup-ready HTTP transcript with the given
    /// options (redaction, pretty JSON, payload highlight, truncation).
    pub fn to_raw_opts(&self, opts: &RenderOpts) -> String {
        let mut out = format!(
            "{} {}{}\n",
            self.http_version,
            self.status,
            reason_phrase(self.status)
                .map(|r| format!(" {r}"))
                .unwrap_or_default()
        );
        out.push_str(&render_headers(&self.headers, opts.redact));
        out.push('\n');
        if !self.body.is_empty() {
            let text = body_text(self.header("content-type"), &self.body, opts.pretty);
            out.push_str(&shape_body(text, opts));
        }
        if self.body_truncated {
            out.push_str("\n… [body truncated by capture limit]");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: Vec<Header>, body: &[u8], ct: Option<&str>) -> HttpRequest {
        let mut h = headers;
        if let Some(ct) = ct {
            h.push(("Content-Type".into(), ct.into()));
        }
        HttpRequest {
            method: "POST".into(),
            scheme: "https".into(),
            host: "t.test".into(),
            port: 443,
            path: "/x".into(),
            query: None,
            http_version: "HTTP/1.1".into(),
            headers: h,
            body: body.to_vec(),
            body_truncated: false,
        }
    }

    #[test]
    fn redacts_sensitive_headers() {
        let r = req(
            vec![
                ("Cookie".into(), "session=supersecretvalue".into()),
                ("Authorization".into(), "Bearer abcdef123456".into()),
                ("Accept".into(), "*/*".into()),
            ],
            b"",
            None,
        );
        let raw = r.to_raw_opts(&RenderOpts::default());
        assert!(raw.contains("Cookie: sessio…[redacted]"));
        assert!(raw.contains("Authorization: Bearer…[redacted]"));
        assert!(raw.contains("Accept: */*")); // untouched
    }

    #[test]
    fn redaction_can_be_disabled() {
        let r = req(vec![("Cookie".into(), "session=abc123456".into())], b"", None);
        let opts = RenderOpts {
            redact: false,
            ..Default::default()
        };
        assert!(r.to_raw_opts(&opts).contains("Cookie: session=abc123456"));
    }

    #[test]
    fn pretty_prints_json_body() {
        let r = req(vec![], br#"{"a":1,"b":[2,3]}"#, Some("application/json"));
        let raw = r.to_raw_opts(&RenderOpts::default());
        assert!(raw.contains("\"a\": 1"));
        assert!(raw.contains("\"b\": [")); // reflowed
    }

    #[test]
    fn highlights_payload() {
        let r = req(vec![], b"q=SELECT * FROM users--", Some("text/plain"));
        let opts = RenderOpts {
            highlight: Some("SELECT".into()),
            ..Default::default()
        };
        let raw = r.to_raw_opts(&opts);
        assert!(raw.contains("«SELECT»"));
    }

    #[test]
    fn truncates_but_keeps_payload_window() {
        let big = format!("{}NEEDLE{}", "A".repeat(5000), "B".repeat(5000));
        let r = req(vec![], big.as_bytes(), Some("text/plain"));
        let opts = RenderOpts {
            highlight: Some("NEEDLE".into()),
            max_body: 2000,
            ..Default::default()
        };
        let raw = r.to_raw_opts(&opts);
        assert!(raw.contains("«NEEDLE»")); // survived truncation
        assert!(raw.contains("truncated")); // and was truncated
        assert!(raw.len() < big.len()); // smaller than the raw dump
    }
}
