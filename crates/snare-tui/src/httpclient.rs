//! Tiny dependency-free HTTP/1.1 client for the local REST API.
//!
//! Only what the TUI needs: localhost, JSON, `Connection: close`, read to EOF.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};

fn request(method: &str, host: &str, port: u16, path: &str, read_secs: u64) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port))
        .with_context(|| format!("connect {host}:{port} (is `snared run` up?)"))?;
    stream.set_read_timeout(Some(Duration::from_secs(read_secs)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status_line = head.lines().next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        bail!("HTTP {code} for {path}");
    }
    Ok(raw[split + 4..].to_vec())
}

/// GET `path`, returning the response body bytes.
pub fn get(host: &str, port: u16, path: &str) -> Result<Vec<u8>> {
    request("GET", host, port, path, 5)
}

/// Empty-body POST `path` (used by the repeater), returning the response body.
/// Longer read timeout: the daemon does a real round-trip before replying.
pub fn post(host: &str, port: u16, path: &str) -> Result<Vec<u8>> {
    request("POST", host, port, path, 25)
}

pub fn get_json<T: serde::de::DeserializeOwned>(host: &str, port: u16, path: &str) -> Result<T> {
    let body = get(host, port, path)?;
    Ok(serde_json::from_slice(&body)?)
}

pub fn post_json<T: serde::de::DeserializeOwned>(host: &str, port: u16, path: &str) -> Result<T> {
    let body = post(host, port, path)?;
    Ok(serde_json::from_slice(&body)?)
}
