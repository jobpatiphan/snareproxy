//! Live event feed over the daemon's SSE stream (`/api/v1/stream`).
//!
//! A background thread holds a long-lived connection, parses `data:` lines into
//! [`FlowEvent`]s, and forwards them over a channel the UI loop drains. It
//! reconnects on drop and exits once the receiver is gone.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use snare_core::model::FlowEvent;

/// Start streaming; returns the receiving end of the event channel.
pub fn subscribe(host: String, port: u16) -> Receiver<FlowEvent> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        // `false` = the UI dropped the receiver → stop the thread. Any other
        // outcome (clean disconnect or io error) means reconnect after a pause.
        if !stream_once(&host, port, &tx) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    });
    rx
}

/// Read one connection to exhaustion. Returns `true` to keep reconnecting,
/// `false` once the receiver is gone.
fn stream_once(host: &str, port: u16, tx: &Sender<FlowEvent>) -> bool {
    let Ok(stream) = TcpStream::connect((host, port)) else {
        return true;
    };
    let Ok(mut w) = stream.try_clone() else {
        return true;
    };
    let req = format!(
        "GET /api/v1/stream HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n"
    );
    if w.write_all(req.as_bytes()).is_err() {
        return true;
    }

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { return true };
        let Some(data) = line.strip_prefix("data:") else {
            continue; // headers, blank lines, or ':' keep-alive comments
        };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<FlowEvent>(data) {
            if tx.send(ev).is_err() {
                return false; // UI gone
            }
        }
    }
    true
}
