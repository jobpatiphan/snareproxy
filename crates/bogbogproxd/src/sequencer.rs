//! Sequencer (§ Burp Sequencer) — analyses the randomness of a set of tokens
//! (session ids, CSRF tokens, …), either supplied directly or collected by
//! resending a request N times and extracting a value from each response.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use regex::Regex;
use serde_json::{json, Value};
use bogbogprox_core::model::{FlowEvent, HttpRequest, Source};
use bogbogprox_core::store::FlowStore;
use tokio::sync::broadcast;

use crate::repeater;

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Compute randomness statistics for a set of tokens.
pub fn analyze(tokens: &[String]) -> Value {
    let n = tokens.len();
    let unique: HashSet<&String> = tokens.iter().collect();
    let duplicates = n.saturating_sub(unique.len());
    let lengths: Vec<usize> = tokens.iter().map(|t| t.chars().count()).collect();
    let min_len = lengths.iter().min().copied().unwrap_or(0);
    let max_len = lengths.iter().max().copied().unwrap_or(0);

    // Per-character-position Shannon entropy over the common prefix length.
    let mut pos_entropy = Vec::with_capacity(min_len);
    let total = n as f64;
    for i in 0..min_len {
        let mut freq: HashMap<char, usize> = HashMap::new();
        for t in tokens {
            if let Some(c) = t.chars().nth(i) {
                *freq.entry(c).or_default() += 1;
            }
        }
        let h: f64 = freq
            .values()
            .map(|&c| {
                let p = c as f64 / total;
                -p * p.log2()
            })
            .sum();
        pos_entropy.push(round2(h));
    }
    let total_entropy: f64 = pos_entropy.iter().sum();
    let avg = if pos_entropy.is_empty() {
        0.0
    } else {
        total_entropy / pos_entropy.len() as f64
    };
    let charset: HashSet<char> = tokens.iter().flat_map(|t| t.chars()).collect();

    let verdict = if n < 20 {
        "INCONCLUSIVE — collect ≥ 20 samples for a meaningful verdict"
    } else if duplicates > 0 {
        "WEAK — duplicate tokens observed"
    } else if avg < 2.0 {
        "WEAK — low per-position entropy"
    } else if avg < 3.5 {
        "MODERATE"
    } else {
        "STRONG"
    };

    json!({
        "samples": n,
        "unique": unique.len(),
        "duplicates": duplicates,
        "min_len": min_len,
        "max_len": max_len,
        "charset_size": charset.len(),
        "total_entropy_bits": round2(total_entropy),
        "avg_position_entropy_bits": round2(avg),
        "position_entropy": pos_entropy,
        "verdict": verdict,
    })
}

/// Resend `base` `count` times, extracting a token from each response with
/// `extract` (capture group 1 if present, else the whole match; searched over
/// response headers + body).
pub async fn collect(
    store: &Arc<dyn FlowStore>,
    events: &broadcast::Sender<FlowEvent>,
    base: &HttpRequest,
    count: usize,
    extract: &str,
) -> Result<Vec<String>> {
    let re = Regex::new(extract)?;
    let url = base.url();
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count.min(500) {
        let flow = repeater::send(
            store,
            events,
            Source::Repeater,
            &base.method,
            &url,
            &base.headers,
            base.body.clone(),
        )
        .await?;
        if let Some(resp) = &flow.response {
            let headers: String = resp
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            let hay = format!("{headers}\n\n{}", String::from_utf8_lossy(&resp.body));
            if let Some(cap) = re.captures(&hay) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                    tokens.push(m.as_str().to_string());
                }
            }
        }
    }
    Ok(tokens)
}
