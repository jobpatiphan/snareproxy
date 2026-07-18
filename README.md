<h1 align="center">🪤 Snare</h1>

<p align="center">
  <b>The Rust-native, AI-driven web security proxy.</b><br>
  <i>เบาแต่เก่งรอบด้าน · เสถียร · parallel ขั้นสุด · เล่นได้ 3 หน้า จากแกนเดียว</i>
</p>

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-alpha%20%C2%B7%20core%20working-brightgreen">
  <img alt="language" src="https://img.shields.io/badge/built%20with-Rust-orange?logo=rust">
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-green">
  <img alt="AI" src="https://img.shields.io/badge/AI--native-MCP-8A2BE2">
</p>

---

## What is Snare?

**Snare** is an open-source web application security proxy — a **Burp Suite alternative built in Rust from the core**, designed to be **faster, lighter, and smarter**, and open for everyone to extend.

One core, **three faces** from the same engine:

- 🖥️ **TUI** — keyboard-driven terminal UI (ratatui), perfect over SSH
- 🌐 **Web** — open it in any browser, host it on a server
- 🪟 **Desktop** — native app (Tauri), ~30–50 MB RAM, < 10 MB bundle

And it's **AI-native**: Snare exposes its *entire* toolset over the **Model Context Protocol (MCP)**, so agents like Claude can drive it directly — from a simple "analyze this request" to an **autonomous, self-verifying pentester**.

> **In one line:** *Burp's power with Rust's speed and an AI brain — lighter, faster, smarter, and open to everyone.*

## Why Snare wins

| | Snare | Legacy proxies |
|---|---|---|
| **AI-native** | Full toolset over MCP; autonomous agent loop | Bolt-on, closed, limited |
| **Performance** | Rust/hyper · constant RAM over millions of flows · startup < 0.5s | JVM · heavy RAM · slow start |
| **Frontends** | TUI + Web + Desktop + remote, one core | Single desktop app |
| **Open & extensible** | Apache-2.0 · cross-language WASM plugins · imports Nuclei templates | Closed · single-language extensions |
| **Automation** | HTTPQL + CLI + REST + MCP — fully scriptable | UI-centric |
| **Trust** | Zero telemetry · runs local AI models | Ads / cloud telemetry |

## Feature vision

Proxy · Repeater · Intruder · **HTTPQL** query language · Match & Replace · Decoder / Comparer / Sequencer · Sitemap & Scope · Passive & Active Scanner (with **Nuclei** import) · WebSocket / gRPC / GraphQL tooling · JWT / OAuth kit · **Autonomous AI pentester** · session-handling & macros · full reporting (MD / HTML / PDF / **SARIF**) · team mode · WASM plugins.

**📖 [Usage guide](docs/USAGE.md)** — how to use every tool + team mode. ·
See the full **57-section architecture** in **[`docs/DESIGN.md`](docs/DESIGN.md)**
and the **[team-mode design](docs/design/team-mode.md)**.

## Architecture at a glance

```
  TUI (ratatui) ── Web (WASM) ── Desktop (Tauri)     ← thin frontends, no logic
                       │  snare-client SDK
                       ▼
                   snared (daemon)  ── axum REST/WS · MCP (rmcp)
                       │
                   snare-core  (library) ── capture · repeater · intruder · scanner
                       │                     rules · HTTPQL · AI orchestrator
        tokio (async I/O) ⇄ rayon (CPU-bound) + backpressure
        Storage port: SQLite WAL + blob  →  Postgres (team mode)
        Engine  port: snare-engine (hudsucker / hyper / rustls)
  [Browser / client] ─▶ snare-engine (data-plane) ─▶ [Target]
```

## Status

🟢 **Working today** — the Burp-style core is implemented, runnable, and
verified end-to-end:

| Capability | State |
|---|---|
| HTTPS-intercepting proxy + capture (SQLite) | ✅ |
| **Interactive Intercept** — hold/edit/drop requests *and* responses | ✅ |
| **Scope** — limit intercept to given hosts | ✅ |
| **Repeater** — resend a captured request | ✅ |
| **Match & Replace** — automatic regex rewrites on req/resp | ✅ |
| **Intruder** — bounded-parallel payload fuzzing | ✅ |
| **Passive scanner** — auto-flag missing headers, cookie flags, reflected params | ✅ |
| **Decoder** — Base64 / URL / Hex / JWT | ✅ |
| Three faces — TUI · Web dashboard · Desktop (Tauri) | ✅ |
| AI-native — MCP tools (`proxy_*`, `repeater_send`, `intruder_run`) | ✅ |
| Persisted rules / scope / scanner across restart | ✅ |

Still on the roadmap (see [`docs/DESIGN.md`](docs/DESIGN.md), 57 sections):
HTTPQL query language, active scanner, Comparer/Sequencer, WebSocket/GraphQL,
session handling & macros, reporting (SARIF), team mode, WASM plugins, and the
autonomous AI pentester.

The live dashboard (`http://127.0.0.1:9000/`) exposes intercept, scope, Match &
Replace, findings, and the decoder from its toolbar.

### Quickstart

```bash
cargo build
./target/debug/snared ca generate          # unique per-install CA (§28)
# install the printed cert in your browser/OS trust store, then:
./target/debug/snared run                   # proxy :8888, REST API + dashboard :9000
# open the live dashboard in any browser:
#   http://127.0.0.1:9000/
# point your browser/curl at the proxy:
curl --proxy http://127.0.0.1:8888 --cacert <ca.pem> https://example.com
./target/debug/snared flows                 # list captured flows (CLI)
./target/debug/snare-tui                     # or watch them live in the TUI (r = resend)
```

Ports are overridable: `snared run --proxy 127.0.0.1:9999 --api 127.0.0.1:9001`.

Three faces, one core — the same live dashboard, natively:

```bash
./target/debug/snare-desktop     # native window (Tauri) onto the daemon dashboard
# SNARE_URL=http://remote:9000/ ./target/debug/snare-desktop   # or a remote daemon
```

> **Desktop build prerequisites (Linux):** the `snare-desktop` crate needs the
> Tauri/webkit system libraries:
> `sudo apt install -y libwebkit2gtk-4.1-dev build-essential libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev pkg-config`.
> The other crates build without them.

The `snare-mcp` binary is a stdio MCP server exposing `proxy_list_flows`,
`proxy_get_flow`, `proxy_stats`, `repeater_send`, and `intruder_run` — point an
MCP client (e.g. Claude) at it to drive the captured traffic. It reports each
call to the daemon,
so the dashboard shows, live, what the agent is doing.

### Roadmap

| Phase | Delivers |
|---|---|
| **0 · Skeleton** | Cargo workspace, `snare-core` traits, empty `snared`, CI, gen-CA |
| **1 · Core Loop** | Engine (hudsucker) + capture + SQLite + REST/WS + TUI + MCP (stdio) |
| **2 · Attack + Web** | Intruder + Match&Replace + Decoder/Comparer + Sitemap + full HTTPQL + Web UI |
| **3 · AI + Passive + Desktop** | MCP Streamable HTTP + AI tools + passive scanner + Desktop (Tauri) |
| **4 · Active Scanner** | Crawl + active checks (SQLi/XSS/SSRF/IDOR) + reporting |
| **5 · Pro-grade + Scale** | OAST/Collaborator + session handling + workflows + Postgres/team mode |

## Contributing

Snare is an ambitious, open project — ideas, RFCs, and code are welcome once Phase 0 lands.
Architectural changes follow the ADR process documented in the design doc.

## License

[Apache-2.0](LICENSE) © Snare contributors

---

<p align="center"><i>Built with ❤️ and 🦀 — a dream in progress.</i></p>
