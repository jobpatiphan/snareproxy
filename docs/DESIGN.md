# BogBogProx — Design Document (v2, Rust-first)

> **BogBogProx** — an open-source, AI-native web security proxy, written in **Rust**.
> เบาแต่เก่งรอบด้าน · เสถียร · parallel ขั้นสุด · เผื่อ scale · เล่นได้ 3 หน้า: **Terminal (TUI) · Web · Desktop** จากแกนเดียวกัน.

- **Status:** Design / Planning (ยังไม่เริ่มเขียนโค้ดแอป)
- **Language:** Rust (ทั้งระบบ) · **License (planned):** Apache-2.0
- **Last updated:** 2026-07-16

---

## 1. Vision, Goals, Non-Goals

### 1.1 Vision
เครื่องมือทดสอบความปลอดภัยเว็บที่ **เขียนด้วย Rust ตั้งแต่แกน** เพื่อความเร็ว/เสถียร/หน่วยความจำต่ำระดับโปรดักชัน — โดยมี **แกนเดียว (single core)** ที่หน้าตาได้หลายแบบ: TUI สาย terminal, Web สำหรับทุกที่, และ Desktop แบบ native — และเปิดให้ **AI ทุกสำนักสั่งงานผ่าน MCP**.

### 1.2 Goals
1. **Rust-first, quality-first** — memory-safe, no-GC, static binary, สตาร์ตเร็ว, RAM ต่ำ.
2. **Tri-frontend จากแกนเดียว** — TUI (ratatui) · Web (WASM/SPA) · Desktop (Tauri) ใช้ `bogbogprox-core` ร่วมกัน ไม่เขียน logic ซ้ำ.
3. **Parallel ขั้นสุด** — tokio สำหรับ async I/O (proxy หลายพันคอนเนกชัน), rayon สำหรับงาน CPU-bound (scanner/diff/entropy), มี backpressure กันล้น.
4. **Feature จัดเต็ม** — Proxy, Repeater, Intruder, Target/Sitemap, Match&Replace, Decoder, Comparer, Sequencer, Passive/Active Scanner, WebSocket tooling, JWT/OAuth kit.
5. **AI-native** — MCP server (stdio + Streamable HTTP) เปิด "ทั้งเครื่องมือ".
6. **Scale ง่าย** — local single-binary → daemon + หลาย client → team mode (Postgres) โดยไม่รื้อ.

### 1.3 Non-Goals (ช่วงแรก — พูดตรง)
- แข่งความแม่นของ **Burp Scanner** ทันที (สะสม 10+ ปี) — เราทำ "ระดับใช้ได้" ก่อน.
- **Collaborator/OAST** เต็มรูป (ต้อง public infra) — เฟสท้าย.
- Mobile app — ยังไม่ทำ (แต่สถาปัตยกรรม core แยกไว้ให้ต่อได้).
- **HTTP/3 (QUIC)** — hudsucker/hyper ยังไม่รองรับ MITM ระดับโปรดักชัน; ใส่ Engine port เผื่อไว้ (§6, §27) แต่ยังไม่ทำเฟสแรก.
- **รัน Burp extension (.jar/BApp) ตรง ๆ** — คนละ ABI; เราไปทาง WASM+MCP (§21) แทน. อาจมี "import wordlist/config" จาก Burp แต่ไม่รันโค้ด Java.

> **ซื่อสัตย์:** "ครบ + เก่งกว่า Burp 100%" ไม่จบในไม่กี่วัน. เอกสารนี้เลือก *สถาปัตยกรรมปลายทางที่แรงสุด (Rust)* ตั้งแต่บรรทัดแรก และวาง *เส้นทางเป็นเฟส* ที่มีของรันได้ไว ๆ โดยไม่ต้องรื้อ.

---

## 2. Research Summary (อ้างอิงจริง)

| ประเด็น | ข้อค้นพบ | ผลต่อการออกแบบ | อ้างอิง |
|---|---|---|---|
| เครื่องมือยุคใหม่ชนะ Burp | **Caido** = Rust backend + browser UI + query language (HTTPQL) + AI plugins | ยืนยัน Rust core + web UI + query lang + AI | [1] |
| MITM ใน Rust | **hudsucker** = intercepting HTTP/S proxy บน **hyper + rustls + rcgen** (ออก cert on-the-fly), แก้ req/resp/WebSocket | แกน engine ของเรา | [2][3] |
| บทเรียน proxy Rust | `hyper` low-level จัดการ body/chunked/SSE ดี; รักษา **ALPN/HTTP2** (HTTP/2 ห้าม Host header); ตั้ง `TCP_NODELAY`; `rcgen` ออก cert | รู้กับดักล่วงหน้า | [4] |
| Desktop เบา | **Tauri** vs Electron: bundle < 10MB (Electron 80–150MB), RAM ~30–50MB (Electron 150–300MB); Hoppscotch ย้าย Electron→Tauri: 165MB→8MB, RAM −70% | Desktop = **Tauri** (native webview + Rust) | [5] |
| TUI | **ratatui** = de-facto TUI ของ Rust (เบื้องหลัง gitui/แนว lazygit), immediate-mode, render **sub-ms** | TUI = **ratatui** | [6] |
| แชร์ core หลาย frontend | **Cargo workspace**: core lib + หลาย frontend crate (เช่น linutil: core/tui/xtask) แชร์ Cargo.lock, dep เดียว | โครง monorepo แบบ workspace | [7] |
| Parallel async+CPU | **tokio + rayon**: async I/O บน tokio, งาน CPU-bound โยนเข้า rayon ผ่าน `spawn`+oneshot, ใช้ **semaphore** ทำ backpressure กัน queue ล้น | โมเดล concurrency ของเรา | [8] |
| MCP transports | เหลือ **stdio (local)** + **Streamable HTTP (remote)**; HTTP+SSE เดิม deprecate (2025-03-26) | MCP = stdio + Streamable HTTP (Rust SDK `rmcp`) | [9][10] |
| Storage | **SQLite WAL** single-writer, ~10k–50k writes/s, เจอ `SQLITE_BUSY` เมื่อ writer หลายร้อย → ใช้ writer actor + batch; Postgres เป็น scale-out | storage layer (§7) | [11][12] |

ดู §46 สำหรับอ้างอิงเต็ม.

---

## 3. สถาปัตยกรรมภาพรวม (Single Core, Many Faces)

```
        ┌──────────────── FRONTENDS (บาง, ไม่มี business logic) ────────────────┐
        │   bogbogprox-tui (ratatui)      bogbogprox-web (WASM SPA)      bogbogprox-desktop     │
        │   สาย terminal/lazygit      เปิดในเบราว์เซอร์          (Tauri, native)   │
        └───────────────┬───────────────────┬───────────────────┬──────────────┘
                        │  bogbogprox-client (SDK) — REST/WS/gRPC ไปยัง daemon เดียว    │
                        ▼                    ▼                    ▼
        ┌───────────────────────────── bogbogproxd (daemon) ─────────────────────────┐
        │  API surface:  axum(REST + WS)  ·  MCP(stdio + Streamable HTTP, rmcp)  │
        ├───────────────────────────────────────────────────────────────────────┤
        │                       bogbogprox-core  (library crate)                      │
        │  Capture · Repeater · Intruder · Scanner · Sitemap · Rules ·           │
        │  HTTPQL engine · Projects · AI-assist orchestrator                     │
        │  concurrency: tokio (async I/O)  ⇄  rayon (CPU-bound) + backpressure    │
        │  ┌───────── Storage port ─────────┐   ┌──────── Engine port ─────────┐ │
        │  │ SQLite WAL (writer actor+batch) │   │ trait ProxyEngine            │ │
        │  │ + blob store (content-addressed)│   │  ← impl: bogbogprox-engine (Rust) │ │
        │  │ adapter → Postgres (team mode)  │   │    hudsucker/hyper/rustls    │ │
        │  └─────────────────────────────────┘   └──────────────────────────────┘│
        └───────────────────────────────┬───────────────────────────────────────┘
   [Browser / client / Stealth-Browser MCP] ──▶ bogbogprox-engine (data-plane) ──▶ [Target]
```

**หลักการ:** logic ทั้งหมดอยู่ใน `bogbogprox-core` (Rust library). `bogbogproxd` ห่อ core ด้วย transport. Frontends ทั้ง 3 เป็น **เปลือกบาง** ที่คุยกับ `bogbogproxd` ผ่าน `bogbogprox-client` SDK ตัวเดียว → ไม่มี logic ซ้ำ, พฤติกรรมตรงกันทุกหน้า, และ **ต่อ remote daemon ได้** (TUI/Desktop เชื่อม bogbogproxd ที่รันบนเซิร์ฟเวอร์ได้แบบ Caido [1]).

**โหมด single-binary:** `bogbogprox-tui`/`bogbogprox-desktop` สามารถ embed `bogbogprox-core` ตรง ๆ (ไม่ต้องมี daemon แยก) สำหรับใช้เครื่องเดียวแบบเบาสุด — เพราะ core เป็น library.

---

## 4. Concurrency & Parallelism (หัวใจ "parallel ขั้นสุด")

อ้างอิงแนวปฏิบัติ tokio+rayon [8]:

| งาน | รันบน | เหตุผล |
|---|---|---|
| Proxy connections, HTTP replay, WS | **tokio** async tasks | I/O-bound หลายพันพร้อมกัน, ไม่บล็อก |
| Intruder (ยิง N payload) | tokio tasks + `Semaphore` คุม concurrency | I/O-bound, ต้องจำกัดอัตรากัน DoS ตัวเอง |
| Scanner analysis, body diff, entropy, regex ชุดใหญ่ | **rayon** thread-pool | CPU-bound; แยกออกจาก tokio worker ไม่ให้ freeze event loop [8] |
| Storage writes | **writer actor เดียว** + batch | กัน SQLite single-writer contention [11][12] |

**สะพาน tokio⇄rayon:** งาน CPU โยนเข้า `rayon::spawn` แล้วรอผลผ่าน `tokio::sync::oneshot`; มี **semaphore เป็น pressure valve** จำกัด batch in-flight ไม่ให้คิว rayon โตไม่จำกัดตอน burst [8]. ผลคือ proxy ยังตอบทันแม้ scanner ทำงานหนักพร้อมกัน.

---

## 5. Frontends (เล่นได้ 3 หน้า)

### 5.1 TUI — `bogbogprox-tui` (ratatui [6])
- แนว **lazygit/gitui**: keyboard-driven, panel History/Request/Response, HTTPQL bar, hotkey `r`=send-to-repeater, `i`=intruder, `/`=filter.
- render sub-ms, เบามาก, เหมาะรันบน SSH/เซิร์ฟเวอร์/สาย terminal.
- ใช้ `bogbogprox-client` → ต่อ daemon local หรือ remote.

### 5.2 Web — `bogbogprox-web`
- SPA ต่อ `bogbogproxd` (REST + WS). เปิดในเบราว์เซอร์, host บนเซิร์ฟเวอร์แล้วต่อไกลได้ (แบบ Caido [1]).
- **ตัวเลือก stack:** *Rust/WASM* (Leptos หรือ Dioxus — คงความเป็น all-Rust, แชร์ type กับ core) เป็นค่าเริ่ม; TypeScript (Svelte/React) เป็น fallback ถ้าต้องการ ecosystem UI.

### 5.3 Desktop — `bogbogprox-desktop` (Tauri [5])
- ห่อ `bogbogprox-web` ใน **native webview** (WebView2/WebKit/GTK) + backend Rust = bundle < 10MB, RAM ~30–50MB [5].
- ฝัง/สั่ง `bogbogproxd` ให้ในตัว, จัดการ CA trust, เมนู native, auto-update.

> ทั้ง 3 หน้าใช้ core+API เดียวกัน → พฤติกรรม/ข้อมูลตรงกันเป๊ะ.

---

## 6. Component — Proxy Engine (`bogbogprox-engine`, data-plane)

**Trait `ProxyEngine` (Engine port):**
```rust
trait ProxyEngine {
    async fn start(&self, cfg: EngineCfg, tx: Sender<FlowEvent>) -> Result<()>;
    async fn set_intercept(&self, scope: Scope, on: bool);
    async fn resolve(&self, flow_id: FlowId, action: Action, modified: Option<HttpRequest>);
    async fn set_rules(&self, rules: Vec<Rule>);   // match & replace ระดับ wire-speed
}
enum FlowEvent { Started{..}, RequestReady{..}, ResponseReady{..}, WsMessage{..} }
```
- **Impl:** hudsucker/hyper/rustls/rcgen [2][3][4] — HTTP/1.1 · HTTP/2 · WebSocket, streaming body (ไม่โหลดทั้งก้อนในหน่วยความจำ), ออก cert on-the-fly.
- **กับดักที่รู้แล้ว** [4]: รักษา ALPN/HTTP version, ลบ Host header เมื่อข้าม HTTP/2, ตั้ง `TCP_NODELAY`.
- **body** ส่งเป็น `body_ref` (เก็บลง blob store) ไม่ส่งทั้งก้อนผ่าน channel → RAM คงที่.

---

## 7. Storage (port + adapters)

| ตัวเลือก | บทบาท | อ้างอิง |
|---|---|---|
| **SQLite WAL** (rusqlite/sqlx) | default local — metadata ของ flow/issue/tab | [11][12] |
| **Blob store** (ไฟล์ content-addressed, hash = ชื่อ) | req/resp body (dedup, ไม่บวม DB) | — |
| **Postgres** (sqlx) | scale-out / team mode (MVCC หลาย writer) | [11] |

**กันคอขวด single-writer:** ทุก write ผ่าน **writer actor เดียว** batch เป็นชุด (ทุก ~50 flows หรือ 100ms) + `PRAGMA journal_mode=WAL; synchronous=NORMAL; busy_timeout=5000` [11][12]. FTS5 สำหรับ full-text body ใน HTTPQL.

---

## 8. Core Service API (บน `bogbogproxd`)

### 8.1 REST (axum) — bind `127.0.0.1` default (§12)
```
# flows / proxy
GET  /api/v1/flows?q=<HTTPQL>&limit&offset&sort
GET  /api/v1/flows/{id}[/request|/response][?raw=1]
POST /api/v1/flows/{id}/annotate {color,comment,tags[]}
# intercept
GET  /api/v1/intercept · PUT {enabled,scope} · POST /{id}/resolve {action,modified?}
# repeater
POST /api/v1/repeater/send {request,target,options} -> {response,timing}
CRUD /api/v1/repeater/tabs
# intruder
POST /api/v1/intruder/attacks {base,positions[],payload_sets[],mode,grep[]} -> {attack_id}
GET  /api/v1/intruder/attacks/{id}[/results?q=]  · POST /{id}/{pause|resume|stop}
# rules / tools
CRUD /api/v1/rules            # match&replace, scope
POST /api/v1/codec {op,scheme,data}
POST /api/v1/comparer {a,b,mode}
POST /api/v1/sequencer {token_source,samples} -> entropy
# target / scanner
GET  /api/v1/sitemap?host= · GET/PUT /api/v1/scope
GET  /api/v1/issues?q= · POST /api/v1/scan {target,profile:passive|active}
# ai
POST /api/v1/ai/{analyze|find-idor|suggest-payloads} {flow_id,..}
# project / realtime
POST /api/v1/projects · /{id}/open · /{id}/export {format:bogbogprox|har|json}
WS   /ws            # summary events (§9)
```

### 8.2 HTTPQL (query language, แนว Caido [1])
```
req.method:"POST" AND resp.status:500..599 AND req.host:*.aegis-ctf.com
resp.body.contains:"flag{" OR req.path:/api/orders/*
```
→ parser (crate `bogbogprox-core::httpql`) แปลงเป็น SQL WHERE + FTS5.

---

## 9. Realtime Event Schema (WS)
```
-> flow.new {summary}      -> flow.update {id,status,resp_summary}
-> intercept.hold {id,req} -> intruder.tick {attack_id,done,total,last}
-> issue.new {issue}
<- subscribe {channels:["flows","intercept","intruder:<id>"]}
```
ส่ง **summary** เท่านั้น (ไม่รวม body) → body ดึงตาม id เพื่อลด payload/latency บนทุก frontend.

---

## 10. MCP Server (จุดขายหลัก) — Rust `rmcp` [9][10]
**Transport:** **stdio** (local: Claude Code/Desktop, Cline) + **Streamable HTTP** (remote/AI สำนักอื่น: endpoint เดียว `POST+GET /mcp`, ตรวจ `Origin` กัน DNS-rebinding). ไม่ใช้ HTTP+SSE รุ่นเก่า.

**Tools:**
```
proxy_list_flows(query?,limit,offset) · proxy_get_flow(id,part) · proxy_search(query)
proxy_set_intercept(on,scope?) · proxy_intercept_queue() · proxy_resolve(id,action,modified?)
repeater_send(request,target,options?) · intruder_run(base,positions,payloads,mode,grep) · intruder_results(id,query?)
rules_match_replace(op,rule?) · codec(op,scheme,data) · comparer(a,b,mode?)
scanner_passive_issues(query?) · scanner_active(target,profile)
ai_analyze_request(id) · ai_find_idor(id) · ai_suggest_payloads(id,param)
project_export(format)
```
**Resources:** `bogbogprox://flow/{id}`, `bogbogprox://issue/{id}` ให้ agent อ้างหลักฐาน. **โหมด read-only** จำกัด active tool ตอนยังไม่อนุญาต.

---

## 11. Feature Parity Matrix (Burp → BogBogProx, all-Rust)

| Burp | BogBogProx | เฟส | หมายเหตุ |
|---|---|---|---|
| Proxy (intercept/history) | engine+capture | **1** | hudsucker |
| Repeater | repeater | **1** | |
| HTTP history filter | HTTPQL | **1** | Caido-style [1] |
| Target/Sitemap/Scope | sitemap | 2 | |
| Intruder (4 โหมด) | intruder | 2 | tokio+semaphore |
| Match & Replace | rules | 2 | ที่ engine = wire-speed |
| Decoder/Encoder · Comparer · Sequencer | tools | 2–3 | |
| Passive Scanner | scanner/passive | 3 | rayon |
| Active Scanner | scanner/active | 4 | สะสมความแม่น |
| WebSocket repeater/history | ws-tools | 3 | engine รองรับ WS อยู่แล้ว |
| JWT/OAuth toolkit | tools/authkit | 3 | เหนือ Burp community |
| Extensions (BApp) | **MCP + WASM/native plugin** | 1→ | จุดต่าง |
| Workflows/automation | workflows (node) | 5 | Caido-style [1] |
| Collaborator/OAST | oast | 5 | ต้อง public infra |
| **AI assistant** | ai + MCP | 3 | Burp ให้น้อย/ปิดโค้ด |

---

## 12. Performance/Scale Targets + Security

### 12.1 SLO
- Proxy: p99 added-latency **< 5ms**, throughput **≥ 5,000–10,000 req/s** ต่อ node (Rust/hyper), RAM คงที่แม้ flow ล้านรายการ (body แยก blob).
- TUI: render **sub-ms** [6]. Desktop: RAM **~30–50MB**, bundle **< 10MB** [5].
- Storage: writer actor batch กัน `SQLITE_BUSY`, รองรับ burst หลายพัน insert/s [11][12].

### 12.2 Security / Authz
- bind `127.0.0.1` default; remote mode = **token auth + TLS** + ตรวจ `Origin` (MCP/WS) กัน DNS-rebinding [9].
- CA private key 0600, คำสั่ง regenerate/trust แยก.
- MCP read-only mode; active tools ต้อง opt-in.

---

## 13. Repo Layout (Cargo workspace [7])
```
bogbogprox/                        # cargo workspace root (Cargo.toml [workspace])
├── docs/                     DESIGN.md, ADRs, API.md, HTTPQL.md
├── crates/
│   ├── bogbogprox-core/           domain: capture, repeater, intruder, scanner, rules, httpql, storage port
│   ├── bogbogprox-engine/         proxy data-plane (hudsucker/hyper/rustls/rcgen)  ← impl ProxyEngine
│   ├── bogbogprox-store-sqlite/   SQLite WAL + writer actor + blob store
│   ├── bogbogprox-store-postgres/ scale-out adapter
│   ├── bogbogprox-mcp/            MCP server (stdio + streamable-http, rmcp)
│   ├── bogbogprox-client/         client SDK (REST/WS/gRPC) — ใช้โดย TUI/Desktop
│   ├── bogbogproxd/               daemon: axum(REST+WS) + MCP + serve web assets  (bin)
│   ├── bogbogprox-tui/            ratatui frontend  (bin)
│   └── bogbogprox-desktop/        Tauri app         (bin)
├── web/                      bogbogprox-web SPA (Leptos/Dioxus หรือ TS) → build → served by bogbogproxd/tauri
├── plugins/                  WASM/native plugin host + ตัวอย่าง
├── tests/                    unit + engine-conformance + e2e (ยิง lab จริง)
├── xtask/                    task runner (build/release/gen-ca)  [7]
└── README.md
```

---

## 14. Roadmap + Acceptance (Rust ตั้งแต่เฟส 1)

| เฟส | ส่งมอบ | Acceptance |
|---|---|---|
| **0 · Skeleton** | cargo workspace, `bogbogprox-core` traits, `bogbogproxd` เปล่า, CI (fmt/clippy/test), gen-CA | `cargo build` ผ่านทุก crate, CI เขียว |
| **1 · Core Loop** | bogbogprox-engine(hudsucker) + capture + SQLite + REST/WS + **bogbogprox-tui** + MCP(stdio) | จับ HTTPS จริง, TUI เห็น flow สด + Repeater, `proxy_list_flows`/`repeater_send` จาก Claude, restart แล้วงานไม่หาย |
| **2 · Attack + Web** | Intruder(4โหมด, parallel) + Match&Replace + Decoder/Comparer + Sitemap + HTTPQL เต็ม + **bogbogprox-web** | Intruder 500 payload+grep, M&R สด, Web UI ใช้ได้เท่า TUI |
| **3 · AI + Passive + Desktop** | MCP Streamable HTTP + ai_* tools + passive scan(rayon) + Sequencer + WS/JWT tools + **bogbogprox-desktop(Tauri)** | agent หา IDOR ใน lab ได้เอง, remote MCP ต่อได้, desktop RAM ~30–50MB |
| **4 · Active Scanner** | crawl + active checks (SQLi/XSS/SSRF/IDOR) + report | เจอ vuln ตัวอย่างครบชุด, false-positive ต่ำ |
| **5 · Pro-grade + Scale** | OAST/Collaborator + session-handling/macro + Workflows + **Postgres/team mode** + ผูก pentest-dashboard | OAST callback เข้า, team mode หลาย client, workflow อัตโนมัติ |

**เผื่อ scale:** เพราะ frontends คุยผ่าน `bogbogprox-client`/API, storage/engine อยู่หลัง port — เปลี่ยน SQLite→Postgres หรือเพิ่ม node ได้โดยไม่แตะ UI; core เป็น library ฝังในโหมด single-binary ก็ได้ กระจายเป็น daemon ก็ได้.

---

## 15. Risks & Hard Parts (พูดตรง)
1. **Rust dev เริ่มช้ากว่า** ช่วงแรก (borrow checker, async) — แลกกับเสถียร/perf ระยะยาว; คุมด้วย workspace + CI + conformance test.
2. **HTTP/2 + WebSocket edge cases** [4] — conformance test ชุดใหญ่.
3. **Active Scanner accuracy** — ยากสุดเชิง "เก่งกว่า"; เริ่มจากเช็คมีหลักฐานชัด.
4. **OAST/Collaborator** — ต้อง public infra; service แยก optional.
5. **Web ใน Rust/WASM (Leptos/Dioxus)** ecosystem UI ยังใหม่กว่า React — มี fallback TS.
6. **AI cost/latency** — opt-in + cache.

---

## 16. Architecture Decision Records (ADR log)

| # | การตัดสินใจ | ทางเลือกที่ทิ้ง | เหตุผล |
|---|---|---|---|
| 001 | ภาษา = **Rust ทั้งระบบ** | Go, Python(mitmproxy) | perf/RAM/เสถียร, static binary, แชร์ core ทุก frontend [1][2] |
| 002 | Engine = **hudsucker/hyper** | ex-mitmproxy, custom | streaming, HTTP2/WS, cert on-the-fly, รู้กับดักแล้ว [2][4] |
| 003 | Storage = **SQLite WAL + writer actor** | Postgres-first, sled | zero-config local, batch กัน single-writer; Postgres เป็น adapter [11][12] |
| 004 | Desktop = **Tauri** | Electron | 8–10MB, RAM ~30–50MB, backend Rust ตรงกับ core [5] |
| 005 | TUI = **ratatui** | cursive, tui-rs | de-facto, sub-ms, ecosystem แข็ง [6] |
| 006 | MCP = **stdio + Streamable HTTP (rmcp)** | HTTP+SSE เดิม | ตามสเปกล่าสุด, SSE ถูก deprecate [9][10] |
| 007 | Plugins = **WASM Component Model (wasmtime)** | dylib, embedded Lua/JS | sandbox untrusted code, ABI ผ่าน WIT [13] |
| 008 | Concurrency = **tokio + rayon + semaphore** | tokio-only, thread-per-conn | แยก I/O จาก CPU-bound, backpressure [8] |
| 009 | API model = **local-first daemon + client SDK** | embed-only, cloud-only | ได้ทั้ง single-binary และ remote/team โดยโค้ดเดียว |
| 010 | Migrations = **versioned, embedded, forward-only** (sqlx/refinery) ตั้งแต่ Phase 0 | ปล่อยฟรีฟอร์ม, แก้ทีหลัง | project เก่าต้องเปิดกับ binary ใหม่ได้; schema เปลี่ยนแพงถ้าไม่วางแต่แรก [27] (§30) |
| 011 | CA = **unique per-install, ไม่ share, leaf cache ต่อ host** | ship CA กลาง (แบบเก่า/อันตราย) | กัน CA รั่วใช้ดักคนอื่น; UX install ต้องดีสุด [23] (§28) |
| 012 | Config = **TOML + XDG + precedence CLI>env>project>user>default**, secrets เข้า OS keychain | JSON/YAML, เก็บ secret ใน plaintext | มาตรฐาน, comment ได้, secret ไม่หลุดลง repo [26] (§29) |
| 013 | Connectivity = **upstream proxy chain + custom DNS/host map + client-cert** เป็น core | เพิ่มทีหลัง | tester ต้องใช้จริงตั้งแต่วันแรก (Tor/corporate/mTLS) (§27) |
| 014 | Session = **session-handling rules + macro engine** ไม่ใช่แค่ static auth | hardcode cookie | scanner ไร้ค่าถ้า re-login ไม่ได้; ยกจาก Phase 5 ขึ้นมา (§31) |
| 015 | Scanner = **check registry + insertion-point engine + OAST**, นำเข้า **Nuclei templates** ได้ | เขียน check ตายตัว | ได้ community coverage ฟรีมหาศาลจาก Nuclei [20] (§32) |
| 016 | Report = **template engine → MD/HTML/PDF/DOCX + SARIF/DefectDojo/Jira** | export ดิบอย่างเดียว | ต่อ CI/CD และส่งลูกค้าได้จริง [21] (§35) |
| 017 | i18n = **Project Fluent (fluent-rs)**, TH เป็น first-class | gettext/hardcode | plural/gender/bidi ครบ, แชร์ string ทุก frontend [22] (§39) |
| 018 | Team mode = **CRDT (Automerge) สำหรับ annotation/finding** + Postgres สำหรับ flow | lock-based only | แก้ offline/พร้อมกันไม่ชน, merge อัตโนมัติ [25] (§36) |
| 019 | Privacy = **zero telemetry, opt-in crash report แบบ local-first** | analytics เงียบ ๆ | เครื่องมือถือ creds ของคนอื่น = trust สำคัญสุด (§41) |
| 020 | Branding = **ตรวจชื่อก่อนลงทุน** (BOGBOGPROX ชนของเดิม) | ลุยชื่อเดิม | เลี่ยง trademark/SEO collision (§45) |

> ADR เต็ม (context/consequences) เก็บเป็นไฟล์ `docs/adr/NNN-*.md`.

---

## 17. Threat Model (STRIDE) — ตัวเครื่องมือเองคือของอันตราย
proxy เก็บ credential/session/PII และถอด TLS ได้ ⇒ ต้อง harden ตัวเอง [16][19].

| ภัย (STRIDE) | สถานการณ์ | มาตรการ |
|---|---|---|
| **S**poofing | client ปลอมต่อ daemon | token auth + TLS สำหรับ remote; local ผูก UDS สิทธิ์ผู้ใช้ |
| **T**ampering | แก้ project/CA บนดิสก์ | CA key 0600, project ลงลายเซ็น/hash, WAL integrity |
| **R**epudiation | ใครยิง active scan | audit log ทุก action ของ MCP/agent + timestamp |
| **I**nfo disclosure | history หลุด (มี creds) | project encryption-at-rest (optional), redaction rules, secret-scrub ตอน export |
| **D**oS | agent ยิง intruder ถล่มตัวเอง/เป้าหมาย | semaphore + global rate-limit + scope guard |
| **E**oP | plugin/agent ทำเกินสิทธิ์ | WASM sandbox (deny-by-default caps) [13]; MCP read-only mode; scope allowlist |

**Scope enforcement เป็นกฎเหล็ก:** ทุก active tool (intruder/scanner/agent) ต้องอยู่ใน scope ที่ประกาศ — นอก scope = block + เตือน. ป้องกันยิงผิดเป้า (ทั้งเชิงเทคนิคและจริยธรรม/กฎหมาย).

---

## 18. Testing, Fuzzing & QA
- **Unit + property tests** (`proptest`) — HTTPQL parser, request builder, codec (round-trip encode/decode).
- **Fuzzing** (`cargo-fuzz`/libFuzzer [17]) — HTTP parsing, HTTPQL, WebSocket frame, cert gen — จุดที่รับ input ไม่น่าเชื่อถือ.
- **Engine conformance suite** — ชุดเดียวที่ทุก `ProxyEngine` impl ต้องผ่าน (HTTP/1.1, HTTP/2, WS, chunked, SSE, gzip/br, redirect, cert edge cases) → ทำให้สลับ engine ปลอดภัย.
- **E2E** — ยิง lab จริง (เช่น aegis-ctf IDOR, DVWA, Juice Shop, bWAPP) ผ่าน CI; ตรวจว่า agent หา IDOR ได้เอง.
- **Perf regression** — benchmark ในCI (§25), fail ถ้า p99 latency ถอยหลัง.
- **Coverage** gate + `clippy -D warnings` + `cargo deny` (audit license/CVE ของ dep).

---

## 19. Observability (self-diagnostics)
- **`tracing`** เป็น instrumentation หลัก + **OpenTelemetry** export (Jaeger/Prometheus) [15].
- Metrics: req/s, added-latency p50/p99, flow store size, writer-queue depth, rayon pool saturation, MCP calls, memory.
- แท็บ **"Diagnostics"** ในทุก frontend: สถานะ engine/storage/MCP, live throughput sparkline, error log — ผู้ใช้เห็นสุขภาพระบบเอง (แบบ btop).
- Crash resilience: supervised tasks (restart engine/writer โดยไม่ล้มทั้ง daemon), panic = log+recover, WAL = งานไม่หาย.

---

## 20. Data Model (SQLite DDL — concrete)
```sql
CREATE TABLE flows (
  id INTEGER PRIMARY KEY, project_id INTEGER, ts INTEGER,
  scheme TEXT, method TEXT, host TEXT, port INTEGER, path TEXT, query TEXT, http_version TEXT,
  req_headers_json TEXT, req_body_blob TEXT,        -- blob = hash → blob store
  status INTEGER, resp_headers_json TEXT, resp_body_blob TEXT,
  duration_ms INTEGER, resp_size INTEGER, mime TEXT,
  color TEXT, comment TEXT, tags_json TEXT, source TEXT   -- proxy|repeater|intruder|scanner
);
CREATE VIRTUAL TABLE flows_fts USING fts5(url, req_body, resp_body, content='');  -- HTTPQL full-text
CREATE TABLE projects  (id INTEGER PRIMARY KEY, name TEXT, created INTEGER, scope_json TEXT, settings_json TEXT);
CREATE TABLE repeater_tabs (id INTEGER PRIMARY KEY, name TEXT, request_blob TEXT, last_response_blob TEXT, env_json TEXT);
CREATE TABLE intruder_attacks (id INTEGER PRIMARY KEY, base_blob TEXT, config_json TEXT, status TEXT, created INTEGER);
CREATE TABLE intruder_results (id INTEGER PRIMARY KEY, attack_id INTEGER, payloads_json TEXT,
                               status INTEGER, resp_len INTEGER, time_ms INTEGER, grep_json TEXT, resp_blob TEXT);
CREATE TABLE issues   (id INTEGER PRIMARY KEY, flow_id INTEGER, severity TEXT, confidence TEXT,
                       type TEXT, detail_md TEXT, created INTEGER);   -- scanner/findings
CREATE TABLE rules    (id INTEGER PRIMARY KEY, kind TEXT, enabled INTEGER, match_json TEXT, action_json TEXT, ord INTEGER);
CREATE TABLE findings (id INTEGER PRIMARY KEY, title TEXT, severity TEXT, cwe TEXT, notes_md TEXT,
                       flow_ids_json TEXT, status TEXT);              -- report tracker (§26)
-- indices: flows(host,path,status,ts); blob store = ไฟล์ content-addressed แยกนอก DB
```

---

## 21. Plugin SDK (WASM Component Model, sandboxed [13])
- Plugin = **WASM component** โหลดใน **wasmtime**, คุยกับ host ผ่าน interface ที่ประกาศด้วย **WIT** (bindgen สร้าง binding), export/import เฉพาะ function — sandbox แข็งกว่า dylib [13].
- **Capability-based (deny-by-default):** plugin ขอสิทธิ์ระบุ (อ่าน flow, แก้ req, ยิง http, เขียน note) — host อนุมัติทีละอัน. ไม่มีสิทธิ์แตะ filesystem/network นอกที่ให้.
- Hooks: `on_request`, `on_response`, `on_flow`, `passive_check(flow)->issues[]`, `active_check(target)`.
- ภาษาเขียน plugin: Rust/Go/JS/Python ที่ compile เป็น WASM component ได้ → community เขียนได้หลากหลาย (คล้าย BApp แต่ปลอดภัยกว่า + ข้ามภาษา).
- **สอง path เสริมกัน:** WASM plugin (แพ็กเกจแจก) + MCP (AI/automation แบบสด).

---

## 22. AI Layer (provider-agnostic, มี guardrail)
- **Provider-agnostic:** interface เดียว (`AiProvider` trait) เสียบ Anthropic/OpenAI/Google/local(Ollama) — ผู้ใช้เลือกเอง (แบบ Caido plugins [1]).
- **สองทางเข้า:** (ก) ปุ่มใน UI (Analyze/Find-IDOR/Suggest) เรียก provider; (ข) MCP ให้ external agent (Claude ฯลฯ) ขับทั้งเครื่องมือ.
- **Agent mode:** ตั้ง goal ("หา IDOR ใน scope นี้") → agent ใช้ MCP tools วนเอง, ทุก active action ผ่าน scope+rate guard + audit (§17).
- **Guardrails:** read-only default, active tool ต้อง confirm/opt-in, **cost cap** (token/$ ต่อ session), **cache** ผลวิเคราะห์ต่อ flow-hash กันจ่ายซ้ำ, ไม่ส่ง body ที่ติด redaction rule ออกไป provider.
- **Prompt contracts:** โครง input/output เป็น JSON schema ต่อ tool → ผลนำไปใช้อัตโนมัติได้ (สร้าง finding, ยิง payload ที่แนะ).

---

## 23. UX & Keybindings (ให้ 3 frontend รู้สึกเป็นตัวเดียว)
- **Command palette** (`Ctrl/⌘-K`) ทุก frontend — ค้นคำสั่ง/flow/tab.
- **Vim-like keys** ใน TUI + Web editor (`j/k`, `/`=filter, `gg/G`, `dd`), ปรับได้.
- **Send-to** เร็ว: `r`=Repeater, `i`=Intruder, `c`=Comparer, `n`=note/finding.
- ธีม dark/light, **i18n รวมภาษาไทย**, hex/raw/render/JSON views, inline diff.
- Layout จำได้ต่อ project; ทุกอย่าง scope-aware (เน้น flow ใน scope).

---

## 24. Distribution & Packaging
- **`cargo-dist` [14]** — สร้าง installer + binary ข้ามแพลตฟอร์ม (Linux/macOS/Windows), gen CI ให้เอง, cross-compile ผ่าน zigbuild/xwin.
- ช่องทาง: GitHub Releases (signed), Homebrew tap, AUR, `.deb`/`.rpm`, Docker image (`bogbogproxd` headless), `cargo install`.
- **Auto-update** ใน Desktop (Tauri updater). **Reproducible builds** + SBOM (`cargo auditable`).
- One-liner: `curl -sSf https://.../install.sh | sh` (จาก cargo-dist).

---

## 25. Benchmark Plan (พิสูจน์ "เบาแต่เก่ง")
- **โหลด:** `oha`/`wrk` ยิงผ่าน proxy → วัด throughput + added-latency p50/p99 เทียบ **baseline ไม่มี proxy**.
- **เทียบคู่แข่ง:** BogBogProx vs Burp vs Caido vs ZAP บน workload เดียวกัน (idle RAM, RAM ที่ 100k flows, startup time, added-latency, intruder 10k req เวลาเสร็จ).
- **เมตริกเป้า:** startup < 0.5s, idle RAM < 60MB, added-latency p99 < 5ms, 100k flows RAM คงที่ (body แยก blob).
- รันใน CI เป็น perf-regression gate (§18); เผยแพร่ผลใน README (โปร่งใส).

---

## 26. Power-user Features (เหมือนใช้เอง — delighters)
สิ่งที่ผมอยากได้จริงเวลาทำงาน (นอกเหนือ parity):
- **Findings/Report tracker** — มาร์ก flow เป็น finding (severity/CWE/notes) → gen report **Markdown/HTML/PDF** อัตโนมัติ (ต่อยอดสไตล์ writeup ที่เราทำ).
- **Import/Export** — Burp project/HAR/**OpenAPI/Swagger**/Postman → seed sitemap+repeater; export HAR/CSV.
- **Auth/Env profiles** — เก็บ token/cookie/header ชุด ๆ (แบบ Postman env), สลับ profile ต่อ request; auto-refresh JWT/OAuth.
- **Payload library ในตัว** — รวม **SecLists** [18] + wordlist ของเรา, ค้น/แทรกเข้า Intruder ได้ทันที.
- **Match/Replace + Auto-mods** — เช่น strip CSP, unhide, auto-add header, downgrade — เปิด/ปิดเป็นชุด.
- **WebSocket & gRPC & GraphQL** viewers — introspection GraphQL, decode gRPC.
- **Diff & timeline** — เทียบ 2 response, ไทม์ไลน์ session, ย้อนดู flow เดิม.
- **ผูก Stealth-Browser MCP** (ที่เรามีอยู่) — "replay ผ่าน browser จริง" ทะลุ anti-bot; และส่ง traffic จาก browser เข้า BogBogProx.
- **ต่อ pentest-dashboard** — สตรีม flow/finding ขึ้น dashboard live (โปรเจกต์เดิมของคุณ).
- **Interceptor rules อัจฉริยะ** — auto-forward assets, hold เฉพาะ in-scope + content-type ที่สนใจ (ลด noise).
- **Session recording → GIF/report** (แนวเดียวกับที่เราทำ writeup).

---

## 27. Connectivity & Network Topology (ต่อได้ทุกสภาพหน้างาน)

Burp เก่งเพราะต่อได้ทุกที่ — BogBogProx ต้องไม่แพ้. ทั้งหมดอยู่ที่ `bogbogprox-engine` + config (§29).

### 27.1 Proxy modes
| โหมด | ใช้เมื่อ | หมายเหตุ |
|---|---|---|
| **Explicit** (HTTP CONNECT) | ตั้ง proxy ใน browser/แอป | ค่าเริ่ม, รองรับ HTTP/1.1+2 |
| **SOCKS5** listener | เครื่องมือที่พูด SOCKS | เสริม explicit |
| **Transparent** (iptables/pf redirect) | อุปกรณ์ตั้ง proxy ไม่ได้ (IoT/มือถือบางแอป) | ต้องอ่าน SNI/Host หา target |
| **Reverse** (bind host → target) | ทดสอบ API เฉพาะ, share endpoint | ใช้ทำ interception ฝั่ง server |
| **Invisible/implicit** | client ไม่ส่ง absolute-URI | map ตาม Host/SNI |

### 27.2 Upstream / chaining (จุดที่ tester ต้องใช้)
- **Upstream proxy**: ต่อออกผ่าน HTTP/HTTPS/**SOCKS5** upstream — ใช้ทะลุ corporate proxy, ยิงผ่าน **Tor**, หรือ chain **BogBogProx → Burp/ZAP**.
- **Rules ต่อ host**: `*.internal → SOCKS 127.0.0.1:9050`, ที่เหลือ direct.
- **Auth ที่ upstream**: basic/digest/NTLM/kerberos passthrough.

### 27.3 Name resolution & routing
- **Custom host mapping** (`/etc/hosts` style ในแอป): `app.target.com → 10.0.0.5` โดยไม่แตะไฟล์ระบบ — จำเป็นตอนทดสอบ staging/vhost.
- **SNI override / spoof**, **DNS over HTTPS/TCP**, บังคับ **IPv4/IPv6**, custom resolver.
- **Connection matching**: virtual-host testing, absolute vs. relative target.

### 27.4 TLS ฝั่ง target (upstream TLS)
- Toggle **ยอมรับ cert เสีย/หมดอายุ/self-signed** ของ target (ค่าเริ่ม = ยอม เพราะเราคือ pentest tool) — แต่ **log ชัด**.
- **Client certificate / mTLS**: โหลด PKCS#12/PEM ต่อ host เพื่อทดสอบแอปที่บังคับ client cert.
- เลือก **TLS version/cipher/ALPN** ที่ยิงออก (ทดสอบ downgrade), ปิด/เปิด SNI, custom CA bundle ฝั่ง target.

### 27.5 Non-HTTP & tuning
- **TCP/TLS pass-through** สำหรับ traffic ที่ไม่ใช่ HTTP (log ว่ามี, ไม่ decode) เพื่อไม่พังการเชื่อมต่อ.
- **Connection pool / keep-alive / HTTP2 multiplexing** ปรับได้; **timeout/retry/backoff** ต่อ scope; `TCP_NODELAY` (§6).

---

## 28. CA / TLS Trust & First-Run Onboarding (จุดเจ็บอันดับ 1 ของทุก proxy)

> เป้าหมาย: จาก "ลงเสร็จ" ถึง "เห็น HTTPS flow แรก" **< 2 นาที**.

### 28.1 CA lifecycle
- **Unique CA ต่อ install** (สร้างตอน first-run ด้วย `rcgen`) — **ไม่ ship CA กลาง** (กันคนเอา CA เราไปดักคนอื่น) [ADR 011].
- Key **0600**, เลือก **ECDSA P-256** (เร็ว) หรือ RSA-2048; อายุยาว, name ระบุ machine.
- **Leaf cert on-the-fly** ต่อ host, **cache** (mem+disk) กัน gen ซ้ำ = latency ต่ำ; copy SAN/CN/wildcard จาก cert จริงของ target.
- คำสั่ง **regenerate / rotate / revoke** + export public cert หลายรูปแบบ (PEM/DER/`.crt`).

### 28.2 Install flows (ครบทุกปลายทาง)
| ปลายทาง | วิธี |
|---|---|
| **หน้า self-serve** | เปิด `http://bogbogprox.setup/` (หรือ `cert.bogbogprox`) ขณะต่อ proxy → ปุ่มดาวน์โหลด + คู่มือ per-OS |
| **Browser** | Firefox (own store) / Chrome-Edge (OS store) — คำสั่ง+รูปทีละขั้น |
| **OS trust store** | script: `certutil`(Win), `security add-trusted-cert`(mac), `update-ca-certificates`(Linux) |
| **มือถือ** | **QR code** ชี้ไป cert endpoint; คู่มือ iOS (Install Profile + *Trust* ใน About) & Android (user vs. system CA + APK ที่ pin) |
| **ตรวจสถานะ** | หน้า diag บอก "CA trusted ✔ / proxy set ✔" ทันที |

### 28.3 First-run wizard
1. สร้าง CA + โชว์ install (พร้อม copy คำสั่ง/QR).
2. ตั้ง proxy ให้ (ปุ่ม "set system proxy" / แนะ FoxyProxy / launch browser ที่ชี้ proxy เอง).
3. สร้าง/เปิด project แรก + ตั้ง **scope** (§17 กฎเหล็ก).
4. ยิง request ทดสอบ → เห็น flow แรก = สำเร็จ.

---

## 29. Configuration Management

- **Format**: **TOML** (comment ได้), โครง `bogbogprox.toml`.
- **ที่อยู่ (XDG)**: user `~/.config/bogbogprox/`, project `<project>/bogbogprox.toml`, state `~/.local/state/bogbogprox/`, cache `~/.cache/bogbogprox/`.
- **Precedence** [ADR 012]: **CLI flag > env (`BOGBOGPROX_*`) > project config > user config > built-in default**.
- **Secrets** (upstream creds, AI API keys, client-cert passphrase): เข้า **OS keychain** (`keyring-rs` [26]) — *ไม่* เก็บ plaintext ลง config/repo; config อ้าง reference เท่านั้น.
- **Hot-reload** ค่าที่ปลอดภัย (rules/scope/theme) โดยไม่ restart; ค่าเชิงโครง (bind/engine) ต้อง restart แจ้งชัด.
- **Env/profile** สลับได้ (dev/lab/client-A) — คู่กับ Auth profiles (§31).

---

## 30. Schema Migrations & Data Lifecycle (กันของพังตอนอัปเกรด)

### 30.1 Migrations
- **Versioned, embedded, forward-only** ตั้งแต่ Phase 0 [ADR 010] — `schema_version` ในตาราง meta, migration ฝังใน binary (`sqlx migrate`/`refinery` [27]).
- เปิด project เก่า → ตรวจ version → รัน migration ในทรานแซกชัน + **backup อัตโนมัติก่อน migrate**; migration ล้ม = rollback + แจ้ง.
- **Project-format version** แยกต่างหาก (สำหรับ export/import ข้ามเวอร์ชัน) + compat matrix.

### 30.2 Data lifecycle
- **Retention/auto-prune**: cap ต่อ project (จำนวน flow / ขนาด GB / อายุ) — เก่าเกินก็ archive/drop ตามตั้ง (กัน DB บวมจาก proxy noise).
- **Blob GC**: content-addressed blob (§7) ที่ไม่มี flow อ้าง = เก็บกวาด (refcount/mark-sweep).
- **Backup/restore**: snapshot project (DB+blob) เป็นไฟล์เดียว; export/import ข้ามเครื่อง.
- **Encryption at rest** (opt-in): project เข้ารหัสด้วย key จาก keychain/passphrase (เพราะ history มี creds — §17 Info-disclosure). **Secret-scrub** ตอน export.
- **Integrity**: WAL checkpoint, `PRAGMA integrity_check` เป็นระยะ, ตรวจ blob hash.

---

## 31. Authentication, Sessions & Macros (หัวใจ authenticated testing)

ยกจากเชิงอรรถ Phase 5 → ฟีเจอร์แกน [ADR 014] เพราะ **scanner ไร้ค่าถ้า login ค้างไม่ได้**.

### 31.1 Auth profiles
- เก็บชุด **cookie/bearer/API-key/basic/mTLS** ต่อ target; สลับต่อ request/tab (แบบ Postman env).
- **Auto-refresh** JWT/OAuth2 (client-creds/refresh-token/device flow) ก่อนหมดอายุ; รู้จัก `exp` ใน JWT.

### 31.2 Session-handling rules (แบบ Burp แต่คมกว่า)
- **ตรวจ logged-out** ด้วย rule (status 401/302→login, body มี "sign in", header หาย) → **รัน macro re-auth อัตโนมัติ** แล้ว retry request เดิม.
- ใช้ได้ทั้งกับ Repeater/Intruder/Scanner/AI-agent → ทุกเครื่องมือ "อยู่ในเซสชัน" เสมอ.

### 31.3 Macro engine
- **บันทึก sequence** (login → เก็บ token/CSRF → ใช้ต่อ) จาก flow ที่จับมาได้.
- **Extract → re-inject**: ดึงค่าจาก response (regex/JSONPath/header/cookie) ไปเสียบ request ถัดไป (CSRF token, anti-forgery, nonce).
- **Login recorder ผ่าน browser จริง** — ผูก **Stealth-Browser MCP** (§26) เพื่ออัดขั้น login ที่มี JS/2FA/anti-bot แล้ว replay.
- **CSRF/nonce auto-handling** เป็น rule สำเร็จรูป.

---

## 32. Scanner Architecture (เชิงลึก — ที่ Burp ได้เปรียบ เราต้องปิดช่อง)

### 32.1 Crawl / spider
- **Passive discovery** จาก proxy traffic (ไม่ยิงเพิ่ม) + **active crawl** เลือกได้.
- **JS-rendered crawl**: ขับ headless/real browser ผ่าน **Stealth-Browser MCP** → เก็บ SPA/route ที่ static crawler ไม่เห็น, ทะลุ anti-bot.
- Seed จาก **OpenAPI/Swagger/Postman/GraphQL schema** (§34) → ไม่ต้องเดา endpoint.

### 32.2 Insertion-point engine
- ตรวจจุดฉีดอัตโนมัติ: query/body param, JSON/XML/multipart field, header, cookie, path segment, GraphQL var — ผู้ใช้ปรับ/เพิ่มได้.

### 32.3 Check registry (passive + active)
- **Registry แบบปลั๊ก** map กับ **OWASP WSTG** [16]: passive (secret/PII/CSP/cookie flags/verbose error/CORS) + active (SQLi/XSS/SSRF/IDOR/LFI/SSTI/XXE/open-redirect/cmd-inj/deserialization).
- **นำเข้า Nuclei templates** [20] [ADR 015] → ได้ community coverage มหาศาลฟรี (ตัวต่างสำคัญจาก Burp).
- **AI-assisted checks** (§22): find-IDOR/suggest-payloads เป็น check ชนิดหนึ่ง.

### 32.4 OAST / out-of-band
- Client OAST (แนว interactsh [24]) จับ blind SSRF/XXE/RCE ที่ callback ออกนอก — payload มี domain ของ collaborator, poll ผล.
- Phase 5 (§14) เพราะต้อง public infra; interface เผื่อ self-host ไว้.

### 32.5 คุณภาพผล
- **Insertion-point + confidence + severity/CVSS + CWE** ต่อ issue.
- **Deduplication** (group by type+location+signature), **false-positive suppression list**, **retest** ซ้ำได้.
- **Scan profiles**: passive-only / light-active / thorough; scope-bound เข้ม (§17).

---

## 33. Content Inspectors, Codecs & Editors (ทำงานกับ payload ให้ลื่น)

- **Inspector panel** (แบบ Burp Inspector): แตก request/response เป็น params, cookies, headers, **JWT decode**, base64/url auto-decode — แก้แล้วประกอบกลับ.
- **Nested/Hackvertor-style codec**: encode/decode ซ้อนชั้น (url→base64→gzip→hex...), tag `<@base64>...<@/base64>` แทรกใน payload; ทำ **HMAC/JWT sign** ในตัว.
- **Viewers**: raw / hex / pretty (JSON/XML/HTML/JS beautify) / render / **image** / **Protobuf** decode.
- **Editors**: syntax highlight, search/replace, resend; **auto-decompress** (gzip/br/zstd/deflate) โปร่งใส.
- **Modern payloads**: JSON, XML, MessagePack, Protobuf, multipart, form-urlencoded, **GraphQL** (introspection + var editor), **gRPC** decode.

---

## 34. Import / Export / Interop

| ทิศ | ฟอร์แมต |
|---|---|
| **Import** | Burp project/items · **HAR** · **OpenAPI/Swagger** · Postman · WSDL · **GraphQL schema** · Nuclei templates [20] · raw request files · SecLists/wordlist [18] |
| **Export flows** | HAR · CSV · raw · project snapshot (§30) |
| **Export findings** | Markdown · HTML · **PDF** · DOCX · **SARIF** [21] · DefectDojo · Jira · CSV |
| **Seed** | OpenAPI/Postman → เติม sitemap + repeater tabs อัตโนมัติ |

- **CI/CD**: `bogbogproxd` headless รับ OpenAPI → scan → ออก **SARIF + exit code** ให้ pipeline fail; เทียบ baseline กัน regression.

---

## 35. Reporting Engine [ADR 016]

- **Template-based** (Tera/handlebars-style) → **Markdown / HTML / PDF / DOCX**; ธีม/โลโก้/หัวรายงานปรับได้ (ต่อยอด writeup HTML ที่เราทำ).
- ต่อ finding: **severity + CVSS v3.1/4.0 + CWE + remediation + evidence** (request/response, diff, **screenshot/GIF** จาก session recording §26).
- **Machine formats**: SARIF [21] (ขึ้น GitHub code-scanning), DefectDojo/Jira push.
- **Executive summary + technical detail** สองระดับ; i18n รายงาน (TH/EN §39).

---

## 36. Collaboration & Team Mode (เฟส 5, ออกแบบเผื่อตั้งแต่ต้น)

- **Storage**: flow/blob บน **Postgres** (§7); **annotation/finding/comment** เป็น **CRDT (Automerge [25])** → หลายคนแก้พร้อมกัน/ออฟไลน์ได้ merge อัตโนมัติ ไม่ชน [ADR 018].
- **RBAC**: owner/editor/viewer; scope + active-tool permission ต่อ user (§17).
- **Realtime presence** (ใครดู flow ไหน), comment/mention, live cursor (web).
- **Audit trail ต่อ user** (ใครยิง active scan/แก้ rule — §17 Repudiation).
- **Conflict/merge** policy ชัดเจน; sync ผ่าน WS event (§9).

---

## 37. Extensibility & Ecosystem (นอกเหนือ Plugin SDK §21)

- **Plugin registry/marketplace**: index กลาง, ติดตั้ง/อัปเดต/verify signature ของ WASM plugin.
- **Inline scripting**: snippet สั้น (JS/Rhai/Python-via-WASM) สำหรับ transform request/response แบบ Caido convert-workflow — เร็วกว่าเขียน plugin เต็ม.
- **Custom HTTPQL functions** + saved queries/filter library แชร์ในทีม.
- **Workflows** (node-graph, §11 เฟส 5): trigger→condition→action (auto-tag, auto-scan in-scope, ยิง webhook).
- **Outbound webhooks/events**: on issue.new/intruder.done → Slack/Discord/HTTP (§38).
- **CLI-first**: ทุกอย่างสั่งผ่าน CLI + REST + MCP → scriptable/automatable ทั้งหมด.

---

## 38. Notifications & Integrations

- **In-app + desktop notification** (Tauri): issue ใหม่ (≥ severity ที่ตั้ง), intruder/scan เสร็จ, session re-auth ล้ม, error engine.
- **Outbound**: Slack/Discord/Teams/generic webhook; digest หรือ realtime.
- **Ticketing**: push finding → Jira/DefectDojo/GitHub Issues (§34/§35).
- ปรับ **threshold/quiet-hours/per-project** กัน noise.

---

## 39. Internationalization & Accessibility

- **i18n = Project Fluent (`fluent-rs`)** [22] [ADR 017]: plural/gender/bidi ครบ, **ไทยเป็น first-class**, string bundle แชร์ทั้ง 3 frontend; รายงานก็ i18n.
- **a11y**: web ตาม WCAG (aria, keyboard-only, high-contrast, focus ชัด); TUI = keyboard-driven อยู่แล้ว + ปรับสี/รองรับ NO_COLOR; desktop ตาม native.
- หน่วย/เวลา/timezone ตาม locale; RTL เผื่อไว้.

---

## 40. Supply-Chain & Release Security (โซ่อุปทานของตัวเครื่องมือ)

- **`cargo deny`** (license/CVE/ban dup), **`cargo audit`** ใน CI; dependency **pinned + `Cargo.lock` commit**.
- **SBOM** (`cargo auditable`/CycloneDX) แนบทุก release; **reproducible builds**.
- **Signed releases** (sigstore/cosign หรือ minisign) + checksums; verify ตอน auto-update (Tauri updater §24).
- **Secrets ในหน่วยความจำ**: `zeroize` ตอน drop (CA key/token/passphrase); กัน core-dump รั่ว.
- **Security disclosure policy** (`SECURITY.md`) + `security.txt`; ตอบ CVE ของตัวเอง.

---

## 41. Privacy & Telemetry Stance (ประกาศให้ชัด) [ADR 019]

- **Zero telemetry by default** — ไม่มี phone-home, ไม่มี analytics เงียบ ๆ. เครื่องมือถือ credential/session/PII ของเป้าหมาย = **trust คือทุกอย่าง**.
- **Crash report = opt-in + local-first**: เขียนไฟล์ในเครื่องก่อน, ส่งเมื่อผู้ใช้กดเท่านั้น, **scrub secret/PII** ก่อนส่ง.
- **AI provider egress โปร่งใส**: แสดงชัดว่าอะไรถูกส่งออกไป provider, redaction rule กันส่ง body ที่ห้าม (§22), มี **offline/local model (Ollama)** เป็นทางเลือกไม่ให้ข้อมูลออกเครื่อง.
- **Update check** = ping version endpoint แบบ minimal, ปิดได้.

---

## 42. Legal / Ethical Guardrails

- **Authorization gate**: ครั้งแรกของ active tool/agent แสดงคำเตือน "ทดสอบเฉพาะระบบที่ได้รับอนุญาต" + บันทึกการรับทราบ.
- **Scope = กฎเหล็ก** (§17): active action นอก scope = **block + เตือน** — ทั้งเชิงเทคนิคและกฎหมาย/จริยธรรม.
- **Rate/impact guard**: จำกัดอัตรากันถล่มเป้าหมาย (semaphore + per-host limit §27).
- **Audit ทุก active action** (§36) เพื่อ accountability.
- เอกสาร responsible-use + license ที่ไม่การันตี fitness (Apache-2.0).

---

## 43. Deployment Topologies

| โหมด | รูปแบบ | ใช้เมื่อ |
|---|---|---|
| **Single-binary** | TUI/Desktop ฝัง `bogbogprox-core` (ไม่มี daemon แยก, §3) | เครื่องเดียว, เบาสุด |
| **Daemon + clients** | `bogbogproxd` + TUI/Web/Desktop ต่อผ่าน `bogbogprox-client` | รัน daemon บนเซิร์ฟเวอร์/VPS, คุมจากไกล (แบบ Caido) |
| **Headless / CI** | `bogbogproxd` no-UI + REST/MCP + SARIF out (§34) | pipeline, scheduled scan |
| **Docker / K8s** | image `bogbogproxd` headless, volume = project/blob | lab, team infra |
| **Team server** | `bogbogproxd` + **Postgres** + RBAC/CRDT (§36) | หลายคน, shared engagement |

- **Config เดียว หลาย topology** (§29); ย้าย SQLite→Postgres โดยไม่แตะ UI (§7, §14).

---

## 44. Project Governance & Licensing

- **License**: **Apache-2.0** (permissive, มี patent grant). พิจารณา **open-core**: core ฟรีทั้งหมด, ส่วน team/cloud-hosted เป็น optional เชิงพาณิชย์ภายหลัง (ตัดสินตอน Phase 5).
- **Contribution**: `CONTRIBUTING.md`, **RFC/ADR process** (§16) สำหรับการเปลี่ยนสถาปัตยกรรม, DCO/CLA.
- **Quality gate**: `clippy -D warnings`, fmt, test, `cargo deny`, perf-regression (§18/§25) เป็น CI บังคับ.
- **Versioning**: SemVer; project-format + schema version แยก (§30); changelog + migration note ทุก release.
- **Community**: issue templates, roadmap สาธารณะ, security disclosure (§40).

---

## 45. Naming / Branding note (ก่อนลงทุนกับชื่อ) [ADR 020]

- **"BOGBOGPROX" ชนของเดิม**: (ก) *BOGBOGPROX* = Linux **audit/log agent** (InterSect Alliance) และ (ข) *BOGBOGPROX* = **web application honeypot** (MushMush/Glastopf lineage) — ทั้งคู่อยู่สาย security ⇒ เสี่ยง **trademark + SEO + สับสน**.
- **ก่อนลงทุนโลโก้/โดเมน/แพ็กเกจ**: เช็ก crates.io/npm/GitHub org/โดเมน (`.io`/`.dev`) + trademark เบื้องต้น.
- ทางเลือก: คงชื่อแต่ทำ wordmark เฉพาะ (`BogBogProx Proxy`/`bogbogprox-sec`), หรือ shortlist ชื่อสำรอง. **ตัดสินก่อน Phase 1** (ก่อนมี public artifact).

---

## 46. What Makes BogBogProx Win (North-Star — ทำไมถึงชนะ ไม่ใช่แค่ตาม)

parity อย่างเดียวไม่พอ. สิ่งที่ Burp **เป็นไม่ได้** เพราะ legacy/ปิดโค้ด/Java คือสนามที่เราชนะ:

| แกนชนะ | BogBogProx | Burp (ข้อจำกัดเชิงโครง) |
|---|---|---|
| **AI-native ตั้งแต่แกน** | MCP เปิด "ทั้งเครื่องมือ" ให้ agent ขับเอง (§10, §47) | AI เป็น add-on, ปิด, จำกัด |
| **Perf/RAM** | Rust/hyper, RAM คงที่ล้าน flow, startup < 0.5s (§12) | JVM, RAM หนัก, สตาร์ตช้า |
| **Tri-frontend แกนเดียว** | TUI+Web+Desktop+remote (§5) | Desktop Java เท่านั้น |
| **เปิด + ต่อยอดได้** | Apache-2.0, WASM plugin ข้ามภาษา, **นำเข้า Nuclei** (§21, §32) | ปิด, BApp Java, Pro เสียเงิน |
| **Query & automation** | HTTPQL + CLI + REST + MCP = scriptable ทั้งหมด (§8) | UI-centric, automation จำกัด |
| **โปร่งใส/trust** | zero-telemetry, local model ได้ (§41) | โฆษณา/telemetry, cloud AI |

> **ประโยคเดียว:** *"Burp ความเร็ว Rust + สมอง AI + เปิดให้ทุกคนต่อยอด — เบากว่า เร็วกว่า ฉลาดกว่า และเป็นของทุกคน."*

---

## 47. Autonomous AI Pentester (ความฝันตัวจริง — เกินกว่าปุ่ม "Analyze")

เป้าหมายสูงสุด: บอก goal → agent **ทดสอบเองทั้ง engagement** อย่างปลอดภัย มีหลักฐาน ตรวจสอบย้อนได้.

### 47.1 Agent loop (plan → act → verify → report)
```
Goal ("หา IDOR/authz flaw ใน scope นี้")
  └► Plan   : ย่อยเป็น sub-goal (map surface → หา insertion point → ตั้งสมมติฐาน)
  └► Act    : เรียก MCP tools (proxy/repeater/intruder/scanner) ใน scope+rate guard (§42)
  └► Observe: อ่าน response/diff/OAST callback เป็นหลักฐาน
  └► Verify : ยิงซ้ำ/สลับ user เพื่อ "พิสูจน์" ก่อนบันทึก (กัน false positive)
  └► Report : สร้าง finding + evidence + remediation (§35) — auto
```
- **Self-verifying findings**: ทุกข้อกล่าวหาต้องมี reproducible request/response + control ที่ต่างกัน → confidence สูงจริง.
- **Multi-agent** (เลือกได้): planner / exploiter / verifier / reporter แยกบทบาท คุยผ่าน core เดียว.
- **Memory ของ engagement**: agent จำ surface/creds/สิ่งที่ลองแล้ว ข้ามรอบ (เก็บใน project §20).
- **Human-in-the-loop**: active/destructive ต้อง approve; read-only เดินเองได้ (§10, §22).
- **Explainable**: ทุก step มี rationale + audit (§36) — ผู้ใช้เห็นว่า "คิดอะไร ทำอะไร ทำไม".
- **Cost/scope governor**: token/$ cap, scope allowlist, rate — agent วิ่งเองแต่ไม่หลุดกรอบ (§42).
- **ต่อ Stealth-Browser MCP**: agent ทดสอบ flow ที่ต้อง JS/2FA/anti-bot ผ่าน browser จริง (§31/§32).

### 47.2 Regression-as-agent
ตั้ง agent รันซ้ำตาม schedule (cron/CI) → เทียบผลรอบก่อน → เตือนเมื่อ **มี vuln ใหม่/หลักฐานเปลี่ยน** = "continuous pentest".

---

## 48. Recon & Attack-Surface Mapping (เริ่มจาก "โดเมนเดียว" → เห็นทั้งพื้นผิว)

Burp เริ่มที่ traffic; BogBogProx เริ่มได้ที่ **แค่ชื่อโดเมน**.

- **Passive/active recon**: subdomain enum, DNS, cert-transparency, tech fingerprint, favicon-hash, ASN/IP range, port hint.
- **Seed surface อัตโนมัติ**: จาก recon → เติม sitemap + scope + target list โดยไม่ต้องเดิน browser ก่อน.
- **ต่อ OpenAPI/GraphQL introspection** (§34) → endpoint map แม่นยำ.
- **Integrate เครื่องมือที่มี** (subfinder/httpx/nuclei/amass) ผ่าน adapter — ผลไหลเข้า core.
- **Surface diff**: subdomain/endpoint ใหม่โผล่ = แจ้ง (§38) → เฝ้า attack surface ต่อเนื่อง.
- ผูก **pentest-dashboard** (โปรเจกต์เดิม) โชว์ surface live.

---

## 49. Smart Fuzzing & Payload Intelligence (เหนือ Intruder ธรรมดา)

- **Grammar/format-aware fuzzing**: รู้โครง JSON/XML/multipart/GraphQL → mutate อย่างมีความหมาย ไม่สุ่มมั่ว.
- **Coverage/response-guided**: ดู status/len/timing/error signature → โฟกัส payload ที่ "ขยับ" ระบบ (แนว feedback fuzzing §18).
- **Payload library อัจฉริยะ**: SecLists [18] + polyglot + context-aware (เลือกชุดตาม insertion point: SQL vs. template vs. path).
- **Auto-encoding chains** (§33) เพื่อทะลุ filter/WAF; mutation rules (case/comment/whitespace/unicode).
- **Anomaly detection บนผล**: cluster response, ชี้ outlier อัตโนมัติ (rayon §4).
- **Differential/timing** analysis สำหรับ blind (SQLi/injection ตามเวลา).

---

## 50. Traffic Capture Everywhere (ไม่ใช่แค่ browser)

| แหล่ง | วิธี |
|---|---|
| **Browser** | proxy + CA (§28), หรือ Stealth-Browser MCP |
| **มือถือ (iOS/Android)** | proxy + CA มือถือ (§28), จับ traffic แอป (ที่ไม่ pin) |
| **System-wide** | transparent/SOCKS mode (§27) จับทุกโปรเซส |
| **CLI/แอปเดสก์ท็อป** | `HTTP_PROXY`/SOCKS env, หรือ transparent |
| **นำเข้า** | **PCAP** (tshark/pdml), **HAR**, **mitmproxy flow**, Burp/ZAP export (§34) |
| **replay** | ยิงซ้ำจากไฟล์ที่ import เข้าเครื่องมือทุกตัว |

- **cert-pinning bypass note**: เอกสารแนวทาง (Frida/patched APK) — เราไม่ทำ tool แต่ชี้ทาง; รับ traffic ที่ bypass แล้วเข้ามา.

---

## 51. API & Regression Security (CI-native, เป็น "gate" ของทีม dev)

- **OpenAPI/GraphQL-driven scan**: อ่าน schema → ทดสอบทุก endpoint/param อัตโนมัติ (authz/BOLA/BFLA/mass-assignment — OWASP API Top 10).
- **Contract/diff**: เทียบ response ต่อรุ่น → จับ regression (field leak ใหม่, authz หลุด, error verbose).
- **Headless ใน pipeline**: `bogbogproxd` + schema → **SARIF + exit code** (§34) → PR fail ถ้ามี high; baseline suppression.
- **BOLA/IDOR matrix**: ยิง endpoint เดียวด้วยหลาย identity อัตโนมัติ แล้วเทียบสิทธิ์ (แกนของ AI §47).

---

## 52. Learning Mode & Knowledge Base (เครื่องมือที่สอนไปด้วย)

ต่อยอดนิสัยทำ **writeup** ของเรา — ให้ BogBogProx เป็นทั้งอาวุธและครู.

- **อธิบาย payload/finding**: ทุก issue มี "ทำไมถึงเป็นช่องโหว่ + หลักการ + remediation + อ้างอิง" (AI + template).
- **Writeup generator**: จาก flow+finding+evidence → เอกสาร HTML/MD สวย (สไตล์ที่เราทำใน `~/writeups/`) + GIF (§35/§26).
- **Guided mode**: สำหรับผู้เริ่ม — แนะขั้นถัดไป, ชี้ insertion point, สอน HTTPQL.
- **Knowledge base ในตัว**: cheat-sheet (encoding/payload/technique) + ลิงก์ WSTG/CWE, ค้นจาก command palette.

---

## 53. Performance Engineering Internals (พิสูจน์ "เบาแต่เก่ง" ระดับโครง)

- **Zero-copy path**: body เป็น `Bytes`/`bytes::Buf`, blob content-addressed (§7) — ไม่ clone ก้อนใหญ่.
- **Streaming ทุกจุด**: proxy/replay/scan ทำงานบน stream ไม่โหลดทั้ง body (§6).
- **io_uring** (tokio-uring) เป็น optional backend บน Linux สำหรับ throughput สูง.
- **Arena/slab allocator** สำหรับ per-flow object; `mimalloc`/`jemalloc` เลือกได้.
- **Lock-free** hot path (channel + writer actor §7 แทน mutex ร่วม).
- **Virtualized UI**: list ล้านแถว render เฉพาะที่เห็น (ทุก frontend).
- **Perf budget เป็น CI gate** (§18/§25): fail ถ้า p99/RAM/startup ถอย.

---

## 54. Cloud / Hosted BogBogProx (vision, optional — เฟสไกล)

- **Self-host team server** (§43) → ต่อยอดเป็น **managed cloud** (open-core §44): project ในคลาวด์, collaborate, agent รันบน worker.
- **Elastic scan workers**: กระจาย active scan/intruder ข้าม node (queue + `bogbogprox-core` เป็น library).
- **OAST public infra** (§32) เป็นบริการ.
- **BYO-key AI** + billing/quota; **zero-knowledge option** (encrypt project ฝั่ง client §30).
- ยึดหลัก: **local-first เสมอ**, cloud เป็นทางเลือก ไม่บังคับ (trust §41).

---

## 55. Success Metrics & North-Star KPIs (รู้ว่าฝันเป็นจริงแค่ไหน)

| ด้าน | ตัวชี้วัด | เป้า |
|---|---|---|
| **Perf** | added-latency p99 / idle RAM / startup | < 5ms / < 60MB / < 0.5s (§25) |
| **Capability** | Burp parity checklist (§11) | ครบเฟส 4 |
| **AI** | agent หา vuln ใน lab ได้เองแบบ verified | IDOR/SSRF/SQLi ใน CI (§18/§47) |
| **DX** | first-flow time (ลง→เห็น HTTPS แรก) | < 2 นาที (§28) |
| **Trust** | telemetry / CVE response | 0 / มี policy+SLA (§40/§41) |
| **Adoption** | stars / contributors / plugins | โตต่อเนื่อง, community เขียน plugin ได้ |
| **Reliability** | crash-free session / งานไม่หายหลัง restart | สูง, WAL คุ้ม (§7/§19) |

---

## 56. Moonshots (blue-sky — เผื่อฝันไกลกว่านี้)

- **eBPF capture** (Linux) จับ traffic ระดับ kernel โดยไม่ตั้ง proxy.
- **HTTP/3 (QUIC) MITM** เมื่อ ecosystem Rust พร้อม (ปลด Non-Goal §1.3).
- **On-device fine-tuned model** เฉพาะงาน web-sec (ไม่ต้องพึ่ง cloud, §41).
- **Auto-exploit-chain**: agent ต่อ vuln หลายตัวเป็น chain เอง (SSRF→metadata→RCE) แบบมี guard.
- **Collaborative agent swarm**: หลาย agent แบ่งพื้นผิวเทสต์ขนานกันในทีม (§36/§47).
- **Marketplace economy**: plugin/workflow/report-template แบ่งปัน/ขาย (§37).
- **Wireless/OT/mobile-deep** modules ต่อจากแกนเดียว (สถาปัตยกรรม port เผื่อไว้แล้ว).

> ทุก moonshot ต่อได้เพราะ **core เป็น library + ports (engine/storage/AI/transport)** — ไม่ต้องรื้อ.

---

## 57. References
1. Caido — modern Burp alternative (Rust backend, browser UI, HTTPQL, Workflows, AI plugins). https://www.caido.io/compare/burpsuite/
2. hudsucker — Rust intercepting HTTP/S proxy (hyper/rustls/rcgen). https://github.com/omjadas/hudsucker · https://docs.rs/hudsucker
3. hudsucker on crates.io. https://crates.io/crates/hudsucker
4. hatoo — *Building a mitmproxy-like tool in Rust: Lessons learned* (hyper/rustls/rcgen, ALPN/HTTP2, TCP_NODELAY). https://zenn.dev/hatoo/articles/f7f0d5900e1c2e
5. Tauri vs Electron (bundle/RAM; Hoppscotch 165MB→8MB, −70% RAM). https://tech-insider.org/tauri-vs-electron-2026/ · https://raftlabs.medium.com/tauri-vs-electron-a-practical-guide-to-picking-the-right-framework-5df80e360f26
6. Ratatui — Rust TUI framework (immediate-mode, sub-ms, powers gitui). https://ratatui.rs/ · https://github.com/ratatui/ratatui
7. The Rust Book — *Cargo Workspaces* (core lib + multi-frontend crates). https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html
8. PostHog — *Untangling Tokio and Rayon in production* (async I/O + rayon CPU pool + semaphore backpressure). https://posthog.com/blog/untangling-rayon-and-tokio · tokio-rayon bridge: https://docs.rs/tokio-rayon
9. Model Context Protocol — *Transports* (stdio + Streamable HTTP; single `/mcp`; Origin check). https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
10. *Why MCP Deprecated SSE and Went with Streamable HTTP* (2025-03-26). https://blog.fka.dev/blog/2025-06-06-why-mcp-deprecated-sse-and-go-with-streamable-http/ · Rust SDK `rmcp`: https://github.com/modelcontextprotocol/rust-sdk
11. SQLite — *Write-Ahead Logging*. https://sqlite.org/wal.html · SQLite vs Postgres in production. https://dev.to/merbayerp/sqlite-vs-postgresql-which-one-in-production-1og9
12. *SQLite concurrent writes and "database is locked"* (busy_timeout, synchronous=NORMAL). https://tenthousandmeters.com/blog/sqlite-concurrent-writes-and-database-is-locked-errors/
13. Wasmtime — WebAssembly runtime + Component Model (sandboxed plugins, WIT/bindgen). https://docs.wasmtime.dev/ · component: https://docs.wasmtime.dev/api/wasmtime/component/index.html · plugin guide: https://tartanllama.xyz/posts/wasm-plugins/
14. cargo-dist — cross-platform Rust release installers + CI. https://axodotdev.github.io/cargo-dist/ · https://crates.io/crates/cargo-dist
15. OpenTelemetry Rust + `tracing` (de-facto instrumentation; tracing-opentelemetry export). https://opentelemetry.io/docs/languages/rust/ · https://docs.rs/tracing-opentelemetry
16. OWASP Web Security Testing Guide (scanner check catalog) + Threat Modeling. https://owasp.org/www-project-web-security-testing-guide/ · https://owasp.org/www-community/Threat_Modeling
17. cargo-fuzz — coverage-guided fuzzing (libFuzzer) for Rust. https://github.com/rust-fuzz/cargo-fuzz
18. SecLists — payload/wordlist collection. https://github.com/danielmiessler/SecLists
19. STRIDE threat model (Microsoft). https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
20. Nuclei — template-based vulnerability scanner (import community templates). https://github.com/projectdiscovery/nuclei · templates: https://github.com/projectdiscovery/nuclei-templates
21. SARIF — Static Analysis Results Interchange Format (CI/GitHub code-scanning output). https://sarifweb.azurewebsites.net/ · spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
22. Project Fluent — localization system (plural/gender/bidi); `fluent-rs`. https://projectfluent.org/ · https://github.com/projectfluent/fluent-rs
23. mkcert — locally-trusted dev certs / CA install patterns per-OS & mobile (reference for onboarding UX). https://github.com/FiloSottile/mkcert
24. interactsh — OAST / out-of-band interaction server (blind SSRF/XXE/RCE). https://github.com/projectdiscovery/interactsh
25. Automerge — CRDT for local-first collaboration (offline merge). https://automerge.org/ · https://github.com/automerge/automerge
26. keyring-rs — cross-platform OS keychain access for secrets. https://github.com/hwchen/keyring-rs
27. sqlx / refinery — embedded, versioned DB migrations for Rust. https://github.com/launchbadge/sqlx · https://github.com/rust-db/refinery
