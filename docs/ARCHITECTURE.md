# bogbogprox — Architecture & Browser Integration

> เอกสารสถาปัตยกรรมเชิงลึก: ระบบทำงานยังไง, **browser เชื่อมยังไง (MITM/CA/proxy)**, และเหตุผลเบื้องหลังการออกแบบแต่ละชั้น. เป็นคู่มือสำหรับคนที่จะ **แก้/ต่อยอดโค้ด** (สำหรับ "วิธีใช้งาน" ดู [`USAGE.md`](USAGE.md)).

สารบัญ:
1. [ภาพรวม & หลักการ](#1-ภาพรวม--หลักการ)
2. [แผนที่ crate (workspace)](#2-แผนที่-crate-workspace)
3. [Data plane vs Control plane](#3-data-plane-vs-control-plane)
4. [วงจรชีวิตของ request/response](#4-วงจรชีวิตของ-requestresponse)
5. [🌐 Browser integration เชิงลึก](#5--browser-integration-เชิงลึก)
6. [Storage architecture](#6-storage-architecture)
7. [Event system (live + cross-process)](#7-event-system-live--cross-process)
8. [Concurrency model](#8-concurrency-model)
9. [Team mode](#9-team-mode)
10. [Plugin architecture (WASM)](#10-plugin-architecture-wasm)
11. [Security model](#11-security-model)
12. [Running modes & config](#12-running-modes--config)

---

## 1. ภาพรวม & หลักการ

bogbogprox เป็น **web security proxy** — คั่นกลางระหว่าง browser กับ target, decrypt HTTPS,
จับ/แก้/วิเคราะห์ traffic. หลักการออกแบบ 5 ข้อ:

| หลักการ | ทำจริงยังไง |
|---|---|
| **Ports & adapters** | logic อยู่ใน `bogbogprox-core` หลัง trait; storage/engine สลับ impl ได้ (SQLite↔Postgres) โดยไม่แตะ caller |
| **Local-first, scale-out ทีหลัง** | binary เดียวรัน local (SQLite) → ตัวเดิมรัน team (Postgres) แค่เปลี่ยน flag |
| **Thin frontends** | TUI/Web/Desktop คุยผ่าน REST+SSE เดียวกัน ไม่มี logic ของตัวเอง |
| **Blocking-friendly async** | proxy บน tokio; store/plugin ที่ blocking รันบน worker หรือ actor thread (ยอมรับได้, เหมือน Burp) |
| **Deny-by-default security** | CA เฉพาะเครื่อง, auth token, plugin sandbox, body limit, perms 0600/0700 |

```mermaid
flowchart LR
  B["Browser / curl / tool"] -->|"proxy :8888"| E["bogbogprox-engine<br/>(data plane, hudsucker)"]
  E -->|"MITM TLS"| T["Target site"]
  E --> C["bogbogprox-core<br/>(intercept · rules · scanner ·<br/>session · ws · plugins)"]
  C --> S[("Store<br/>SQLite / Postgres")]
  C --> EV(("Event bus"))
  EV -->|SSE| UI["Web · TUI · Desktop"]
  EV -->|MCP| AI["Claude / AI"]
```

---

## 2. แผนที่ crate (workspace)

```
crates/
├── bogbogprox-core           # โมเดล + trait + coordinators (ไม่มี I/O ของ proxy)
│   ├── model            #   Flow/HttpRequest/HttpResponse/FlowEvent (+ body_truncated)
│   ├── store            #   trait FlowStore (storage port)
│   ├── intercept        #   breakpoint coordinator (oneshot per held item)
│   ├── rules            #   Match & Replace (regex + {{var}} templating)
│   ├── scanner          #   passive findings + dedup
│   ├── session          #   Vars + Macros + template
│   └── ws               #   WsLog (WebSocket messages)
├── bogbogprox-store-sqlite   # FlowStore ← SQLite (Mutex<Connection>)   [local]
├── bogbogprox-store-postgres # FlowStore ← Postgres (DB-actor thread)   [team]
├── bogbogprox-engine         # data plane: hudsucker (hyper+rustls) + capture + hooks
├── bogbogprox-plugin         # WASM plugin host (wasmtime component model)
├── bogbogproxd               # the daemon: wires engine + REST/SSE API + auth + config + pubsub
├── bogbogprox-tui            # ratatui frontend (REST+SSE client)
├── bogbogprox-desktop        # Tauri native window → dashboard
└── bogbogprox-mcp            # stdio MCP server (AI ขับผ่าน API)
```

**กฎการพึ่งพา:** `bogbogprox-core` ไม่รู้จัก proxy/HTTP/DB; ทุกอย่างพึ่ง core; adapter (store/engine/plugin)
พึ่ง core แล้ว `bogbogproxd` ประกอบทั้งหมด. → เปลี่ยน backend หรือเพิ่ม frontend ไม่กระเทือนแกน.

---

## 3. Data plane vs Control plane

แยกสองระนาบชัดเจน:

- **Data plane** (`bogbogprox-engine`) — เส้นทางที่ traffic จริงวิ่ง. ต้องเร็ว, ต่อ connection. hudsucker
  รับ connection, MITM, เรียก handler ต่อ request/response.
- **Control plane** (`bogbogproxd` REST/SSE) — คน/AI สั่งงาน (intercept toggle, add rule, run intruder).
  ทั้งสองระนาบแชร์ **coordinators** ตัวเดียวกัน (Arc): `Intercept`, `Rules`, `Scanner`, `Vars`,
  `WsLog`, `PluginHost` + **event bus** (`broadcast::Sender<FlowEvent>`).

```mermaid
flowchart TB
  subgraph DP["Data plane — bogbogprox-engine"]
    H["CaptureHandler<br/>(per connection)"]
  end
  subgraph CP["Control plane — bogbogproxd axum"]
    API["REST /api/v1/*"]
    SSE["SSE /stream"]
  end
  subgraph SH["Shared (Arc) — bogbogprox-core"]
    IC["Intercept"]; RU["Rules"]; SC["Scanner"]; VA["Vars"]; PL["PluginHost"]; BUS(("events"))
  end
  H --- IC & RU & SC & VA & PL & BUS
  API --- IC & RU & SC & VA & PL
  BUS --> SSE
```

---

## 4. วงจรชีวิตของ request/response

หัวใจอยู่ที่ `CaptureHandler::handle_request` / `handle_response` (`bogbogprox-engine/src/lib.rs`).
**ลำดับ hook สำคัญมาก** (แต่ละชั้นทำก่อนชั้นถัดไป):

```mermaid
sequenceDiagram
  participant Br as Browser
  participant Eng as Engine (handler)
  participant Core as Coordinators
  participant Tg as Target

  Br->>Eng: request (ผ่าน proxy)
  Note over Eng: CONNECT? → ปล่อยผ่าน (ตั้ง TLS tunnel)
  Note over Eng: Upgrade: websocket? → ปล่อยผ่าน (→ WS handler)
  Eng->>Eng: buffer body (≤16 MiB, เกิน = truncated flag)
  Eng->>Core: 1) Match & Replace (apply_request + {{var}})
  Eng->>Core: 2) Plugins on_request (skip ถ้า truncated)
  Eng->>Core: 3) Intercept (ถ้า on & in-scope) → await ตัดสินใจ
  Note over Eng: dirty? → rebuild_parts (สร้าง wire ใหม่)
  Eng->>Core: store.insert_request (final) + broadcast FlowNew
  Eng->>Tg: forward
  Tg-->>Eng: response
  Eng->>Eng: buffer body (≤16 MiB)
  Eng->>Core: 4) Match & Replace (apply_response)
  Eng->>Core: 5) Plugins on_response
  Eng->>Core: 6) Intercept response (ถ้า on)
  Eng->>Core: store.attach_response + broadcast FlowUpdate
  Eng->>Core: 7) Scanner.scan(flow) → broadcast Finding
  Eng-->>Br: response
```

**จุดสำคัญ:**
- **store ที่ request หลัง decision** → history เห็น request "ที่ส่งจริง" (หลัง M&R/plugin/intercept edit)
- **`dirty` flag** — rebuild wire (method/path/query/headers/body) แค่เมื่อมีชั้นไหนแก้ → ไม่เสีย perf ตอนไม่แก้
- **truncated body ข้าม M&R/plugin** — กัน "unsafe partial replay" (body ที่ตัดแล้วห้ามเอาไปแก้เป็นเสมือนครบ)
- **req↔resp correlation = FIFO ต่อ connection** — ถูกต้องเพราะ build hudsucker **ไม่เปิด feature `http2`** → ทุก connection เป็น HTTP/1.1 (ไม่ multiplex)

---

## 5. 🌐 Browser integration เชิงลึก

> **bogbogprox ไม่มี browser ของตัวเอง** — เป็น **HTTP proxy** ที่ browser (ของคุณ) ชี้มาหา.
> โมเดลเดียวกับ Burp classic. ส่วนนี้อธิบายว่า "เชื่อมกันยังไง" ตั้งแต่ TCP จนถึง TLS MITM.

### 5.1 browser เชื่อมยังไง — proxy protocol

ตั้ง browser ให้ใช้ HTTP proxy `127.0.0.1:8888`. จากนั้น:

- **HTTP ธรรมดา (`http://`)** — browser ส่ง request แบบ **absolute-form** ไปที่ proxy:
  `GET http://site/path HTTP/1.1`. proxy อ่าน host จาก URI แล้ว forward เอง.
- **HTTPS (`https://`)** — browser ส่ง **`CONNECT site:443 HTTP/1.1`** ให้ proxy ก่อน (ขอ tunnel).
  ปกติ proxy จะ "เปิดท่อ" ให้ TLS วิ่งผ่านโดยไม่เห็นเนื้อ. **แต่เราจะ MITM** (ดู 5.2).

```mermaid
sequenceDiagram
  participant Br as Browser
  participant Px as bogbogprox :8888
  participant Tg as site:443
  Br->>Px: CONNECT site:443
  Px-->>Br: 200 Connection established
  Note over Px: แทนที่จะเปิดท่อเฉยๆ<br/>Px สวมเป็น "site" (MITM)
  Br->>Px: TLS ClientHello (คิดว่าคุยกับ site)
  Px-->>Br: TLS cert ที่ Px ออกเอง (ลงนามด้วย BogBogProx CA)
  Note over Px,Tg: Px เปิด TLS อีกเส้นไปหา site จริง
  Px->>Tg: TLS (verify cert จริงของ site)
  Br->>Px: (decrypted) GET /path
  Px->>Tg: forward
```

### 5.2 TLS MITM — ทำยังไง (hudsucker)

`bogbogprox-engine` ใช้ **[hudsucker]** (hyper + rustls + rcgen) เป็น data plane:

1. รับ `CONNECT site:443` → ตอบ `200` → เริ่ม TLS handshake กับ browser **โดยสวมเป็น site**.
2. hudsucker **ออก leaf cert ของ `site` สดๆ** (rcgen) ลงนามด้วย **BogBogProx CA** ของเครื่อง, cache ไว้.
3. browser ทำ TLS handshake สำเร็จ (เพราะ browser trust BogBogProx CA — ดู 5.3) → คุยเป็น plaintext กับ proxy.
4. proxy อ่าน request ที่ decrypt แล้ว (มาถึง handler เป็น **origin-form** `GET /path`), เปิด TLS
   เส้นที่สองไป **site จริง** (rustls, verify cert จริง), forward.

→ ผลคือ proxy **เห็นและแก้ HTTPS ได้เต็ม** ทั้งที่ browser กับ site ยังคิดว่าคุย TLS ปกติ.

### 5.3 CA & trust — ทำไมต้องติดตั้ง cert

BogBogProx สร้าง **CA เฉพาะเครื่อง** (`bogbogproxd ca generate` → `~/.config/bogbogprox/ca/bogbogprox-ca.pem` +
`.key` perms 0600). leaf cert ที่ proxy ออกให้ทุก site ลงนามด้วย CA นี้.
browser จะ trust ก็ต่อเมื่อ **ติดตั้ง `bogbogprox-ca.pem` ใน trust store**:

- **ห้าม** เอา CA นี้ไปแชร์/commit (ใครมี key = MITM traffic ของคุณได้) — `.gitignore` กัน `*.key/*.pem` แล้ว
- ถ้าไม่ติดตั้ง → browser ขึ้น cert error (เพราะไม่รู้จักผู้ลงนาม)

### 5.4 managed browser — `bogbogproxd browser`

เพื่อความสะดวก (เหมือน Burp embedded browser) มี subcommand เปิด Chromium ที่ตั้งค่าให้เสร็จ:

```bash
bogbogproxd browser --url https://target.com
# = chromium --proxy-server=http://127.0.0.1:8888 --ignore-certificate-errors \
#            --user-data-dir=<throwaway> ...
```
- **throwaway profile** (ไม่แตะ browser จริงของคุณ)
- **`--ignore-certificate-errors`** (ยอมรับ MITM cert โดยไม่ต้องติดตั้ง CA — เหมาะ *เฉพาะ testing*)
- หา binary อัตโนมัติ: chromium → chrome → brave

### 5.5 WebSocket

- **WS upgrade** (`Upgrade: websocket`) — handler **ปล่อยผ่านไม่ buffer** (ไม่งั้นจะรบกวน upgrade);
  hudsucker dispatch ไป `WsHandler` แยก. แต่ละ message ถูก log (`WsLog`) แล้ว broadcast `WsMessage`.
- **wss://** MITM ได้ (ผ่าน CONNECT+TLS เหมือน HTTPS). **ws://** ธรรมดา hudsucker ต่อ upstream ด้วย
  rustls (TLS) → plain ws server จะ mismatch — ในทางปฏิบัติ traffic จริงเป็น wss เกือบหมด.

### 5.6 ทำไม HTTP/1.1 อย่างเดียว

build hudsucker **ไม่เปิด feature `http2`** โดยตั้งใจ → ทั้งฝั่ง browser (ALPN) และ upstream เป็น h1.
ผลดี: request บน connection เดียว **serialize** (ไม่ multiplex) → จับคู่ req↔resp แบบ **FIFO** ถูกต้อง 100%
โดยไม่ต้องมี stream-id correlation. แลกกับ: บางไซต์ที่ชอบ h2 อาจ behave ต่างเล็กน้อย (แต่ทุกไซต์รองรับ h1 fallback).

---

## 6. Storage architecture

**Port:** `trait FlowStore` (`bogbogprox-core/store`) — `insert_request / attach_response / list_flows /
get_flow / count / clear`. Method เป็น **sync** (เรียกจาก async engine แบบ blocking — ยอมรับได้).

### 6.1 SQLite (local) — `bogbogprox-store-sqlite`
- `Arc<Mutex<Connection>>` (single-writer), WAL mode, headers เก็บเป็น JSON, body เป็น BLOB.
- perms 0600 บน db/wal/shm.

### 6.2 Postgres (team) — `bogbogprox-store-postgres`
ปัญหา: sync `postgres` client มี tokio runtime ของตัวเอง → เรียกใน tokio worker = **panic**.
แก้ด้วย **DB-actor thread**:

```mermaid
flowchart LR
  A["async worker<br/>(FlowStore call)"] -->|"closure + reply channel"| ACT["DB-actor thread<br/>(std::thread, ไม่ใช่ tokio)"]
  ACT -->|"sync query"| PG[("Postgres")]
  ACT -->|"reply"| A
```
- FlowStore method ส่ง closure ไปรันบน actor thread แล้ว **block รอผล** (เหมือน SQLite mutex block).
- **schema init race:** หลาย daemon start พร้อมกันบน DB ว่าง race กันที่ `CREATE TABLE IF NOT EXISTS`
  (pg_type unique violation) → ป้องกันด้วย `pg_advisory_lock` เป็น **statement แยก autocommit** ก่อน DDL.

### 6.3 Config backend
`config::Backend { Local(file) | Postgres }` — rules/scope/vars/macros/scanner persist เป็น
`config.json` (local) หรือตาราง `bogbogprox_settings` (team, แชร์กัน). อ่านตอน startup, save หลังทุก mutation.

---

## 7. Event system (live + cross-process)

**ในเครื่องเดียว:** ทุกเหตุการณ์เป็น `FlowEvent` ยิงเข้า `broadcast::channel`. `enum FlowEvent`:
`FlowNew · FlowUpdate · Activity · InterceptPaused/RespPaused/Resolved/State · Finding ·
WsMessage · ConfigChanged · Presence`.

SSE endpoint (`/api/v1/stream`) subscribe channel → ส่งเป็น `data: <json>` ให้ทุก client (Web/TUI/MCP).

**ข้ามหลาย daemon (topology B):** `pubsub.rs` relay ผ่าน **Postgres LISTEN/NOTIFY**:

```mermaid
flowchart LR
  subgraph DA["daemon A"]
    LA(("local bus")) -->|publish +origin=A| PGN[("NOTIFY bogbogprox_events")]
    PGN -->|LISTEN| RA(("remote bus A"))
  end
  subgraph DB2["daemon B"]
    PGN -->|LISTEN| RB(("remote bus B"))
    RB --> SB["SSE (B)"]
  end
  LA --> SA["SSE (A)"]
```
- publisher tag ทุก event ด้วย **origin id สุ่ม**; listener **ข้าม event ของ origin ตัวเอง** → กัน echo.
- แยก **local bus** (engine ยิง) กับ **remote bus** (listener ยิง) → SSE merge สองอัน → publisher ไม่เห็น remote → ไม่ echo ซ้ำ.

---

## 8. Concurrency model

| งาน | รันบน | เหตุผล |
|---|---|---|
| Proxy connections (I/O-bound พันคอนเนกชัน) | **tokio** async | ไม่บล็อก, scale connection |
| Store call (SQLite) | tokio worker (blocking) | rusqlite เป็น sync ล้วน — บล็อก worker ชั่วครู่ ยอมรับได้ |
| Store call (Postgres) | **DB-actor thread** | sync postgres client รันใน tokio ไม่ได้ (มี runtime เอง) |
| Postgres LISTEN/NOTIFY | **2 std threads** (notify + listen) | connection ค้างไว้รับ notification |
| Plugin hook | tokio worker (blocking) | wasmtime `Engine/Component/Linker` = Send+Sync; `Store` สร้าง **local ต่อ call** → ไม่ต้องมี actor |
| Intercept await | tokio (`oneshot`) | request "ค้าง" ใน async task รอ decision จาก API |

**หลัก:** อะไรที่ blocking แต่ *เร็ว* (store) → บล็อก worker ตรงๆ. อะไรที่ blocking + *มี runtime ของตัวเอง*
(postgres) → actor thread แยก. อะไรที่ *ต้องรอคน* (intercept) → async await.

---

## 9. Team mode

- **Topology A (central, MVP):** daemon เดียวบน Postgres; ทุกคนชี้ browser + เปิด dashboard เดียว → เห็นสด (SSE broadcast ตัวเดียว).
- **Topology B (scale):** หลาย daemon ชี้ Postgres เดียว → sync event ข้าม process ผ่าน NOTIFY (§7).
- **Auth:** project token (แชร์) → `POST /team/join` → **session token** (getrandom, constant-time compare).
  middleware บังคับ `Authorization: Bearer` ทุก /api/ (ยกเว้น health/join/dashboard); SSE รับ `?token=`
  (EventSource ตั้ง header ไม่ได้). session idle timeout 12h + `/team/logout`.
- **Presence:** last-seen ต่อ session (refresh ทุก authed request + poll `/operators` ทุก 15s), online ภายใน 30s.
- **Config sync:** ทุก mutation broadcast `ConfigChanged{kind}` → client reload panel ที่เปิดอยู่.

---

## 10. Plugin architecture (WASM)

`bogbogprox-plugin` = **wasmtime component-model host**. Contract ผ่าน **WIT** (`wit/world.wit`):
plugin export `hooks` (name/on-request/on-response), host export `log` capability.

```mermaid
flowchart LR
  subgraph H["bogbogprox-plugin (host)"]
    L["load .wasm<br/>from plugins/"] --> ST["per-call:<br/>new Store + fuel 200M<br/>+ instantiate"]
  end
  ENG["engine handle_request"] -->|"Req"| ST
  ST -->|"on-request"| G["guest component<br/>(Rust/Go/JS → WASM)"]
  G -->|"log cap"| H
  G -->|"ReqAction<br/>Unchanged/Forward/Drop"| ENG
```

- **Sandbox by default** — guest ทำ syscall/net/fs เองไม่ได้ ต้องผ่าน host cap. WASI จำกัดสุด.
- **Fuel limit 200M instruction/call** — runaway plugin trap ไม่ทำ proxy ค้าง; trap → log + ข้าม.
- **Instantiate-per-call (stateless)** → `PluginHost` เป็น Send+Sync เรียกจาก async engine ตรงๆ ได้
  (ไม่ต้องมี actor เพราะ Engine/Component/Linker เป็น Send+Sync, Store สร้าง local บน worker).
- Hook เสียบ **หลัง M&R ก่อน intercept** (request) และ **หลัง M&R** (response); Forward→dirty rebuild, Drop→403.
- สถานะ: **P1** (on-request/response + log). ถัดไป P2 passive-scan hook + add-finding, P3 http-send/vars/kv.
  ดู [`design/wasm-plugins.md`](design/wasm-plugins.md).

---

## 11. Security model

| ชั้น | มาตรการ |
|---|---|
| **MITM CA** | เฉพาะเครื่อง, key perms 0600, ไม่ commit; leaf cert cache ต่อ host |
| **API/team auth** | project token → session token (getrandom, constant-time), middleware, idle 12h, logout, secrets ผ่าน env (`BOGBOGPROX_AUTH_TOKEN`) ไม่โผล่ process list |
| **Plugin** | WASM sandbox, capability deny-by-default, fuel/epoch/mem limit, trap→disable |
| **Body** | capture ≤16 MiB + `body_truncated` flag; ห้าม replay body ที่ truncated (กัน unsafe partial) |
| **M&R** | ไม่ทำ binary body เสีย (bail ถ้า non-UTF8); `{{var}}` escape `$`→`$$` กัน regex-ref injection |
| **Filesystem** | config/data/ca dir perms 0700, db/wal/shm 0600 |
| **Transport (team)** | ⚠️ API/SSE เป็น http — **ต้องวางหลัง TLS/reverse-proxy ก่อน expose** |

---

## 12. Running modes & config

```bash
# Local (SQLite, ไม่มี auth)
bogbogproxd run                                  # proxy :8888 · dashboard :9000

# Team (Postgres + auth) — ใช้ env สำหรับ secrets
BOGBOGPROX_POSTGRES=postgres://bogbogprox:bogbogprox@host/bogbogprox \
BOGBOGPROX_AUTH_TOKEN=SECRET bogbogproxd run

# เปลี่ยนพอร์ต
bogbogproxd run --proxy 127.0.0.1:9999 --api 127.0.0.1:9001

# เครื่องมืออื่น
bogbogproxd ca generate | ca path                # CA
bogbogproxd browser --url https://target         # managed browser
bogbogproxd flows | flush                        # CLI
bogbogprox-tui [--api https://.. --token ..]     # TUI (รองรับ TLS+auth)
bogbogprox-desktop                               # native window
bogbogprox-mcp                                   # MCP (env BOGBOGPROX_API/BOGBOGPROX_TOKEN/BOGBOGPROX_AGENT)
```

**ไฟล์/พอร์ต** (override ทั้งหมดด้วย `BOGBOGPROX_HOME`):
- `~/.config/bogbogprox/ca/` — CA · `~/.config/bogbogprox/config.json` — settings · `~/.config/bogbogprox/plugins/*.wasm`
- `~/.local/share/bogbogprox/flows.sqlite` — flows (local)
- proxy `:8888` · API+dashboard `:9000` · Postgres `:5432`

---

*เอกสารนี้อธิบายสถาปัตยกรรมที่ **implement จริง**. ส่วนวิสัยทัศน์ 57 sections ดู [`DESIGN.md`](DESIGN.md);
วิธีใช้ทีละฟีเจอร์ดู [`USAGE.md`](USAGE.md); ดีไซน์ team mode / plugins ดู [`design/`](design/).*
