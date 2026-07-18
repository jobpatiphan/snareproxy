# Design: Team Mode (Collaborative Engagements)

> Status: **Draft / design** · Owner: bogbogprox core · Supersedes: DESIGN.md §7/§14/§15 "team mode (Postgres)" notes
> เป้าหมาย: ให้ผู้ทดสอบหลายคน **ทำงานบน engagement เดียวกันแบบเรียลไทม์** — เห็น flow/finding/rule/scope ของกันและกันสด, แก้ config ร่วมกัน, รู้ว่าใครกำลังทำอะไร โดย **ไม่รื้อสถาปัตยกรรมเดิม** (storage/engine อยู่หลัง port อยู่แล้ว).

---

## 1. Goals / Non-goals

**Goals**
- ผู้ทดสอบหลายคนต่อ engagement เดียว เห็น **flows, findings, WebSocket, sitemap** ที่ใครจับก็ได้ **สดๆ**.
- แชร์ **config ร่วมกัน**: Match&Replace rules, scope, session vars/macros, scanner state.
- **Attribution** — ทุก flow/finding/action ติดชื่อคนทำ.
- **Presence** — ใครออนไลน์, กำลังดู flow ไหน.
- **Auth** — เข้าร่วม server ของทีมได้เฉพาะคนที่ได้รับอนุญาต; traffic API/SSE เข้ารหัส (TLS).
- **ไม่ทำลาย single-user local mode** — `snared run` (SQLite, ไม่มี auth) ต้องทำงานเหมือนเดิม.

**Non-goals (เฟสนี้)**
- Offline-first / multi-master sync แบบ **CRDT** — ยังไม่ทำ (ดู §6, เปิดทางไว้แต่ deferred).
- Multi-region / horizontal scale หลาย server node — deferred (§9).
- Role/permission ละเอียด (viewer/editor/admin) — MVP เป็น flat "member".
- Video/voice/chat — นอกขอบเขต.

---

## 2. What we build on (existing architecture)

- `snared` = daemon เดียว: proxy engine (hudsucker) + **`FlowStore` port** (ตอนนี้ SQLite) + coordinators ใน process (`Intercept`, `Rules`, `Scanner`, `Vars`, `Macros`, `WsLog`) + `broadcast::channel<FlowEvent>` → **SSE** `/api/v1/stream`.
- Frontends (TUI/Web/Desktop) คุย snared ผ่าน **REST + SSE** เท่านั้น (thin clients).
- Config เก็บถาวรใน `config.json` (rules/scope/scanner/vars/macros).

Team mode คือ **การสลับ backing store เป็น Postgres + เพิ่มชั้น auth/attribution/presence** บนโครงเดิม — ไม่ต้องแตะ UI เพราะ UI คุยผ่าน API ที่ port อยู่แล้ว (สอดคล้อง ADR 009 "local-first daemon + client SDK").

---

## 3. Topology decision

พิจารณา 3 แบบ:

| แบบ | อธิบาย | ข้อดี | ข้อเสีย |
|---|---|---|---|
| **A. Central proxy + central store** | มี `snared` ตัวเดียว (team server) รัน proxy + Postgres; ทุกคนตั้ง browser ชี้ team proxy + client ต่อ API เดียวกัน | reuse โค้ดเดิมเกือบ 100% (แค่ SQLite→Postgres + auth) | traffic ทุกคนผ่าน host เดียว, ต้องแชร์ CA, privacy/coupling สูง |
| **B. Local proxy + central collab store** | แต่ละคนรัน proxy engine ในเครื่องตัวเอง แต่ push flow/finding + subscribe event ไปที่ **collab server** กลาง (Postgres) | isolation ดี, capture เป็น local (latency ต่ำ), ต่างคนต่าง CA | ต้องมีชั้น sync (client→server push), โค้ดเพิ่ม |
| C. Peer-to-peer | ไม่มี server กลาง, sync ตรงระหว่าง peer | ไม่ต้องมี infra กลาง | consistency/discovery ยาก, เกินความจำเป็น |

**Decision (ADR T-001): MVP = A (central), target = B.**
เริ่มด้วย **A** เพราะ reuse โค้ดสูงสุดและพิสูจน์ collaboration layer ได้เร็ว; ออกแบบ store/event ให้พร้อมย้ายไป **B** (แยก "capture" ออกจาก "collab state") โดยไม่รื้อ. เหตุผล: `FlowStore` + `FlowEvent` เป็น port อยู่แล้ว → โมเดล B แค่ทำ store adapter ที่ push ข้าม network.

```
        MVP (A):                              Target (B):
  [op1 browser]─┐                      [op1 local snared]─push─┐
  [op2 browser]─┼─▶ team snared ──▶ PG   [op2 local snared]─push─┼─▶ collab server ──▶ PG
  [op3 browser]─┘   (proxy+api+sse)       [op3 local snared]─push─┘   (api+sse+auth)
        clients ◀── SSE ──┘                     clients ◀── SSE ──────────┘
```

---

## 4. Storage: SQLite → Postgres

เรามี **`FlowStore` trait (storage port)** อยู่แล้ว → team mode = เพิ่ม crate **`snare-store-postgres`** (sqlx) impl trait เดิม.

**สิ่งที่ append-only (ง่าย, ไม่มี conflict):** flows, responses/blobs, findings, ws_messages, activity.
**สิ่งที่ mutable ร่วมกัน (ต้องมีกลยุทธ์, §6):** rules, scope, vars, macros, scanner toggle.

Coordinators ที่ตอนนี้อยู่ใน memory + persist ลง `config.json` ต้องมี **backing store abstraction** ใหม่:

```rust
// ใหม่: settings port — local ใช้ file, team ใช้ Postgres
trait SettingsStore: Send + Sync {
    async fn load(&self) -> Result<Persisted>;
    async fn save(&self, p: &Persisted) -> Result<()>;
    // team: ฟังการเปลี่ยนแปลงจากคนอื่น
    async fn watch(&self) -> impl Stream<Item = SettingsChange>;
}
```

**Postgres schema (sketch):**
```
projects(id, name, created_at)
operators(id, project_id, display_name, token_hash, created_at, last_seen)
flows(id, project_id, operator_id, ts, source, method, scheme, host, port, path, query,
      status, mime, resp_size, duration_ms)
flow_bodies(flow_id, kind ENUM(req,resp), headers JSONB, body BYTEA)   -- blobs แยกตาราง
findings(id, project_id, operator_id, flow_id, severity, title, detail, host, ts)
ws_messages(id, project_id, ts, host, direction, kind, data, size)
rules(id, project_id, name, enabled, part, pattern, replace, updated_by, version)
scope(project_id, host)                        -- set
vars(project_id, name, value, updated_by)
macros(id, project_id, name, method, url, headers JSONB, body, extract, var, updated_by)
settings(project_id, key, value)               -- scanner_enabled ฯลฯ
```

**Blob/body:** เก็บใน `BYTEA` (MVP). ถ้า body ใหญ่มาก → external blob store (S3/minio) ทีหลัง; port เดิมซ่อนได้.
**Single-writer bottleneck หายไป** (Postgres MVCC หลาย writer) → ไม่ต้องมี writer-actor batch แบบ SQLite (แต่ยังทำ batch insert เพื่อ throughput ได้).

**Decision (ADR T-002):** ใช้ **sqlx + Postgres** หลัง `FlowStore` เดิม; blobs ใน BYTEA (MVP); เพิ่ม `SettingsStore` port ให้ coordinators.

---

## 5. Real-time fan-out

- **Append-only events** (flow_new/update, finding, ws_message, activity): server-authoritative, fan-out ผ่าน `broadcast::channel<FlowEvent>` → SSE เดิม **ไม่ต้องแก้อะไร** สำหรับ single server. ทุก client ที่ subscribe เห็นของทุกคน.
- **หลาย server node (future):** in-process broadcast ไม่พอ → ใช้ **Postgres `LISTEN/NOTIFY`** หรือ message bus (NATS/Redis) fan-out ข้าม node. Deferred (§9).
- **Backpressure:** ใช้ semaphore/bounded channel แบบเดิม; client ที่ช้า (lagged) จะ skip event แล้ว re-sync ผ่าน REST (โค้ด SSE ปัจจุบันทำ drop-on-lag อยู่แล้ว).

**Decision (ADR T-003):** MVP = single server, in-process broadcast (reuse ของเดิม). Multi-node fan-out = future.

---

## 6. Consistency model for shared config

Config ที่แก้ร่วมกัน (rules/scope/vars/macros) — เล็ก, แก้ไม่บ่อย, ไม่ใช่ concurrent text editing.

**ตัวเลือก:**
1. **Server-authoritative + serialize + broadcast (LWW).** ทุก write ไปที่ server → server serialize (transaction) → persist → broadcast `RulesChanged`/`VarsChanged` → client อื่น reload/patch. Conflict สองคนแก้พร้อมกัน = ลำดับที่ server รับ (last-write-wins ต่อ id/field).
2. **CRDT** (เช่น add-wins set ต่อ rule id, LWW-register ต่อ var). Merge ได้แม้ offline/multi-master — แต่ overkill สำหรับ single authoritative server.

**Decision (ADR T-004): MVP = ตัวเลือก 1 (server-authoritative LWW + event fan-out).**
- rules/macros มี `id` + `version` → update ตรวจ version กัน lost-update (optimistic concurrency): ถ้า version ไม่ตรง → 409 ให้ client reload แล้วลองใหม่.
- vars = LWW-register ต่อ key (`updated_by`, ts).
- scope = observed-remove set แบบง่าย (server เก็บ set, add/remove เป็น op).
- CRDT เก็บไว้สำหรับตอนไป **B/multi-master** เท่านั้น (ตอนนั้น config ที่ mutable ควรเป็น CRDT จริง: add-wins set of rules keyed by UUID, LWW-register vars). **ออกแบบ id ให้เป็น UUID ตั้งแต่ตอนนี้** เพื่อรองรับ CRDT ภายหลังโดยไม่ migrate.

**Intercept queue (latency-sensitive, ต่อคน):** held request/response เป็นของ **session ของคนที่ traffic วิ่งผ่าน** — **per-operator queue** (key ด้วย operator/client id) ไม่ใช่ global. เลี่ยง conflict บน path ที่ไวสุด. คนอื่นเห็นว่ามี hold (read-only + ใครถือ) แต่ resolve ได้เฉพาะเจ้าของ (หรือ admin override ทีหลัง).

**Decision (ADR T-005):** intercept = per-operator; อื่นๆ = server-authoritative LWW; **ใช้ UUID เป็น id ของ rules/macros เพื่อ future-proof CRDT.**

---

## 7. Auth, identity, transport

- **MVP:** join ด้วย **project bearer token** (แชร์กันในทีม) + operator ใส่ **display name**. Server ออก per-operator session token (JWT/opaque) หลัง join.
- API/SSE middleware: axum layer ตรวจ `Authorization: Bearer` ทุก request (ยกเว้น health). Local mode = ปิด auth (backward-compat).
- **TLS:** team server ต้องรันหลัง TLS. เพิ่ม `snared serve --tls-cert --tls-key` หรือให้อยู่หลัง reverse proxy (nginx/caddy). CA ของ MITM ≠ TLS cert ของ API (คนละอัน).
- **Attribution:** operator id ฝังใน request context → เขียนลง `flows.operator_id`, `findings.operator_id`, `activity.agent/operator`. `Source` enum อาจเพิ่ม operator แยก field (ไม่ทับ proxy/repeater/intruder/scanner).
- **Later:** per-operator accounts, roles (viewer/editor/admin), audit log, SSO.

**Decision (ADR T-006):** MVP auth = shared project token + display name + per-session token; TLS ผ่าน flag หรือ reverse proxy; roles = future.

---

## 8. Presence

- Event ใหม่ `FlowEvent::Presence { operator, status: join|leave|viewing, flow_id? }`.
- Client ส่ง heartbeat (`POST /api/v1/presence`) ทุก ~10s + แจ้ง "กำลังดู flow #N".
- Server เก็บ presence ใน memory (+ `operators.last_seen`), fan-out join/leave/viewing.
- Web: แสดง avatar/ชื่อคนออนไลน์บน toolbar + เครื่องหมายว่ามีคนดู flow เดียวกัน.

**Decision (ADR T-007):** presence = ephemeral in-memory + heartbeat + broadcast; ไม่ persist (ยกเว้น last_seen).

---

## 9. Scale beyond one server (future)

เมื่อต้องหลาย node หรือ geo-distributed:
- Fan-out ข้าม node: **Postgres LISTEN/NOTIFY** (เบา) หรือ **NATS/Redis pub-sub** (ทนกว่า).
- Config ที่ mutable → ต้อง **CRDT** จริง (multi-master): add-wins set of rules (UUID), LWW-register vars, OR-set scope. (เหตุผลที่ §6 บังคับ UUID.)
- Blob → external object store (S3/minio) หลัง port เดิม.
- Sticky session สำหรับ SSE หรือ shared bus.

**Deferred** — MVP single server พอสำหรับทีมทั่วไป (สิบกว่าคน).

---

## 10. API surface (เพิ่มจากของเดิม)

```
POST /api/v1/team/join        { project_token, display_name } -> { session_token, operator_id }
POST /api/v1/presence         { flow_id? }                    -- heartbeat
GET  /api/v1/operators                                        -- ใครออนไลน์
# ของเดิมทั้งหมด (flows/intercept/rules/scope/vars/macros/...) ทำงานเหมือนเดิม
#   แต่ + auth middleware, + operator attribution, + version บน rules/macros
# SSE /api/v1/stream เพิ่ม event: presence, operator-tagged flow_new/finding
```
Local mode: endpoint `team/*` ปิด, ไม่มี auth — โค้ด path เดียว, สลับด้วย config.

---

## 11. Phased delivery plan

| เฟส | สิ่งที่ทำ | Done เมื่อ |
|---|---|---|
| **T1 · Postgres store** | crate `snare-store-postgres` (sqlx) impl `FlowStore`; `snared serve --postgres <url>`; flows/findings/ws append-only แชร์ + fan-out SSE เดิม | 2 คน browse ผ่าน team proxy เห็น flow ของกันสด |
| **T2 · Auth + identity** | project token join, per-session token, axum auth layer, TLS flag, operator attribution บน flow/finding/activity | เข้าได้เฉพาะคนมี token, flow ติดชื่อคนจับ |
| **T3 · Shared config** | `SettingsStore` port → Postgres; rules/scope/vars/macros/scanner ใน PG + change events + client reload; optimistic version (409) | คนหนึ่งเพิ่ม rule คนอื่นเห็นทันที |
| **T4 · Presence** | presence event + heartbeat + operator list; Web avatars | เห็นใครออนไลน์/ดู flow ไหน |
| **T5 · Projects + per-op intercept + roles** | multi-project scoping, per-operator intercept queue, viewer/editor/admin | หลาย engagement, intercept ไม่ชนกัน |
| **T6 · Multi-node (future)** | NOTIFY/bus fan-out + CRDT config | scale หลาย server |

**คุ้มสุดเริ่มที่ T1** (reuse store port, ผล visible ทันที). T1–T4 = MVP ที่ใช้งานทีมได้จริง.

---

## 12. Data model / code changes summary

- **ใหม่:** `snare-store-postgres` crate; `SettingsStore` port; `Presence`/operator ใน `FlowEvent`; auth middleware ใน `snared/api`; `serve` subcommand.
- **แก้:** `flows`/`findings`/`activity` เพิ่ม `operator`; rules/macros id → **UUID + version**; coordinators โหลด/เซฟผ่าน `SettingsStore` แทน `config.json` โดยตรง (local = file adapter, team = PG adapter).
- **ไม่แตะ:** engine data-plane, frontends (คุยผ่าน API เดิม), intercept/repeater/intruder/scanner logic.

---

## 13. Risks & open questions

- **Privacy/trust:** ทุกคนเห็น traffic ของทุกคน (โดยตั้งใจเพื่อ collab) — ต้องสื่อสารชัด + scope ต่อ project. Central-proxy (A) = ทุกคนเชื่อ CA เดียว.
- **Blob load:** body ใหญ่ใน BYTEA + fan-out หลาย client = แบนด์วิดท์/หน่วยความจำ — ใช้ lazy body fetch (summary ก่อน, body ตอนเปิด flow — UI ทำอยู่แล้ว).
- **Auth ตอน MVP อ่อน** (shared token) — ยอมรับได้สำหรับทีมเล็กหลัง VPN/TLS; roll เป็น per-op accounts ใน T5.
- **Open:** central (A) vs local (B) เป็น default ตอน production? → เก็บ decision ไว้ตอนจบ T1 (วัดจากประสบการณ์ใช้จริง).
- **Open:** conflict UX เมื่อ 409 (rule version ชน) — auto-reload+retry เงียบ หรือถามผู้ใช้?
- **Open:** ควรมี "engagement recording/replay" (audit ทั้ง session) ตั้งแต่ T2 มั้ย?

---

## 14. ADR log (team mode)

| # | Decision | ทางเลือกที่ปัด | เหตุผล |
|---|---|---|---|
| T-001 | Topology: **central (MVP) → local (target)** | P2P, local-only | reuse สูงสุด, port เดิมรองรับย้าย |
| T-002 | Store: **Postgres (sqlx) หลัง `FlowStore`**, blob BYTEA, + `SettingsStore` port | sled, Mongo, external-first | multi-writer, ตรง port เดิม |
| T-003 | Fan-out: **in-process broadcast (single server)** | bus-first | เรียบง่าย, reuse SSE เดิม |
| T-004 | Config consistency: **server-authoritative LWW + version** | CRDT-first | single server พอ, CRDT overkill ตอนนี้ |
| T-005 | Intercept = **per-operator queue**; id ของ rules/macros = **UUID** (future-proof CRDT) | global intercept, int id | เลี่ยง conflict บน path ไว, พร้อม CRDT ทีหลัง |
| T-006 | Auth: **project token + display name + session token**, TLS via flag/proxy | full accounts/SSO ทันที | เข้าเร็ว, roll เป็น accounts ใน T5 |
| T-007 | Presence: **ephemeral in-memory + heartbeat** | persist presence | เบา, พอสำหรับ collab |

---

## 15. Next step

เริ่ม **T1**: สร้าง `snare-store-postgres` (impl `FlowStore` ด้วย sqlx), schema flows/bodies/findings/ws, และ `snared serve --postgres <url>` — จุดที่ reuse สูงสุดและเห็นผล (2 คน browse เห็นกันสด) เร็วที่สุด. หลัง T1 ค่อยตัดสิน central-vs-local เป็น default จากการใช้จริง.
